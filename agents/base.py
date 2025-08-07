import logging
import os
import sys
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from config.settings import maybe_monitor_performance
from core.exceptions import SOCStateError
from core.models import AnalysisResult, ProcessingEvent
from core.state import SOCState
from core.state_manager import SOCStateManager


class AgentStatus(str, Enum):
    """Agent execution status"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"


class AgentMetrics(BaseModel):
    """Agent performance and execution metrics"""
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    execution_time_ms: Optional[float] = None
    status: AgentStatus = AgentStatus.IDLE
    error_message: Optional[str] = None
    memory_usage_mb: Optional[float] = None
    state_changes: int = 0
    tools_used: List[str] = Field(default_factory=list)
    confidence_delta: float = 0.0
    
    def complete(self, status: AgentStatus = AgentStatus.COMPLETED, error_message: str = None):
        """Mark execution as complete and calculate metrics"""
        self.end_time = datetime.utcnow()
        self.execution_time_ms = (self.end_time - self.start_time).total_seconds() * 1000
        self.status = status
        if error_message:
            self.error_message = error_message
    
    def add_tool_usage(self, tool_name: str):
        """Record tool usage"""
        if tool_name not in self.tools_used:
            self.tools_used.append(tool_name)


class AgentConfig(BaseModel):
    """Agent configuration settings"""
    agent_name: str
    version: str = "1.0.0"
    timeout_seconds: int = 30
    max_retries: int = 3
    enable_monitoring: bool = True
    enable_state_validation: bool = True
    log_level: str = "INFO"
    custom_settings: Dict[str, Any] = Field(default_factory=dict)


class AgentHealthCheck(BaseModel):
    """Agent health status information"""
    agent_name: str
    is_healthy: bool = True
    last_check: datetime = Field(default_factory=datetime.utcnow)
    error_count: int = 0
    success_count: int = 0
    avg_execution_time_ms: float = 0.0
    status_message: str = "Agent is healthy"
    
    def update_success(self, execution_time_ms: float):
        """Update metrics after successful execution"""
        self.success_count += 1
        total_executions = self.success_count + self.error_count
        self.avg_execution_time_ms = (
            (self.avg_execution_time_ms * (total_executions - 1) + execution_time_ms) / total_executions
        )
        self.last_check = datetime.utcnow()
        self.is_healthy = True
        self.status_message = "Agent is healthy"
    
    def update_error(self, error_message: str):
        """Update metrics after error"""
        self.error_count += 1
        self.last_check = datetime.utcnow()
        self.is_healthy = self.error_count / (self.success_count + self.error_count) < 0.1  # 10% error threshold
        self.status_message = f"Last error: {error_message[:100]}"


class BaseAgent(ABC):
    """
    Abstract base class for all SOC agents.
    
    Provides common functionality:
    - Consistent interface via run() method
    - State validation and error handling
    - Performance monitoring and metrics
    - Logging and health monitoring
    - Agent lifecycle management
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize base agent with configuration.
        
        Args:
            config: Agent configuration settings
        """
        self.config = config
        self.logger = logging.getLogger(f"agents.{config.agent_name}")
        self.logger.setLevel(getattr(logging, config.log_level.upper()))
        
        self.health = AgentHealthCheck(agent_name=config.agent_name)
        self._initialized = False
        self._current_metrics: Optional[AgentMetrics] = None
        
        # Initialize agent-specific resources
        try:
            self.initialize()
            self._initialized = True
            self.logger.info(f"Agent {self.config.agent_name} initialized successfully")
        except Exception as e:
            self.logger.error(f"Agent initialization failed: {e}")
            self.health.update_error(f"Initialization failed: {e}")
            raise
    
    @abstractmethod
    def initialize(self):
        """
        Initialize agent-specific resources.
        Called during agent construction.
        Override in subclasses for custom initialization.
        """
        pass
    
    @abstractmethod
    def _execute(self, state: SOCState) -> SOCState:
        """
        Core agent execution logic.
        
        This is where each agent implements its specific functionality.
        Must be overridden by subclasses.
        
        Args:
            state: Current SOC state
            
        Returns:
            SOCState: Updated state after agent processing
            
        Raises:
            Any agent-specific exceptions
        """
        pass
    
    @maybe_monitor_performance
    def run(self, state: SOCState) -> SOCState:
        if not self._initialized:
            raise RuntimeError(f"Agent {self.config.agent_name} not properly initialized")
        
        initial_confidence = state.get("confidence_score", 0.0)
        self._current_metrics = AgentMetrics(agent_name=self.config.agent_name)
        
        try:
            if self.config.enable_state_validation:
                is_valid, error_msg = SOCStateManager.validate_state(state)
                if not is_valid:
                    raise SOCStateError(f"Invalid input state: {error_msg}")
            
            self.logger.info(f"Starting execution for alert {state.get('alert_id')}")
            self._current_metrics.status = AgentStatus.RUNNING
            
            state = SOCStateManager.update_state(
                state,
                current_agent=self.config.agent_name,
                workflow_step=self._get_workflow_step()
            )
            self._current_metrics.state_changes += 1
            
            updated_state = self._execute_with_retry(state)
            
            if self.config.enable_state_validation:
                is_valid, error_msg = SOCStateManager.validate_state(updated_state)
                if not is_valid:
                    raise SOCStateError(f"Invalid output state: {error_msg}")
            
            final_confidence = updated_state.get("confidence_score", 0.0)
            self._current_metrics.confidence_delta = final_confidence - initial_confidence
            self._current_metrics.complete(AgentStatus.COMPLETED)
            self.health.update_success(self._current_metrics.execution_time_ms)
            
            execution_event = ProcessingEvent(
                event_type="agent_completed",
                agent=self.config.agent_name,
                version=updated_state["version"],
                details={
                    "execution_time_ms": self._current_metrics.execution_time_ms,
                    "confidence_delta": self._current_metrics.confidence_delta,
                    "tools_used": self._current_metrics.tools_used,
                    "state_changes": self._current_metrics.state_changes
                }
            )
            
            processing_history = updated_state["processing_history"].copy()
            processing_history.append(execution_event.model_dump())
            updated_state["processing_history"] = processing_history
            
            self.logger.info(
                f"Agent {self.config.agent_name} completed successfully. "
                f"Execution time: {self._current_metrics.execution_time_ms:.2f}ms, "
                f"Confidence delta: {self._current_metrics.confidence_delta:+.1f}"
            )
            
            return updated_state
            
        except SOCStateError as e:
            # Handle invalid state errors specifically
            error_message = f"Agent execution failed: {str(e)}"
            self.logger.error(error_message, exc_info=True)
            
            if self._current_metrics:
                self._current_metrics.complete(AgentStatus.ERROR, error_message)
            
            self.health.update_error(error_message)
            
            error_event = ProcessingEvent(
                event_type="error_occurred",
                agent=self.config.agent_name,
                version=state.get("version", "0.0.0"),
                details={
                    "error_message": error_message,
                    "error_type": type(e).__name__
                }
            )
            processing_history = state.get("processing_history", []).copy()
            processing_history.append(error_event.model_dump())
            
            # Avoid re-validation for invalid input state
            error_state = state.copy()
            error_state["processing_history"] = processing_history
            error_state["current_agent"] = None
            error_state["agent_notes"] = error_state.get("agent_notes", {}).copy()
            error_state["agent_notes"].setdefault(self.config.agent_name, []).append(f"ERROR: {error_message}")
            
            raise  # Re-raise the original SOCStateError
        
        except Exception as e:
            # Handle all other errors
            error_message = f"Agent execution failed: {str(e)}"
            self.logger.error(error_message, exc_info=True)
            
            if self._current_metrics:
                self._current_metrics.complete(AgentStatus.ERROR, error_message)
            
            self.health.update_error(error_message)
            
            error_event = ProcessingEvent(
                event_type="error_occurred",
                agent=self.config.agent_name,
                version=state.get("version", "0.0.0"),
                details={
                    "error_message": error_message,
                    "error_type": type(e).__name__
                }
            )
            processing_history = state.get("processing_history", []).copy()
            processing_history.append(error_event.model_dump())
            
            error_state = SOCStateManager.update_state(
                state,
                processing_history=processing_history,
                current_agent=None
            )
            error_state = SOCStateManager.add_agent_note(
                error_state,
                self.config.agent_name,
                f"ERROR: {error_message}"
            )
            
            raise RuntimeError(error_message) from e
    
    def _execute_with_retry(self, state: SOCState) -> SOCState:
        """Execute agent logic with retry mechanism"""
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    self.logger.warning(f"Retrying execution (attempt {attempt + 1}/{self.config.max_retries + 1})")
                    time.sleep(min(2 ** attempt, 10))  # Exponential backoff, max 10s
                
                return self._execute(state)
                
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    self.logger.warning(f"Execution attempt {attempt + 1} failed: {e}")
                    continue
                else:
                    self.logger.error(f"All {self.config.max_retries + 1} execution attempts failed")
                    raise
        
        # This shouldn't be reached, but just in case
        raise last_exception
    
    def _get_workflow_step(self) -> str:
        """Get the workflow step name for this agent"""
        # Default implementation based on agent name
        agent_name = self.config.agent_name.lower()
        if "ingestion" in agent_name:
            return "ingestion"
        elif "triage" in agent_name:
            return "triage"
        elif "correlation" in agent_name:
            return "correlation"
        elif "analysis" in agent_name:
            return "analysis"
        elif "human" in agent_name:
            return "human_review"
        elif "response" in agent_name:
            return "response"
        elif "learning" in agent_name:
            return "learning"
        else:
            return "processing"
    
    def add_agent_note(self, state: SOCState, note: str) -> SOCState:
        """
        Convenience method to add agent note with automatic agent name.
        
        Args:
            state: Current state
            note: Note to add
            
        Returns:
            SOCState: Updated state with note
        """
        updated_state = SOCStateManager.add_agent_note(state, self.config.agent_name, note)
        if self._current_metrics:
            self._current_metrics.state_changes += 1
        return updated_state
    
    def add_analysis_result(self, state: SOCState, result: Dict[str, Any], 
                          confidence: float, reasoning: str = None) -> SOCState:
        """
        Convenience method to add analysis result.
        
        Args:
            state: Current state
            result: Analysis result data
            confidence: Confidence score for this result
            reasoning: Optional reasoning explanation
            
        Returns:
            SOCState: Updated state with analysis result
        """
        analysis_result = AnalysisResult(
            agent_name=self.config.agent_name,
            result=result,
            confidence=confidence,
            reasoning=reasoning,
            execution_time_ms=self._current_metrics.execution_time_ms if self._current_metrics else None
        )
        
        updated_state = SOCStateManager.add_analysis_result(state, analysis_result)
        if self._current_metrics:
            self._current_metrics.state_changes += 1
        
        return updated_state
    
    def update_confidence_score(self, state: SOCState, score: float, reasoning: str = None) -> SOCState:
        """
        Convenience method to update confidence score.
        
        Args:
            state: Current state
            score: New confidence score
            reasoning: Optional reasoning for the score
            
        Returns:
            SOCState: Updated state with new confidence score
        """
        updated_state = SOCStateManager.set_confidence_score(state, score, reasoning)
        if self._current_metrics:
            self._current_metrics.state_changes += 1
        return updated_state
    
    def use_tool(self, tool_name: str):
        """
        Record tool usage for metrics.
        Call this method whenever the agent uses an external tool.
        
        Args:
            tool_name: Name of the tool being used
        """
        if self._current_metrics:
            self._current_metrics.add_tool_usage(tool_name)
        self.logger.debug(f"Using tool: {tool_name}")
    
    def get_health_status(self) -> AgentHealthCheck:
        """
        Get current agent health status.
        
        Returns:
            AgentHealthCheck: Current health information
        """
        return self.health
    
    def get_current_metrics(self) -> Optional[AgentMetrics]:
        """
        Get current execution metrics.
        
        Returns:
            AgentMetrics: Current execution metrics if available
        """
        return self._current_metrics
    
    def cleanup(self):
        """
        Cleanup agent resources.
        Override in subclasses for custom cleanup logic.
        """
        self.logger.info(f"Agent {self.config.agent_name} cleanup completed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self.cleanup()


class AgentRegistry:
    """
    Registry for managing agent instances and health monitoring.
    """
    
    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self.logger = logging.getLogger("agents.registry")
    
    def register_agent(self, agent: BaseAgent):
        """
        Register an agent instance.
        
        Args:
            agent: Agent instance to register
        """
        self._agents[agent.config.agent_name] = agent
        self.logger.info(f"Registered agent: {agent.config.agent_name}")
    
    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """
        Get agent by name.
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            BaseAgent: Agent instance if found, None otherwise
        """
        return self._agents.get(agent_name)
    
    def list_agents(self) -> List[str]:
        """
        List all registered agent names.
        
        Returns:
            List[str]: List of agent names
        """
        return list(self._agents.keys())
    
    def get_health_report(self) -> Dict[str, AgentHealthCheck]:
        """
        Get health status for all registered agents.
        
        Returns:
            Dict[str, AgentHealthCheck]: Health status by agent name
        """
        return {
            name: agent.get_health_status() 
            for name, agent in self._agents.items()
        }
    
    def cleanup_all(self):
        """Cleanup all registered agents"""
        for agent in self._agents.values():
            try:
                agent.cleanup()
            except Exception as e:
                self.logger.error(f"Error cleaning up agent {agent.config.agent_name}: {e}")
        
        self._agents.clear()
        self.logger.info("All agents cleaned up")


# Global agent registry instance
agent_registry = AgentRegistry()