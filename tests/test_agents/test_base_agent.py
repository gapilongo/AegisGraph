import os
import sys
import time
from datetime import datetime
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import pytest

from agents.base import (
    AgentConfig,
    AgentHealthCheck,
    AgentMetrics,
    AgentRegistry,
    AgentStatus,
    BaseAgent,
    agent_registry,
)
from core.exceptions import SOCStateError
from core.state_manager import SOCStateManager


class MockAgent(BaseAgent):
    """Simple mock agent for testing"""
    
    def __init__(self, config: AgentConfig, should_fail: bool = False, fail_on_init: bool = False):
        self.should_fail = should_fail
        self.fail_on_init = fail_on_init
        self.init_called = False
        super().__init__(config)
    
    def initialize(self):
        """Mock initialization"""
        self.init_called = True
        if self.fail_on_init:
            raise RuntimeError("Mock initialization failure")
    
    def _execute(self, state):
        """Mock execution"""
        if self.should_fail:
            raise RuntimeError("Mock execution failure")
        
        updated_state = self.add_agent_note(state, "Mock processing completed")
        return self.update_confidence_score(updated_state, 75.0)


class TestAgentConfig:
    """Test agent configuration"""
    
    def test_agent_config_creation(self):
        """Test creating agent configuration"""
        config = AgentConfig(agent_name="test_agent")
        
        assert config.agent_name == "test_agent"
        assert config.version == "1.0.0"
        assert config.timeout_seconds == 30
        assert config.max_retries == 3
        assert config.enable_monitoring is True
        assert config.log_level == "INFO"
    
    def test_agent_config_custom_values(self):
        """Test agent configuration with custom values"""
        config = AgentConfig(
            agent_name="custom_agent",
            version="2.0.0",
            timeout_seconds=60,
            max_retries=5,
            enable_monitoring=False
        )
        
        assert config.agent_name == "custom_agent"
        assert config.version == "2.0.0"
        assert config.timeout_seconds == 60
        assert config.max_retries == 5
        assert config.enable_monitoring is False


class TestAgentMetrics:
    """Test agent metrics functionality"""
    
    def test_metrics_creation(self):
        """Test creating agent metrics"""
        metrics = AgentMetrics(agent_name="test_agent")
        
        assert metrics.agent_name == "test_agent"
        assert metrics.status == AgentStatus.IDLE
        assert metrics.execution_id is not None
        assert len(metrics.execution_id) == 36  # UUID length
        assert metrics.start_time is not None
        assert metrics.end_time is None
    
    def test_metrics_completion(self):
        """Test metrics completion"""
        metrics = AgentMetrics(agent_name="test_agent")
        time.sleep(0.001)  # Small delay for measurable time
        
        metrics.complete(AgentStatus.COMPLETED)
        
        assert metrics.status == AgentStatus.COMPLETED
        assert metrics.end_time is not None
        assert metrics.execution_time_ms is not None
        assert metrics.execution_time_ms > 0
    
    def test_metrics_error_completion(self):
        """Test metrics completion with error"""
        metrics = AgentMetrics(agent_name="test_agent")
        error_msg = "Test error"
        
        metrics.complete(AgentStatus.ERROR, error_msg)
        
        assert metrics.status == AgentStatus.ERROR
        assert metrics.error_message == error_msg
    
    def test_tool_usage_tracking(self):
        """Test tool usage tracking"""
        metrics = AgentMetrics(agent_name="test_agent")
        
        metrics.add_tool_usage("tool1")
        metrics.add_tool_usage("tool2")
        metrics.add_tool_usage("tool1")  # Duplicate
        
        assert "tool1" in metrics.tools_used
        assert "tool2" in metrics.tools_used
        assert len(metrics.tools_used) == 2  # No duplicates


class TestAgentHealthCheck:
    """Test agent health monitoring"""
    
    def test_health_creation(self):
        """Test creating health check"""
        health = AgentHealthCheck(agent_name="test_agent")
        
        assert health.agent_name == "test_agent"
        assert health.is_healthy is True
        assert health.error_count == 0
        assert health.success_count == 0
        assert health.avg_execution_time_ms == 0.0
    
    def test_health_success_update(self):
        """Test health success update"""
        health = AgentHealthCheck(agent_name="test_agent")
        
        health.update_success(50.0)
        health.update_success(100.0)
        
        assert health.success_count == 2
        assert health.error_count == 0
        assert health.avg_execution_time_ms == 75.0  # (50 + 100) / 2
        assert health.is_healthy is True
    
    def test_health_error_update(self):
        """Test health error update"""
        health = AgentHealthCheck(agent_name="test_agent")
        
        # Add a success first to establish a baseline
        health.update_success(50.0)
        health.update_error("Test error")
        
        assert health.error_count == 1
        assert health.success_count == 1
        # With 1 error out of 2 total (50% error rate), agent should be unhealthy
        # But the logic checks if error_count / total < 0.1, so 1/2 = 0.5 > 0.1 = unhealthy
        assert health.is_healthy is False
        assert "Test error" in health.status_message
    
    def test_health_low_error_rate(self):
        """Test health with low error rate stays healthy"""
        health = AgentHealthCheck(agent_name="test_agent")
        
        # Add many successes and few errors to stay below 10% threshold
        for i in range(10):
            health.update_success(50.0)
        health.update_error("Single error")  # 1/11 = 9% error rate
        
        assert health.error_count == 1
        assert health.success_count == 10
        assert health.is_healthy is True  # 9% error rate < 10% threshold
    
    def test_health_unhealthy_threshold(self):
        """Test health becomes unhealthy with high error rate"""
        health = AgentHealthCheck(agent_name="test_agent")
        
        # Create high error rate (>10%)
        health.update_success(50.0)
        health.update_error("Error 1")
        health.update_error("Error 2")  # 2/3 = 66% error rate
        
        assert health.is_healthy is False
        assert health.error_count == 2
        assert health.success_count == 1


class TestBaseAgent:
    """Test base agent functionality"""
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        assert agent.config.agent_name == "test_agent"
        assert agent.init_called is True
        assert agent._initialized is True
        assert agent.health.agent_name == "test_agent"
    
    def test_agent_initialization_failure(self):
        """Test agent initialization failure"""
        config = AgentConfig(agent_name="test_agent")
        
        with pytest.raises(RuntimeError, match="Mock initialization failure"):
            MockAgent(config, fail_on_init=True)
    
    def test_agent_run_success(self):
        """Test successful agent execution"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        result_state = agent.run(state)
        
        assert result_state["current_agent"] == "test_agent"
        assert result_state["confidence_score"] == 75.0
        assert "test_agent" in result_state["agent_notes"]
        assert len(result_state["processing_history"]) > len(state["processing_history"])
        assert agent.health.success_count == 1
        assert agent.health.is_healthy is True
    
    def test_agent_run_failure(self):
        """Test agent execution failure (not initialization failure)"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="test_agent")
        # Initialize agent successfully, but make execution fail
        agent = MockAgent(config, should_fail=True, fail_on_init=False)
        
        with pytest.raises(RuntimeError, match="Agent execution failed"):
            agent.run(state)
        
        assert agent.health.error_count == 1
    
    def test_agent_invalid_state(self):
        """Test agent with invalid state"""
        invalid_state = {
            "alert_id": "test",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "version": 1,
            "schema_version": "1.0.0",
            "raw_alert": {
                "timestamp": "invalid_timestamp",  # Invalid format
                "source": "",  # Empty source (invalid)
                "event_type": ""  # Empty event_type (invalid)
            },
            "enriched_data": {},
            "triage_status": "pending",
            "confidence_score": 0.0,
            "fp_indicators": [],
            "tp_indicators": [],
            "human_feedback": None,
            "next_steps": [],
            "agent_notes": {},
            "analysis_results": [],
            "messages": [],
            "processing_history": [],
            "current_agent": None,
            "workflow_step": "ingestion"
        }
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        with pytest.raises(SOCStateError, match="Invalid input state"):
            agent.run(invalid_state)
        
        assert agent.health.error_count == 1
        assert agent.health.is_healthy is False  # Assuming one error makes it unhealthy
    
    def test_agent_state_validation_disabled(self):
        """Test agent with state validation disabled"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(
            agent_name="test_agent",
            enable_state_validation=False
        )
        agent = MockAgent(config)
        
        result_state = agent.run(state)
        assert result_state["current_agent"] == "test_agent"
    
    def test_agent_workflow_step_detection(self):
        """Test workflow step detection"""
        test_cases = [
            ("ingestion_agent", "ingestion"),
            ("triage_agent", "triage"),
            ("correlation_agent", "correlation"),
            ("analysis_agent", "analysis"),
            ("response_agent", "response"),
            ("unknown_agent", "processing")
        ]
        
        for agent_name, expected_step in test_cases:
            config = AgentConfig(agent_name=agent_name)
            agent = MockAgent(config)
            assert agent._get_workflow_step() == expected_step
    
    def test_agent_convenience_methods(self):
        """Test agent convenience methods"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        agent._current_metrics = AgentMetrics(agent_name="test_agent")
        
        # Test add_agent_note
        updated_state = agent.add_agent_note(state, "Test note")
        assert "test_agent" in updated_state["agent_notes"]
        assert "Test note" in updated_state["agent_notes"]["test_agent"]
        
        # Test add_analysis_result
        result_state = agent.add_analysis_result(
            updated_state,
            {"finding": "test"},
            85.0,
            "Test reasoning"
        )
        assert len(result_state["analysis_results"]) == 1
        assert result_state["analysis_results"][0]["confidence"] == 85.0
        
        # Test use_tool
        agent.use_tool("test_tool")
        assert "test_tool" in agent._current_metrics.tools_used
    
    def test_agent_retry_mechanism(self):
        """Test agent retry mechanism"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="test_agent", max_retries=2)
        
        class RetryAgent(MockAgent):
            def __init__(self, config):
                super().__init__(config)
                self.attempt_count = 0
            
            def _execute(self, state):
                self.attempt_count += 1
                if self.attempt_count < 3:  # Fail first 2 attempts
                    raise RuntimeError(f"Attempt {self.attempt_count} failed")
                return super()._execute(state)
        
        agent = RetryAgent(config)
        result_state = agent.run(state)
        
        assert agent.attempt_count == 3
        assert result_state["current_agent"] == "test_agent"


class TestAgentRegistry:
    """Test agent registry functionality"""
    
    def test_registry_basic_operations(self):
        """Test basic registry operations"""
        registry = AgentRegistry()
        
        assert len(registry.list_agents()) == 0
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        registry.register_agent(agent)
        
        assert len(registry.list_agents()) == 1
        assert "test_agent" in registry.list_agents()
        
        retrieved_agent = registry.get_agent("test_agent")
        assert retrieved_agent is agent
        
        non_existent = registry.get_agent("non_existent")
        assert non_existent is None
    
    def test_registry_health_report(self):
        """Test registry health reporting"""
        registry = AgentRegistry()
        
        config1 = AgentConfig(agent_name="agent1")
        config2 = AgentConfig(agent_name="agent2")
        
        agent1 = MockAgent(config1)
        agent2 = MockAgent(config2)
        
        registry.register_agent(agent1)
        registry.register_agent(agent2)
        
        # Update health
        agent1.health.update_success(50.0)
        agent2.health.update_error("Test error")
        
        health_report = registry.get_health_report()
        
        assert len(health_report) == 2
        assert health_report["agent1"].success_count == 1
        assert health_report["agent2"].error_count == 1
    
    def test_registry_cleanup(self):
        """Test registry cleanup"""
        registry = AgentRegistry()
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        registry.register_agent(agent)
        registry.cleanup_all()
        
        assert len(registry.list_agents()) == 0


class TestAgentPerformance:
    """Test agent performance"""
    
    def test_execution_performance(self):
        """Test agent execution performance"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="perf_agent")
        agent = MockAgent(config)
        
        # Warmup
        for _ in range(5):
            agent.run(state)
        
        # Performance test
        start_time = time.perf_counter()
        iterations = 10
        
        for _ in range(iterations):
            result_state = agent.run(state)
            state = result_state
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        # Mock agents should be very fast
        assert avg_time < 0.1, f"Agent execution took {avg_time*1000:.2f}ms (should be <100ms)"
    
    def test_metrics_performance(self):
        """Test metrics collection performance"""
        start_time = time.perf_counter()
        iterations = 1000
        
        for _ in range(iterations):
            metrics = AgentMetrics(agent_name="test")
            metrics.add_tool_usage("tool1")
            metrics.complete(AgentStatus.COMPLETED)
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        assert avg_time < 0.001, f"Metrics operations took {avg_time*1000:.2f}ms (should be <1ms)"


class TestAgentIntegration:
    """Integration tests for agent framework"""
    
    def test_multi_agent_workflow(self):
        """Test multiple agents working together"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        
        initial_state = SOCStateManager.create_initial_state(raw_alert)
        
        # Create multiple agents
        agents = []
        for i in range(3):
            config = AgentConfig(agent_name=f"agent_{i}")
            agent = MockAgent(config)
            agents.append(agent)
        
        # Execute agents sequentially
        current_state = initial_state
        for agent in agents:
            current_state = agent.run(current_state)
            
            # Verify state remains valid
            is_valid, error_msg = SOCStateManager.validate_state(current_state)
            assert is_valid, f"State invalid after {agent.config.agent_name}: {error_msg}"
        
        # Verify final state
        assert current_state["version"] > initial_state["version"]
        assert len(current_state["agent_notes"]) == 3
        assert current_state["confidence_score"] == 75.0
        
        # Verify all agents are healthy
        for agent in agents:
            assert agent.health.is_healthy
            assert agent.health.success_count == 1
    
    def test_agent_error_recovery(self):
        """Test error recovery in agent workflow"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        initial_state = SOCStateManager.create_initial_state(raw_alert)
        
        # Create failing and succeeding agents
        failing_config = AgentConfig(agent_name="failing_agent", max_retries=0)
        success_config = AgentConfig(agent_name="success_agent")
        
        # Create agent that initializes fine but fails on execution
        failing_agent = MockAgent(failing_config, should_fail=True, fail_on_init=False)
        success_agent = MockAgent(success_config)
        
        # First agent execution fails
        with pytest.raises(RuntimeError, match="Agent execution failed"):
            failing_agent.run(initial_state)
        
        # State should still be valid
        is_valid, error_msg = SOCStateManager.validate_state(initial_state)
        assert is_valid, f"State corrupted after failure: {error_msg}"
        
        # Second agent succeeds
        final_state = success_agent.run(initial_state)
        assert final_state["current_agent"] == "success_agent"
        
        # Verify health states
        assert failing_agent.health.error_count == 1
        assert success_agent.health.success_count == 1


class TestAgentEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_agent_with_long_note(self):
        """Test agent with extremely long note"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        state = SOCStateManager.create_initial_state(raw_alert)
        
        config = AgentConfig(agent_name="test_agent")
        agent = MockAgent(config)
        
        long_note = "A" * 10000  # 10KB note
        updated_state = agent.add_agent_note(state, long_note)
        
        assert len(updated_state["agent_notes"]["test_agent"][0]) == 10000
        is_valid, error_msg = SOCStateManager.validate_state(updated_state)
        assert is_valid
    
    def test_agent_rapid_executions(self):
        """Test agent with many rapid executions"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event'
        }
        
        config = AgentConfig(agent_name="rapid_agent")
        agent = MockAgent(config)
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Execute many times rapidly
        for i in range(20):
            state = agent.run(state)
            assert state["version"] >= i + 2  # Version increments
        
        # Agent should remain healthy
        assert agent.health.success_count == 20
        assert agent.health.is_healthy is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])