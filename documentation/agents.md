# Agent Framework Documentation

## Overview

The Agent Framework provides a consistent, robust foundation for building specialized security analysis agents in the SOC Triage & Orchestration system. Each agent implements specific functionality while maintaining compatibility with the LangGraph workflow system.

## Core Concepts

### BaseAgent Abstract Class

All agents inherit from `BaseAgent`, which provides:

- **Consistent Interface**: All agents implement the same `run(state: SOCState) -> SOCState` method
- **Error Handling**: Automatic retry logic and graceful error recovery
- **Performance Monitoring**: Built-in metrics collection and health monitoring  
- **State Validation**: Optional input/output state validation
- **Logging**: Structured logging with agent-specific contexts

### Agent Configuration

Agents are configured using `AgentConfig`:

```python
config = AgentConfig(
    agent_name="my_agent",
    version="1.0.0",
    timeout_seconds=30,
    max_retries=3,
    enable_monitoring=True,
    enable_state_validation=True,
    log_level="INFO",
    custom_settings={}
)
```

### Agent Lifecycle

1. **Initialization**: Agent-specific resources are set up
2. **Execution**: Core agent logic runs with monitoring and error handling  
3. **Cleanup**: Resources are properly released

## Creating Custom Agents

### Step 1: Define Your Agent Class

```python
from agents.base import BaseAgent, AgentConfig
from core.state import SOCState

class MyCustomAgent(BaseAgent):
    def initialize(self):
        """Initialize agent-specific resources"""
        self.my_resource = connect_to_external_service()
        self.logger.info("Custom agent initialized")
    
    def _execute(self, state: SOCState) -> SOCState:
        """Implement your agent's core logic"""
        # Add agent note
        updated_state = self.add_agent_note(state, "Starting custom analysis")
        
        # Perform your analysis
        result = self.my_analysis_function(state["raw_alert"])
        
        # Record tool usage
        self.use_tool("my_external_api")
        
        # Add analysis result
        updated_state = self.add_analysis_result(
            updated_state,
            result={"findings": result},
            confidence=85.0,
            reasoning="Custom analysis completed"
        )
        
        # Update confidence if needed
        if result.get("high_risk"):
            updated_state = self.update_confidence_score(
                updated_state, 
                90.0, 
                "High risk indicators detected"
            )
        
        return updated_state
    
    def my_analysis_function(self, raw_alert):
        """Your custom analysis logic"""
        return {"status": "analyzed", "risk_level": "medium"}
    
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'my_resource'):
            self.my_resource.close()
        super().cleanup()
```

### Step 2: Create and Use Your Agent

```python
# Create configuration
config = AgentConfig(
    agent_name="my_custom_agent",
    timeout_seconds=60,
    custom_settings={"api_endpoint": "https://api.example.com"}
)

# Create agent instance
agent = MyCustomAgent(config)

# Use with context manager for automatic cleanup
with MyCustomAgent(config) as agent:
    result_state = agent.run(input_state)
```

## Built-in Agents

### IngestionAgent

Handles initial alert processing and normalization:

- Validates and normalizes alert data
- Adds basic enrichment metadata
- Ensures data consistency for downstream agents

```python
from agents.ingestion import IngestionAgent

config = AgentConfig(agent_name="ingestion_agent")
agent = IngestionAgent(config)
processed_state = agent.run(raw_state)
```

### TriageAgent

Performs initial alert classification:

- Detects false positive indicators
- Identifies true positive patterns  
- Calculates initial confidence scores
- Determines triage status

```python
from agents.triage import TriageAgent

config = AgentConfig(agent_name="triage_agent")
agent = TriageAgent(config)
triaged_state = agent.run(ingested_state)
```

### CorrelationAgent

Finds related events and historical context:

- Searches for related events in time windows
- Builds historical context profiles
- Calculates correlation scores
- Adjusts confidence based on correlation strength

```python
from agents.correlation import CorrelationAgent

config = AgentConfig(agent_name="correlation_agent") 
agent = CorrelationAgent(config)
correlated_state = agent.run(triaged_state)
```

### AnalysisAgent

Performs deep analysis using ReAct pattern:

- Implements Reason→Act→Observe loops
- Dynamically selects and executes analysis tools
- Builds comprehensive threat assessment
- Provides final recommendations

```python
from agents.analysis import AnalysisAgent

config = AgentConfig(agent_name="analysis_agent")
agent = AnalysisAgent(config)  
analyzed_state = agent.run(correlated_state)
```

## Agent Registry

The global agent registry manages agent instances:

```python
from agents.base import agent_registry

# Register agents
agent_registry.register_agent(my_agent)

# Retrieve agents
agent = agent_registry.get_agent("my_agent_name")

# Get health status
health_report = agent_registry.get_health_report()

# Cleanup all agents
agent_registry.cleanup_all()
```

## Performance Monitoring

### Agent Metrics

Each agent execution collects detailed metrics:

```python
class AgentMetrics(BaseModel):
    execution_id: str
    agent_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    execution_time_ms: Optional[float] = None
    status: AgentStatus
    error_message: Optional[str] = None
    memory_usage_mb: Optional[float] = None
    state_changes: int = 0
    tools_used: List[str] = []
    confidence_delta: float = 0.0
```

### Health Monitoring

Continuous health monitoring tracks:

```python
class AgentHealthCheck(BaseModel):
    agent_name: str
    is_healthy: bool = True
    last_check: datetime
    error_count: int = 0
    success_count: int = 0
    avg_execution_time_ms: float = 0.0
    status_message: str = "Agent is healthy"
```

### Accessing Metrics

```python
# Get current execution metrics
metrics = agent.get_current_metrics()
print(f"Execution time: {metrics.execution_time_ms}ms")
print(f"Tools used: {metrics.tools_used}")

# Get health status  
health = agent.get_health_status()
print(f"Success rate: {health.success_count}/{health.success_count + health.error_count}")
print(f"Average execution time: {health.avg_execution_time_ms}ms")
```

## Error Handling

### Automatic Retry Logic

Agents automatically retry failed executions:

```python
config = AgentConfig(
    agent_name="retry_agent",
    max_retries=3  # Will try up to 4 times total
)
```

### Error Recovery

When agents fail:

1. Execution metrics are updated with error details
2. Health status reflects the failure  
3. Error events are added to processing history
4. State remains valid for subsequent agents

### Custom Error Handling

Override error handling in your agents:

```python
class MyRobustAgent(BaseAgent):
    def _execute(self, state: SOCState) -> SOCState:
        try:
            return self.perform_risky_operation(state)
        except ExternalServiceError as e:
            # Handle specific errors gracefully
            self.logger.warning(f"External service unavailable: {e}")
            return self.add_agent_note(state, f"Skipped analysis due to service unavailability: {e}")
        except Exception as e:
            # Let framework handle unexpected errors
            raise
```

## Integration with LangGraph

Agents integrate seamlessly with LangGraph workflows:

```python
from langgraph.graph import StateGraph
from agents.ingestion import IngestionAgent
from agents.triage import TriageAgent

# Create workflow graph
workflow = StateGraph(SOCState)

# Create agent instances
ingestion_agent = IngestionAgent(AgentConfig(agent_name="ingestion"))
triage_agent = TriageAgent(AgentConfig(agent_name="triage"))

# Add nodes to graph
workflow.add_node("ingestion", ingestion_agent.run)
workflow.add_node("triage", triage_agent.run)

# Define edges
workflow.add_edge("ingestion", "triage")
workflow.set_entry_point("ingestion")

# Compile and run
app = workflow.compile()
result = app.invoke(initial_state)
```

## Best Practices

### Agent Development

1. **Keep agents focused**: Each agent should have a single, well-defined responsibility
2. **Use convenience methods**: Leverage `add_agent_note()`, `add_analysis_result()`, etc.
3. **Record tool usage**: Call `use_tool()` when using external services
4. **Handle errors gracefully**: Provide meaningful error messages and fallback behavior
5. **Validate inputs**: Check that required data is present before processing

### Performance Optimization

1. **Initialize once**: Put expensive setup in `initialize()`, not `_execute()`
2. **Use context managers**: Ensure proper resource cleanup with `with` statements  
3. **Monitor execution time**: Keep core logic under performance targets
4. **Cache expensive operations**: Store reusable data in agent instance variables

### Testing Strategies

1. **Unit test core logic**: Test `_execute()` method independently
2. **Integration test workflows**: Test agent chains end-to-end
3. **Mock external services**: Use mocks for external dependencies in tests
4. **Performance test**: Verify agents meet timing requirements
5. **Error scenario testing**: Test failure modes and recovery

### Configuration Management

```python
# Use configuration for external settings
config = AgentConfig(
    agent_name="configured_agent",
    custom_settings={
        "api_endpoint": "https://threat-intel.example.com",
        "timeout_seconds": 30,
        "max_results": 100,
        "enable_caching": True
    }
)

class ConfiguredAgent(BaseAgent):
    def initialize(self):
        settings = self.config.custom_settings
        self.api_client = APIClient(
            endpoint=settings["api_endpoint"],
            timeout=settings["timeout_seconds"]
        )
        self.max_results = settings["max_results"] 
        self.cache_enabled = settings["enable_caching"]
```

## Troubleshooting

### Common Issues

**Agent initialization fails**
- Check external service connectivity
- Verify configuration parameters
- Review initialization logs
- Ensure required dependencies are installed

**Agent execution hangs**
- Check timeout configuration
- Review external service response times
- Look for deadlocks in tool usage
- Monitor resource utilization

**State validation errors**
- Verify agent outputs match expected schema
- Check data type consistency
- Review field validation rules
- Test with minimal state examples

**Performance issues**
- Profile agent execution time
- Check for memory leaks
- Review tool usage efficiency
- Consider caching strategies

### Debugging Tools

```python
# Enable debug logging
config = AgentConfig(
    agent_name="debug_agent",
    log_level="DEBUG"
)

# Access detailed metrics
agent = MyAgent(config)
result = agent.run(state)
metrics = agent.get_current_metrics()

print(f"Execution ID: {metrics.execution_id}")
print(f"Total time: {metrics.execution_time_ms}ms")
print(f"State changes: {metrics.state_changes}")
print(f"Tools used: {metrics.tools_used}")
```

### Health Monitoring

```python
# Check agent health
health = agent.get_health_status()
if not health.is_healthy:
    print(f"Agent unhealthy: {health.status_message}")
    print(f"Error rate: {health.error_count}/{health.success_count + health.error_count}")

# Monitor registry health
health_report = agent_registry.get_health_report()
for agent_name, health in health_report.items():
    if not health.is_healthy:
        print(f"WARNING: {agent_name} is unhealthy")
```

## Advanced Topics

### Custom Tool Integration

```python
class ToolIntegratedAgent(BaseAgent):
    def initialize(self):
        from tools.my_security_tool import MySecurityTool
        self.security_tool = MySecurityTool()
    
    def _execute(self, state: SOCState) -> SOCState:
        # Record tool usage for metrics
        self.use_tool("my_security_tool")
        
        # Use the tool
        result = self.security_tool.analyze(state["raw_alert"])
        
        # Process results
        return self.add_analysis_result(
            state,
            result=result,
            confidence=result.get("confidence", 50.0)
        )
```

### Dynamic Agent Selection

```python
def select_analysis_agent(state: SOCState) -> BaseAgent:
    """Dynamically select appropriate analysis agent"""
    alert_type = state["raw_alert"].get("event_type", "")
    
    if "malware" in alert_type.lower():
        return MalwareAnalysisAgent(AgentConfig(agent_name="malware_analyzer"))
    elif "network" in alert_type.lower():
        return NetworkAnalysisAgent(AgentConfig(agent_name="network_analyzer"))
    else:
        return GeneralAnalysisAgent(AgentConfig(agent_name="general_analyzer"))

# Use in workflow
analysis_agent = select_analysis_agent(current_state)
analyzed_state = analysis_agent.run(current_state)
```

### Agent Composition

```python
class CompositeAgent(BaseAgent):
    """Agent that orchestrates multiple sub-agents"""
    
    def initialize(self):
        self.sub_agents = [
            ThreatIntelAgent(AgentConfig(agent_name="threat_intel")),
            ReputationAgent(AgentConfig(agent_name="reputation")),
            BehaviorAgent(AgentConfig(agent_name="behavior"))
        ]
    
    def _execute(self, state: SOCState) -> SOCState:
        current_state = state
        
        for sub_agent in self.sub_agents:
            try:
                current_state = sub_agent.run(current_state)
                self.use_tool(sub_agent.config.agent_name)
            except Exception as e:
                self.logger.warning(f"Sub-agent {sub_agent.config.agent_name} failed: {e}")
                continue
        
        # Aggregate results
        return self.add_agent_note(
            current_state, 
            f"Composite analysis completed using {len(self.sub_agents)} sub-agents"
        )
```

### Async Agent Execution

```python
import asyncio
from typing import List

class AsyncAgent(BaseAgent):
    """Agent with async execution support"""
    
    async def _execute_async(self, state: SOCState) -> SOCState:
        """Async version of execute"""
        # Perform async operations
        results = await asyncio.gather(
            self.async_tool_1(state["raw_alert"]),
            self.async_tool_2(state["raw_alert"]),
            return_exceptions=True
        )
        
        # Process results
        updated_state = state
        for i, result in enumerate(results):
            if not isinstance(result, Exception):
                updated_state = self.add_analysis_result(
                    updated_state,
                    result={"tool": f"async_tool_{i+1}", "data": result},
                    confidence=75.0
                )
        
        return updated_state
    
    def _execute(self, state: SOCState) -> SOCState:
        """Sync wrapper for async execution"""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self._execute_async(state))

async def run_agents_parallel(agents: List[BaseAgent], state: SOCState) -> List[SOCState]:
    """Run multiple agents in parallel"""
    tasks = [
        asyncio.create_task(agent.run_async(state) if hasattr(agent, 'run_async') else agent.run(state))
        for agent in agents
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

## Migration Guide

### From Legacy Agent System

If migrating from an existing agent system:

1. **Wrap existing logic**: Put current agent code in `_execute()` method
2. **Add configuration**: Create `AgentConfig` for existing settings  
3. **Update interfaces**: Change method signatures to use `SOCState`
4. **Add monitoring**: Instrument with metrics collection
5. **Test thoroughly**: Verify behavior matches legacy system

```python
# Legacy agent wrapper example
class LegacyAgentWrapper(BaseAgent):
    def initialize(self):
        from legacy_system import LegacyAnalyzer
        self.legacy_analyzer = LegacyAnalyzer()
    
    def _execute(self, state: SOCState) -> SOCState:
        # Convert to legacy format
        legacy_input = self.convert_to_legacy_format(state)
        
        # Run legacy logic
        legacy_result = self.legacy_analyzer.analyze(legacy_input)
        
        # Convert back to new format
        return self.convert_from_legacy_format(state, legacy_result)
```

## API Reference

### BaseAgent Class

#### Methods

**`__init__(self, config: AgentConfig)`**
- Initializes agent with configuration
- Calls `initialize()` method
- Sets up logging and health monitoring

**`run(self, state: SOCState) -> SOCState`**
- Main execution entry point
- Handles validation, monitoring, and error recovery
- Calls `_execute()` for core logic

**`initialize(self)`** *(abstract)*
- Initialize agent-specific resources
- Called during construction
- Override in subclasses

**`_execute(self, state: SOCState) -> SOCState`** *(abstract)*
- Core agent execution logic
- Must be implemented by subclasses
- Called by `run()` method

**`add_agent_note(self, state: SOCState, note: str) -> SOCState`**
- Adds agent note to state
- Automatically uses agent name
- Updates state change metrics

**`add_analysis_result(self, state: SOCState, result: Dict, confidence: float, reasoning: str = None) -> SOCState`**
- Adds analysis result to state
- Includes execution time from metrics
- Updates state change counter

**`update_confidence_score(self, state: SOCState, score: float, reasoning: str = None) -> SOCState`**
- Updates confidence score with validation
- Optionally adds reasoning as agent note
- Updates state change metrics

**`use_tool(self, tool_name: str)`**
- Records tool usage for metrics
- Used for tracking external dependencies
- Enables performance analysis

**`get_health_status(self) -> AgentHealthCheck`**
- Returns current health status
- Includes success/error counts
- Shows average execution time

**`cleanup(self)`**
- Cleanup agent resources
- Override for custom cleanup logic
- Called by context manager

### AgentConfig Class

#### Fields

- `agent_name: str` - Unique agent identifier
- `version: str = "1.0.0"` - Agent version
- `timeout_seconds: int = 30` - Execution timeout
- `max_retries: int = 3` - Retry attempts on failure
- `enable_monitoring: bool = True` - Enable metrics collection
- `enable_state_validation: bool = True` - Validate input/output states
- `log_level: str = "INFO"` - Logging level
- `custom_settings: Dict[str, Any] = {}` - Agent-specific settings

### AgentRegistry Class

#### Methods

**`register_agent(self, agent: BaseAgent)`**
- Register agent instance
- Enables retrieval by name

**`get_agent(self, agent_name: str) -> Optional[BaseAgent]`**
- Retrieve agent by name
- Returns None if not found

**`list_agents(self) -> List[str]`**
- List all registered agent names

**`get_health_report(self) -> Dict[str, AgentHealthCheck]`**
- Get health status for all agents
- Returns dictionary by agent name

**`cleanup_all(self)`**
- Cleanup all registered agents
- Clears registry

## Conclusion

The Agent Framework provides a robust, scalable foundation for building security analysis agents. By following the patterns and best practices outlined in this guide, you can create agents that are:

- **Reliable**: Built-in error handling and retry logic
- **Observable**: Comprehensive metrics and health monitoring  
- **Maintainable**: Consistent interfaces and clear separation of concerns
- **Performant**: Optimized execution with performance monitoring
- **Testable**: Clear interfaces and dependency injection

The framework handles the complexities of state management, error recovery, and performance monitoring, allowing you to focus on implementing your agent's core security analysis logic.