from langgraph.graph import END, StateGraph

from agents.analysis import AnalysisAgent
from agents.base import AgentConfig
from agents.correlation import CorrelationAgent
from agents.ingestion import IngestionAgent
from agents.triage import TriageAgent
from core.state import SOCState


def should_continue_after_triage(state: SOCState) -> str:
    """Decision function for routing after triage"""
    confidence = state["confidence_score"]
    status = state["triage_status"]
    
    if status == "closed":
        return END
    elif confidence > 30.0:
        return "correlation"
    else:
        return "analysis"  # Skip correlation for low confidence

def should_escalate(state: SOCState) -> str:
    """Decision function after analysis"""
    confidence = state["confidence_score"]
    
    if confidence > 80.0:
        return "escalate"
    else:
        return END

def create_soc_workflow():
    """Create the main SOC processing workflow"""
    
    # Initialize the state graph
    workflow = StateGraph(SOCState)
    
    # Create agent instances
    agents = {
        'ingestion': IngestionAgent(AgentConfig(agent_name="ingestion_agent")),
        'triage': TriageAgent(AgentConfig(agent_name="triage_agent")), 
        'correlation': CorrelationAgent(AgentConfig(agent_name="correlation_agent")),
        'analysis': AnalysisAgent(AgentConfig(agent_name="analysis_agent"))
    }
    
    # Add nodes to the workflow
    for name, agent in agents.items():
        workflow.add_node(name, agent.run)
    
    # Add escalation node
    def escalate_alert(state: SOCState) -> SOCState:
        from core.state_manager import SOCStateManager
        return SOCStateManager.add_agent_note(
            state, 
            "escalation_system", 
            f"Alert escalated - confidence: {state['confidence_score']:.1f}%"
        )
    
    workflow.add_node("escalate", escalate_alert)
    
    # Define workflow flow
    workflow.set_entry_point("ingestion")
    workflow.add_edge("ingestion", "triage")
    
    # Conditional routing
    workflow.add_conditional_edges(
        "triage",
        should_continue_after_triage,
        {
            "correlation": "correlation",
            "analysis": "analysis", 
            END: END
        }
    )
    
    workflow.add_edge("correlation", "analysis")
    
    workflow.add_conditional_edges(
        "analysis", 
        should_escalate,
        {
            "escalate": "escalate",
            END: END
        }
    )
    
    workflow.add_edge("escalate", END)
    
    return workflow.compile()    