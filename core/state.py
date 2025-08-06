from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages


# LangGraph State Schema with proper constraints
class SOCState(TypedDict):
    """
    LangGraph state schema for SOC alert processing.
    All data that flows between nodes in the workflow.
    """
    # Core identification
    alert_id: str
    created_at: str  # ISO format string
    updated_at: str  # ISO format string
    version: int
    schema_version: str  # NEW: For schema evolution support
    
    # Alert data (validated externally)
    raw_alert: Dict[str, Any]
    enriched_data: Dict[str, Any]
    
    # Triage information
    triage_status: str  # TriageStatus enum value
    confidence_score: float  # 0.0-100.0 (validated externally)
    
    # Classification indicators
    fp_indicators: List[str]
    tp_indicators: List[str]
    
    # Human feedback
    human_feedback: Optional[Dict[str, Any]]
    
    # Next steps and notes
    next_steps: List[str]
    agent_notes: Dict[str, List[str]]
    
    # Analysis results
    analysis_results: List[Dict[str, Any]]
    
    # LangGraph messages
    messages: Annotated[List[BaseMessage], add_messages]
    
    # Processing metadata
    processing_history: List[Dict[str, Any]]
    current_agent: Optional[str]
    workflow_step: str

# State schema version for evolution tracking
CURRENT_SCHEMA_VERSION = "1.0.0"