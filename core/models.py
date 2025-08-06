import uuid
from datetime import datetime
from enum import Enum
from turtle import mode
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator, root_validator, validator


class TriageStatus(str, Enum):
    """Triage status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    CLOSED = "closed"

class AlertSeverity(str, Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertData(BaseModel):
    """Alert data validation model with enhanced constraints"""
    timestamp: datetime
    source: str
    event_type: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('source')
    def validate_source(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('source cannot be empty')
        if len(v.strip()) > 100:
            raise ValueError('source must be less than 100 characters')
        return v.strip()
    
    @validator('event_type')
    def validate_event_type(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('event_type cannot be empty')
        return v.strip()

class EnrichedData(BaseModel):
    """Enriched data validation model"""
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    asset_context: Dict[str, Any] = Field(default_factory=dict) 
    historical_context: Dict[str, Any] = Field(default_factory=dict)
    correlation_data: Dict[str, Any] = Field(default_factory=dict)
    enrichment_timestamp: datetime = Field(default_factory=datetime.utcnow)

class AnalysisResult(BaseModel):
    """Analysis result validation model with enhanced validation"""
    agent_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    result: Dict[str, Any]
    confidence: float = Field(ge=0.0, le=100.0)
    reasoning: Optional[str] = None
    execution_time_ms: Optional[float] = None
    
    @validator('agent_name')
    def validate_agent_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('agent_name cannot be empty')
        return v.strip()
    
    @validator('confidence')
    def validate_confidence(cls, v):
        """Ensure confidence is properly rounded"""
        return round(v, 2)

class ProcessingEvent(BaseModel):
    """Processing event validation model"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    agent: str
    version: int
    details: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('event_type')
    def validate_event_type(cls, v):
        allowed_types = [
            'state_created', 'state_updated', 'agent_started', 
            'agent_completed', 'error_occurred', 'human_feedback_received'
        ]
        if v not in allowed_types:
            raise ValueError(f'event_type must be one of: {allowed_types}')
        return v

# Complete state validation model
class SOCStateValidation(BaseModel):
    """Complete state validation using Pydantic"""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    version: int = Field(default=1, ge=1)
    schema_version: str = Field(default="1.0.0")
    
    raw_alert: AlertData
    enriched_data: EnrichedData = Field(default_factory=EnrichedData)
    
    triage_status: TriageStatus = Field(default=TriageStatus.PENDING)
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    
    fp_indicators: List[str] = Field(default_factory=list)
    tp_indicators: List[str] = Field(default_factory=list)
    
    human_feedback: Optional[Dict[str, Any]] = None
    
    next_steps: List[str] = Field(default_factory=list)
    agent_notes: Dict[str, List[str]] = Field(default_factory=dict)
    
    analysis_results: List[AnalysisResult] = Field(default_factory=list)
    processing_history: List[ProcessingEvent] = Field(default_factory=list)
    
    current_agent: Optional[str] = None
    workflow_step: str = Field(default="ingestion")
    
    @validator('confidence_score')
    def validate_confidence_score(cls, v):
        """Ensure confidence score is within valid range and properly rounded"""
        if not 0.0 <= v <= 100.0:
            raise ValueError('confidence_score must be between 0 and 100')
        return round(v, 2)
    
    @model_validator(mode='after')
    def validate_state_consistency(self):
        """Validate overall state consistency"""
        # Access instance attributes directly
        triage_status = self.triage_status
        confidence_score = self.confidence_score
        
        # High confidence should align with triage status
        if confidence_score > 80 and triage_status == TriageStatus.PENDING:
            self.triage_status = TriageStatus.TRIAGED
        
        # Version should be at least 1
        if self.version < 1:
            self.version = 1
            
        return self
    
    def increment_version(self):
        """Increment version and update timestamp"""
        self.version += 1
        self.updated_at = datetime.utcnow()
    
    class Config:
        use_enum_values = True
        validate_assignment = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }