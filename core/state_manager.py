import json
import logging
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from core.exceptions import (
    StateSerializationError,
    StateValidationError,
    StateVersionError,
)
from core.models import (
    AlertData,
    AnalysisResult,
    EnrichedData,
    ProcessingEvent,
    SOCStateValidation,
    TriageStatus,
)
from core.state import CURRENT_SCHEMA_VERSION, SOCState
from utils.performance import benchmark_operation, validate_performance_requirement

logger = logging.getLogger(__name__)

class SOCStateManager:
    """
    Enhanced SOC state management with full validation, serialization,
    versioning, and performance optimization.
    """
    
    def __init__(self):
        self._migration_handlers = {
            "1.0.0": self._migrate_from_1_0_0
        }
    
    @staticmethod
    @validate_performance_requirement(max_time_ms=10.0)
    @benchmark_operation
    def create_initial_state(raw_alert_data: Dict[str, Any]) -> SOCState:
        """
        Create initial SOC state with comprehensive validation.
        
        Args:
            raw_alert_data: Raw alert data from SIEM
            
        Returns:
            SOCState: Validated initial state
            
        Raises:
            StateValidationError: If alert data is invalid
        """
        try:
            # Validate alert data
            alert_data = AlertData(**raw_alert_data)
            
            # Create full validation model
            validation_model = SOCStateValidation(raw_alert=alert_data)
            
            # Convert to LangGraph state
            state = SOCState(
                alert_id=validation_model.alert_id,
                created_at=validation_model.created_at.isoformat(),
                updated_at=validation_model.updated_at.isoformat(),
                version=validation_model.version,
                schema_version=CURRENT_SCHEMA_VERSION,
                raw_alert=validation_model.raw_alert.model_dump(),
                enriched_data=validation_model.enriched_data.model_dump(),
                triage_status=validation_model.triage_status.value,
                confidence_score=validation_model.confidence_score,
                fp_indicators=validation_model.fp_indicators.copy(),
                tp_indicators=validation_model.tp_indicators.copy(),
                human_feedback=validation_model.human_feedback,
                next_steps=validation_model.next_steps.copy(),
                agent_notes=validation_model.agent_notes.copy(),
                analysis_results=[],
                messages=[],
                processing_history=[],
                current_agent=validation_model.current_agent,
                workflow_step=validation_model.workflow_step
            )
            
            # Add creation event
            creation_event = ProcessingEvent(
                event_type="state_created",
                agent="state_manager",
                version=1,
                details={"alert_source": alert_data.source}
            )
            
            state["processing_history"] = [creation_event.model_dump()]
            
            logger.info(f"Created initial state for alert {state['alert_id']}")
            return state
            
        except Exception as e:
            logger.error(f"Failed to create initial state: {e}")
            raise StateValidationError(f"Invalid alert data: {e}")
    
    @staticmethod
    @validate_performance_requirement(max_time_ms=10.0)
    @benchmark_operation
    def validate_state(state: SOCState) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive state validation with detailed error reporting.
        
        Args:
            state: SOC state to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            # Validate alert data
            AlertData(**state["raw_alert"])
            
            # Validate enriched data if present
            if state["enriched_data"]:
                EnrichedData(**state["enriched_data"])
            
            # Validate confidence score bounds
            confidence = state["confidence_score"]
            if not 0.0 <= confidence <= 100.0:
                return False, f"Invalid confidence_score: {confidence} (must be 0-100)"
            
            # Validate triage status
            valid_statuses = [status.value for status in TriageStatus]
            if state["triage_status"] not in valid_statuses:
                return False, f"Invalid triage_status: {state['triage_status']}"
            
            # Validate analysis results
            for i, result_dict in enumerate(state["analysis_results"]):
                try:
                    AnalysisResult(**result_dict)
                except Exception as e:
                    return False, f"Invalid analysis_result[{i}]: {e}"
            
            # Validate processing history
            for i, event_dict in enumerate(state["processing_history"]):
                try:
                    ProcessingEvent(**event_dict)
                except Exception as e:
                    return False, f"Invalid processing_history[{i}]: {e}"
            
            # Validate version consistency
            if state["version"] < 1:
                return False, f"Invalid version: {state['version']} (must be >= 1)"
            
            return True, None
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    @staticmethod
    @validate_performance_requirement(max_time_ms=10.0)
    @benchmark_operation
    def update_state(state: SOCState, updates: Dict[str, Any] = None, **kwargs) -> SOCState:
        """
        Update state with validation and automatic timestamp/version increment.
        
        Args:
            state: Current state
            updates: Dictionary of updates to apply
            **kwargs: Additional updates passed as keyword arguments
            
        Returns:
            SOCState: Updated and validated state
            
        Raises:
            StateValidationError: If updated state is invalid
        """
        try:
            # Combine updates dictionary and keyword arguments
            all_updates = {}
            if updates:
                all_updates.update(updates)
            if kwargs:
                all_updates.update(kwargs)
            
            # Create new state with updates
            new_state = state.copy()
            new_state.update(all_updates)
            
            # Update metadata
            new_state["updated_at"] = datetime.utcnow().isoformat()
            new_state["version"] = state["version"] + 1
            
            # Validate updated state
            is_valid, error_msg = SOCStateManager.validate_state(new_state)
            if not is_valid:
                raise StateValidationError(f"Invalid state update: {error_msg}")
            
            # Add update event
            current_agent = new_state.get("current_agent") or "unknown"
            update_event = ProcessingEvent(
                event_type="state_updated",
                agent=current_agent,
                version=new_state["version"],
                details={"updated_fields": list(all_updates.keys())}
            )
            
            processing_history = new_state["processing_history"].copy()
            processing_history.append(update_event.model_dump())
            new_state["processing_history"] = processing_history
            
            logger.debug(f"Updated state {new_state['alert_id']} to version {new_state['version']}")
            return new_state
            
        except StateValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to update state: {e}")
            raise StateValidationError(f"State update failed: {e}")

    @staticmethod
    def add_agent_note(state: SOCState, agent_name: str, note: str) -> SOCState:
        """Add agent note with validation"""
        if not agent_name or not note:
            raise StateValidationError("Agent name and note cannot be empty")
        
        agent_notes = state.get("agent_notes", {}).copy()
        if agent_name not in agent_notes:
            agent_notes[agent_name] = []
        agent_notes[agent_name].append(note)
        
        updates = {
            "agent_notes": agent_notes,
            "current_agent": agent_name
        }
        return SOCStateManager.update_state(state, updates)
    
    @staticmethod
    def add_analysis_result(state: SOCState, result: AnalysisResult) -> SOCState:
        """Add analysis result with validation"""
        analysis_results = state["analysis_results"].copy()
        analysis_results.append(result.model_dump())
        
        return SOCStateManager.update_state(
            state,
            analysis_results=analysis_results,
            current_agent=result.agent_name
        )
    
    @staticmethod
    def set_confidence_score(state: SOCState, score: float, reasoning: str = None) -> SOCState:
        """Set confidence score with optional reasoning"""
        if not 0.0 <= score <= 100.0:
            raise StateValidationError(f"Invalid confidence score: {score}")
        
        updates = {"confidence_score": round(score, 2)}
        
        if reasoning:
            updated_state = SOCStateManager.add_agent_note(
                state, "confidence_engine", f"Score: {score} - {reasoning}"
            )
            return SOCStateManager.update_state(updated_state, **updates)
        
        return SOCStateManager.update_state(state, **updates)
    
    # JSON Serialization/Deserialization
    @staticmethod
    def to_json(state: SOCState) -> str:
        """
        Serialize state to JSON string.
        
        Args:
            state: SOC state to serialize
            
        Returns:
            str: JSON representation
            
        Raises:
            StateSerializationError: If serialization fails
        """
        try:
            # Custom encoder for datetime objects
            def json_encoder(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
            
            return json.dumps(state, default=json_encoder, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to serialize state: {e}")
            raise StateSerializationError(f"JSON serialization failed: {e}")
    
    @staticmethod
    def from_json(json_str: str) -> SOCState:
        """
        Deserialize state from JSON string.
        
        Args:
            json_str: JSON string representation
            
        Returns:
            SOCState: Deserialized and validated state
            
        Raises:
            StateSerializationError: If deserialization fails
            StateValidationError: If deserialized state is invalid
        """
        try:
            # Parse JSON
            state_dict = json.loads(json_str)
            
            # Create SOCState (TypedDict)
            state = SOCState(**state_dict)
            
            # Validate deserialized state
            is_valid, error_msg = SOCStateManager.validate_state(state)
            if not is_valid:
                raise StateValidationError(f"Invalid deserialized state: {error_msg}")
            
            return state
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format: {e}")
            raise StateSerializationError(f"Invalid JSON: {e}")
        except StateValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to deserialize state: {e}")
            raise StateSerializationError(f"JSON deserialization failed: {e}")
    
    # State Migration for Schema Evolution
    def migrate_state(self, state: SOCState, target_version: str = None) -> SOCState:
        """
        Migrate state to current or target schema version.
        
        Args:
            state: State to migrate
            target_version: Target schema version (default: current)
            
        Returns:
            SOCState: Migrated state
            
        Raises:
            StateVersionError: If migration fails
        """
        current_version = state.get("schema_version", "1.0.0")
        target_version = target_version or CURRENT_SCHEMA_VERSION
        
        if current_version == target_version:
            return state
        
        try:
            # Apply migration handlers
            migrated_state = state.copy()
            
            if current_version in self._migration_handlers:
                migrated_state = self._migration_handlers[current_version](migrated_state)
            
            migrated_state["schema_version"] = target_version
            
            # Validate migrated state
            is_valid, error_msg = SOCStateManager.validate_state(migrated_state)
            if not is_valid:
                raise StateVersionError(f"Migration validation failed: {error_msg}")
            
            logger.info(f"Migrated state from {current_version} to {target_version}")
            return migrated_state
            
        except Exception as e:
            logger.error(f"State migration failed: {e}")
            raise StateVersionError(f"Migration from {current_version} to {target_version} failed: {e}")
    
    def _migrate_from_1_0_0(self, state: SOCState) -> SOCState:
        """Migration handler for version 1.0.0"""
        # Example migration: add new fields, modify existing ones
        migrated = state.copy()
        
        # Add any new fields with defaults
        if "new_field_example" not in migrated:
            migrated["new_field_example"] = "default_value"
        
        return migrated
    
    # Performance optimized operations
    @staticmethod
    def clone_state(state: SOCState) -> SOCState:
        """Create a deep copy of state optimally"""
        return {
            key: (value.copy() if isinstance(value, (dict, list)) else value)
            for key, value in state.items()
        }