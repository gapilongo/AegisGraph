import json
import os
import sys
import time
from datetime import datetime, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))


import pytest

from core.exceptions import (
    StateSerializationError,
    StateValidationError,
    StateVersionError,
)
from core.models import AlertData, AnalysisResult, TriageStatus
from core.state import CURRENT_SCHEMA_VERSION, SOCState
from core.state_manager import SOCStateManager


class TestSOCStateManager:
    """Comprehensive test suite for SOC state management"""
    
    def test_create_initial_state_valid(self):
        """Test creating valid initial state"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly',
            'severity': 'high'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        assert state["alert_id"] is not None
        assert len(state["alert_id"]) == 36  # UUID length
        assert state["triage_status"] == TriageStatus.PENDING.value
        assert state["confidence_score"] == 0.0
        assert state["version"] == 1
        assert state["schema_version"] == CURRENT_SCHEMA_VERSION
        assert state["workflow_step"] == "ingestion"
        assert len(state["processing_history"]) == 1
        assert state["processing_history"][0]["event_type"] == "state_created"
    
    def test_create_initial_state_invalid_alert(self):
        """Test creating state with invalid alert data"""
        # Missing required fields
        with pytest.raises(StateValidationError):
            SOCStateManager.create_initial_state({})
        
        # Empty source
        with pytest.raises(StateValidationError):
            SOCStateManager.create_initial_state({
                'timestamp': datetime.utcnow(),
                'source': '',
                'event_type': 'test'
            })
        
        # Invalid severity
        with pytest.raises(StateValidationError):
            SOCStateManager.create_initial_state({
                'timestamp': datetime.utcnow(),
                'source': 'test_siem',
                'event_type': 'test',
                'severity': 'invalid'
            })
    
    def test_state_validation_valid(self):
        """Test validation of valid state"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        is_valid, error_msg = SOCStateManager.validate_state(state)
        
        assert is_valid is True
        assert error_msg is None
    
    def test_state_validation_invalid_confidence(self):
        """Test validation with invalid confidence score"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        state["confidence_score"] = 150.0  # Invalid
        
        is_valid, error_msg = SOCStateManager.validate_state(state)
        
        assert is_valid is False
        assert "confidence_score" in error_msg
    
    def test_state_validation_invalid_status(self):
        """Test validation with invalid triage status"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        state["triage_status"] = "invalid_status"
        
        is_valid, error_msg = SOCStateManager.validate_state(state)
        
        assert is_valid is False
        assert "triage_status" in error_msg
    
    def test_update_state_valid(self):
        """Test valid state updates"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        original_version = state["version"]
        original_updated_at = state["updated_at"]
        
        # Small delay to ensure timestamp difference
        time.sleep(0.001)
        
        updated_state = SOCStateManager.update_state(
            state,
            confidence_score=75.5,
            triage_status=TriageStatus.TRIAGED.value
        )
        
        assert updated_state["confidence_score"] == 75.5
        assert updated_state["triage_status"] == TriageStatus.TRIAGED.value
        assert updated_state["version"] == original_version + 1
        assert updated_state["updated_at"] > original_updated_at
        assert len(updated_state["processing_history"]) == 2  # Creation + update
    
    def test_update_state_invalid(self):
        """Test invalid state updates"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Invalid confidence score
        with pytest.raises(StateValidationError):
            SOCStateManager.update_state(state, confidence_score=150.0)
        
        # Invalid triage status
        with pytest.raises(StateValidationError):
            SOCStateManager.update_state(state, triage_status="invalid")
    
    def test_add_agent_note_valid(self):
        """Test adding valid agent notes"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        updated_state = SOCStateManager.add_agent_note(
            state, 'triage_agent', 'Suspicious login detected'
        )
        
        assert 'triage_agent' in updated_state["agent_notes"]
        assert 'Suspicious login detected' in updated_state["agent_notes"]['triage_agent']
        assert updated_state["current_agent"] == 'triage_agent'
        assert updated_state["version"] > state["version"]
    
    def test_add_agent_note_invalid(self):
        """Test adding invalid agent notes"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Empty agent name
        with pytest.raises(StateValidationError):
            SOCStateManager.add_agent_note(state, '', 'note')
        
        # Empty note
        with pytest.raises(StateValidationError):
            SOCStateManager.add_agent_note(state, 'agent', '')
    
    def test_add_analysis_result(self):
        """Test adding analysis results"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        analysis_result = AnalysisResult(
            agent_name='correlation_agent',
            result={'correlation_score': 0.8, 'related_events': 5},
            confidence=85.0,
            reasoning='Multiple related events found in 24h window'
        )
        
        updated_state = SOCStateManager.add_analysis_result(state, analysis_result)
        
        assert len(updated_state["analysis_results"]) == 1
        result = updated_state["analysis_results"][0]
        assert result["agent_name"] == 'correlation_agent'
        assert result["confidence"] == 85.0
        assert updated_state["current_agent"] == 'correlation_agent'
    
    def test_set_confidence_score_valid(self):
        """Test setting valid confidence scores"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Without reasoning
        updated_state = SOCStateManager.set_confidence_score(state, 88.5)
        assert updated_state["confidence_score"] == 88.5
        
        # With reasoning
        updated_state2 = SOCStateManager.set_confidence_score(
            updated_state, 95.2, "High correlation with known attack patterns"
        )
        assert updated_state2["confidence_score"] == 95.2
        assert 'confidence_engine' in updated_state2["agent_notes"]
    
    def test_set_confidence_score_invalid(self):
        """Test setting invalid confidence scores"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Score too high
        with pytest.raises(StateValidationError):
            SOCStateManager.set_confidence_score(state, 150.0)
        
        # Score too low
        with pytest.raises(StateValidationError):
            SOCStateManager.set_confidence_score(state, -10.0)
    
    def test_json_serialization_valid(self):
        """Test JSON serialization of valid state"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Add some complexity to the state
        state = SOCStateManager.add_agent_note(state, 'test_agent', 'test note')
        state = SOCStateManager.set_confidence_score(state, 75.5)
        
        json_str = SOCStateManager.to_json(state)
        
        assert isinstance(json_str, str)
        assert len(json_str) > 0
        
        # Verify it's valid JSON
        parsed = json.loads(json_str)
        assert parsed["alert_id"] == state["alert_id"]
        assert parsed["confidence_score"] == 75.5
    
    def test_json_deserialization_valid(self):
        """Test JSON deserialization of valid state"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        original_state = SOCStateManager.create_initial_state(raw_alert)
        original_state = SOCStateManager.set_confidence_score(original_state, 88.5)
        
        # Serialize then deserialize
        json_str = SOCStateManager.to_json(original_state)
        restored_state = SOCStateManager.from_json(json_str)
        
        assert restored_state["alert_id"] == original_state["alert_id"]
        assert restored_state["confidence_score"] == original_state["confidence_score"]
        assert restored_state["version"] == original_state["version"]
        assert restored_state["triage_status"] == original_state["triage_status"]
    
    def test_json_deserialization_invalid(self):
        """Test JSON deserialization with invalid data"""
        # Invalid JSON
        with pytest.raises(StateSerializationError):
            SOCStateManager.from_json("invalid json")
        
        # Valid JSON but invalid state
        invalid_state_json = json.dumps({
            "alert_id": "test",
            "confidence_score": 150.0,  # Invalid
            "raw_alert": {"timestamp": "2024-01-01", "source": "test", "event_type": "test"}
        })
        
        with pytest.raises(StateValidationError):
            SOCStateManager.from_json(invalid_state_json)
    
    def test_state_cloning(self):
        """Test state cloning functionality"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        original_state = SOCStateManager.create_initial_state(raw_alert)
        original_state = SOCStateManager.add_agent_note(original_state, 'test_agent', 'test note')
        
        cloned_state = SOCStateManager.clone_state(original_state)
        
        # Should be equal but different objects
        assert cloned_state["alert_id"] == original_state["alert_id"]
        assert cloned_state is not original_state
        assert cloned_state["agent_notes"] is not original_state["agent_notes"]
        
        # Modifications to clone shouldn't affect original
        cloned_state["confidence_score"] = 50.0
        assert original_state["confidence_score"] != cloned_state["confidence_score"]

class TestStatePerformance:
    """Performance tests to meet <10ms requirement"""
    
    def test_state_creation_performance(self):
        """Test state creation performance (<10ms per operation)"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        # Warm up
        for _ in range(10):
            SOCStateManager.create_initial_state(raw_alert)
        
        # Actual benchmark
        start_time = time.perf_counter()
        iterations = 100
        
        for _ in range(iterations):
            SOCStateManager.create_initial_state(raw_alert)
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        assert avg_time < 0.01, f"State creation took {avg_time*1000:.2f}ms (should be <10ms)"
    
    def test_state_validation_performance(self):
        """Test state validation performance (<10ms per operation)"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Warm up
        for _ in range(10):
            SOCStateManager.validate_state(state)
        
        # Actual benchmark
        start_time = time.perf_counter()
        iterations = 100
        
        for _ in range(iterations):
            SOCStateManager.validate_state(state)
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        assert avg_time < 0.01, f"State validation took {avg_time*1000:.2f}ms (should be <10ms)"
    
    def test_state_update_performance(self):
        """Test state update performance (<10ms per operation)"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Warm up
        for i in range(10):
            state = SOCStateManager.update_state(state, confidence_score=float(i))
        
        # Actual benchmark
        start_time = time.perf_counter()
        iterations = 100
        
        for i in range(iterations):
            state = SOCStateManager.update_state(state, confidence_score=float(i % 100))
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        assert avg_time < 0.01, f"State update took {avg_time*1000:.2f}ms (should be <10ms)"
    
    def test_json_serialization_performance(self):
        """Test JSON serialization performance"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Add complexity to state
        for i in range(10):
            state = SOCStateManager.add_agent_note(state, f'agent_{i}', f'note_{i}')
        
        # Warm up
        for _ in range(10):
            json_str = SOCStateManager.to_json(state)
            SOCStateManager.from_json(json_str)
        
        # Actual benchmark
        start_time = time.perf_counter()
        iterations = 100
        
        for _ in range(iterations):
            json_str = SOCStateManager.to_json(state)
            SOCStateManager.from_json(json_str)
        
        end_time = time.perf_counter()
        avg_time = (end_time - start_time) / iterations
        
        assert avg_time < 0.01, f"JSON serialization took {avg_time*1000:.2f}ms (should be <10ms)"

class TestStateMigration:
    """Test state migration for schema evolution"""
    
    def test_migration_same_version(self):
        """Test migration when state is already current version"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        manager = SOCStateManager()
        
        migrated_state = manager.migrate_state(state)
        
        # Should be unchanged
        assert migrated_state["schema_version"] == CURRENT_SCHEMA_VERSION
        assert migrated_state["alert_id"] == state["alert_id"]
    
    def test_migration_from_old_version(self):
        """Test migration from older schema version"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        # Simulate old version
        state["schema_version"] = "1.0.0"
        
        manager = SOCStateManager()
        migrated_state = manager.migrate_state(state)
        
        assert migrated_state["schema_version"] == CURRENT_SCHEMA_VERSION
        # Should still be valid
        is_valid, error_msg = SOCStateManager.validate_state(migrated_state)
        assert is_valid, f"Migration failed validation: {error_msg}"

class TestEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_empty_agent_notes(self):
        """Test handling of empty agent notes"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Empty agent notes should be valid
        assert len(state["agent_notes"]) == 0
        is_valid, error_msg = SOCStateManager.validate_state(state)
        assert is_valid
    
    def test_large_state_handling(self):
        """Test handling of states with large amounts of data"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Add many agent notes
        for i in range(100):
            state = SOCStateManager.add_agent_note(
                state, f'agent_{i}', f'This is a long note with lots of details: {i}' * 10
            )
        
        # Should still be valid and performant
        start_time = time.perf_counter()
        is_valid, error_msg = SOCStateManager.validate_state(state)
        validation_time = time.perf_counter() - start_time
        
        assert is_valid, f"Large state validation failed: {error_msg}"
        assert validation_time < 0.1, f"Large state validation too slow: {validation_time*1000:.2f}ms"
    
    def test_concurrent_state_updates(self):
        """Test handling of concurrent state updates"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Simulate concurrent updates (should not interfere)
        state1 = SOCStateManager.add_agent_note(state, 'agent1', 'note1')
        state2 = SOCStateManager.add_agent_note(state, 'agent2', 'note2')
        
        # Both should be valid independent updates
        is_valid1, _ = SOCStateManager.validate_state(state1)
        is_valid2, _ = SOCStateManager.validate_state(state2)
        
        assert is_valid1
        assert is_valid2
        assert state1["version"] == state2["version"]  # Both increment from same base
        assert 'agent1' in state1["agent_notes"]
        assert 'agent2' in state2["agent_notes"]

# Integration tests
class TestLangGraphIntegration:
    """Test integration with LangGraph components"""
    
    def test_state_compatibility_with_langgraph(self):
        """Test that our state is compatible with LangGraph TypedDict requirements"""
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'login_anomaly'
        }
        
        state = SOCStateManager.create_initial_state(raw_alert)
        
        # Should be able to access all fields as dict
        assert isinstance(state, dict)
        assert "alert_id" in state
        assert "messages" in state
        assert isinstance(state["messages"], list)
        
        # Should support LangGraph message operations
        from langchain_core.messages import HumanMessage

        # This would be done by LangGraph internally
        state["messages"].append(HumanMessage(content="Test message"))
        
        is_valid, error_msg = SOCStateManager.validate_state(state)
        assert is_valid, f"State with messages failed validation: {error_msg}"

# Test coverage report
def test_coverage():
    """Ensure we have comprehensive test coverage"""
    import inspect

    from core.state_manager import SOCStateManager

    # Get all public methods
    methods = [name for name, method in inspect.getmembers(SOCStateManager, predicate=inspect.ismethod)
              if not name.startswith('_')]
    
    static_methods = [name for name, method in inspect.getmembers(SOCStateManager, predicate=inspect.isfunction)
                     if not name.startswith('_')]
    
    all_methods = methods + static_methods
    
    # We should have tests for all public methods
    tested_methods = [
        'create_initial_state', 'validate_state', 'update_state', 
        'add_agent_note', 'add_analysis_result', 'set_confidence_score',
        'to_json', 'from_json', 'migrate_state', 'clone_state'
    ]
    
    for method in all_methods:
        assert method in tested_methods, f"Missing test for method: {method}"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])