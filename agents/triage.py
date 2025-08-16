import os
import sys
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from agents.base import AgentConfig, BaseAgent
from core.models import TriageStatus
from core.state import SOCState
from core.state_manager import SOCStateManager


class TriageAgent(BaseAgent):
    """
    Triage agent responsible for initial alert classification and false positive detection.
    """
    
    def initialize(self):
        """Initialize triage-specific resources"""
        self.logger.info("Initializing triage agent")
        
        # Load false positive patterns and rules
        self.fp_patterns = self._load_fp_patterns()
        self.tp_indicators = self._load_tp_indicators()
        
    def _execute(self, state: SOCState) -> SOCState:
        """
        Perform initial triage and classification.
        
        Args:
            state: Current SOC state
            
        Returns:
            SOCState: Updated state with triage results
        """
        self.add_agent_note(state, "Starting alert triage and classification")
        
        raw_alert = state["raw_alert"]
        
        # Analyze for false positive indicators
        fp_indicators = self._detect_fp_indicators(raw_alert)
        tp_indicators = self._detect_tp_indicators(raw_alert)
        
        # Calculate initial confidence score
        confidence_score = self._calculate_triage_confidence(fp_indicators, tp_indicators)
        
        # Determine triage status
        triage_status = self._determine_triage_status(confidence_score, fp_indicators)
        
        # Update state with triage results
        updated_state = SOCStateManager.update_state(
            state,
            triage_status=triage_status.value,
            fp_indicators=fp_indicators,
            tp_indicators=tp_indicators
        )
        
        # Update confidence score with reasoning
        reasoning = f"Triage analysis: {len(fp_indicators)} FP indicators, {len(tp_indicators)} TP indicators"
        updated_state = self.update_confidence_score(updated_state, confidence_score, reasoning)
        
        # Add triage analysis result
        analysis_result = {
            "triage_decision": triage_status.value,
            "fp_indicator_count": len(fp_indicators),
            "tp_indicator_count": len(tp_indicators),
            "confidence_reasoning": reasoning
        }
        
        updated_state = self.add_analysis_result(
            updated_state,
            result=analysis_result,
            confidence=confidence_score,
            reasoning=reasoning
        )
        
        decision_note = f"Triage decision: {triage_status.value} (confidence: {confidence_score:.1f}%)"
        updated_state = self.add_agent_note(updated_state, decision_note)
        
        return updated_state
    
    def _load_fp_patterns(self) -> List[str]:
        """Load false positive detection patterns"""
        # This would typically load from configuration or database
        return [
            "scheduled_maintenance",
            "known_admin_activity",
            "approved_software_installation",
            "routine_backup_operation"
        ]
    
    def _load_tp_indicators(self) -> List[str]:
        """Load true positive indicators"""
        return [
            "suspicious_process_execution",
            "unauthorized_access_attempt",
            "malware_detection",
            "data_exfiltration_pattern",
            "lateral_movement"
        ]
    
    def _detect_fp_indicators(self, raw_alert: Dict) -> List[str]:
        """Detect false positive indicators in alert"""
        indicators = []
        
        # Simple pattern matching (would be more sophisticated in practice)
        alert_content = str(raw_alert).lower()
        
        for pattern in self.fp_patterns:
            if pattern.replace("_", " ") in alert_content:
                indicators.append(pattern)
        
        return indicators
    
    def _detect_tp_indicators(self, raw_alert: Dict) -> List[str]:
        """Detect true positive indicators in alert"""
        indicators = []
        
        alert_content = str(raw_alert).lower()
        
        for indicator in self.tp_indicators:
            if indicator.replace("_", " ") in alert_content:
                indicators.append(indicator)
        
        return indicators
    
    def _calculate_triage_confidence(self, fp_indicators: List[str], tp_indicators: List[str]) -> float:
        """Calculate confidence score based on indicators"""
        # Simple scoring algorithm (would be more sophisticated in practice)
        base_score = 50.0  # Neutral starting point
        
        # Adjust based on indicators
        fp_penalty = len(fp_indicators) * 15.0  # Each FP indicator reduces confidence
        tp_bonus = len(tp_indicators) * 20.0     # Each TP indicator increases confidence
        
        confidence = base_score - fp_penalty + tp_bonus
        
        # Clamp to valid range
        return max(0.0, min(100.0, confidence))
    
    def _determine_triage_status(self, confidence_score: float, fp_indicators: List[str]) -> TriageStatus:
        """Determine triage status based on analysis"""
        if len(fp_indicators) > 2:
            return TriageStatus.CLOSED  # Likely false positive
        elif confidence_score > 75.0:
            return TriageStatus.ESCALATED  # High confidence threat
        elif confidence_score > 40.0:
            return TriageStatus.TRIAGED  # Needs further analysis
        else:
            return TriageStatus.IN_PROGRESS  # Uncertain, continue processing
