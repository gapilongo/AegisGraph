import hashlib
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List

from agents.base import AgentConfig, BaseAgent
from core.state import SOCState
from core.state_manager import SOCStateManager

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))


class CorrelationAgent(BaseAgent):
    """
    Correlation agent responsible for finding related events and historical context.
    """
    
    def initialize(self):
        """Initialize correlation-specific resources"""
        self.logger.info("Initializing correlation agent")
        
        # In a real implementation, this would connect to databases, 
        # SIEM systems, threat intelligence feeds, etc.
        self.correlation_window_hours = 24
        
    def _execute(self, state: SOCState) -> SOCState:
        """
        Perform event correlation and historical analysis.
        
        Args:
            state: Current SOC state
            
        Returns:
            SOCState: Updated state with correlation results
        """
        self.add_agent_note(state, "Starting event correlation and historical analysis")
        
        raw_alert = state["raw_alert"]
        
        # Simulate tool usage for correlation
        self.use_tool("siem_database")
        self.use_tool("threat_intelligence")
        
        # Perform correlation analysis
        related_events = self._find_related_events(raw_alert)
        historical_context = self._analyze_historical_context(raw_alert)
        correlation_score = self._calculate_correlation_score(related_events)
        
        # Update enriched data with correlation results
        enriched_data = state["enriched_data"].copy()
        enriched_data["correlation_data"] = {
            "related_events_count": len(related_events),
            "correlation_score": correlation_score,
            "analysis_window_hours": self.correlation_window_hours,
            "correlation_timestamp": datetime.utcnow().isoformat()
        }
        enriched_data["historical_context"] = historical_context
        
        # Update state
        updated_state = SOCStateManager.update_state(
            state,
            enriched_data=enriched_data
        )
        
        # Adjust confidence based on correlation results
        confidence_adjustment = self._calculate_confidence_adjustment(correlation_score, len(related_events))
        new_confidence = min(100.0, state["confidence_score"] + confidence_adjustment)
        
        reasoning = f"Correlation analysis: {len(related_events)} related events, score: {correlation_score:.1f}"
        updated_state = self.update_confidence_score(updated_state, new_confidence, reasoning)
        
        # Add correlation analysis result
        analysis_result = {
            "related_events_found": len(related_events),
            "correlation_score": correlation_score,
            "confidence_adjustment": confidence_adjustment,
            "historical_patterns": len(historical_context)
        }
        
        updated_state = self.add_analysis_result(
            updated_state,
            result=analysis_result,
            confidence=new_confidence,
            reasoning=reasoning
        )
        
        correlation_note = f"Found {len(related_events)} related events with correlation score {correlation_score:.1f}"
        updated_state = self.add_agent_note(updated_state, correlation_note)
        
        return updated_state
    
    def _find_related_events(self, raw_alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find events related to the current alert"""
        # Simulate database query for related events
        # In practice, this would query SIEM, databases, etc.
        
        source_ip = raw_alert.get("source_ip")
        event_type = raw_alert.get("event_type")
        
        # Simulate finding related events
        related_events = []
        
        if source_ip:
            # Simulate finding events from same IP
            for i in range(3):  # Mock 3 related events
                related_events.append({
                    "event_id": f"related_{source_ip}_{i}",
                    "timestamp": (datetime.utcnow() - timedelta(hours=i+1)).isoformat(),
                    "source_ip": source_ip,
                    "event_type": event_type,
                    "severity": "medium"
                })
        
        return related_events
    
    def _analyze_historical_context(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze historical context for the alert"""
        # Simulate historical analysis
        
        context = {
            "similar_alerts_30d": 5,
            "false_positive_rate": 0.2,
            "escalation_rate": 0.7,
            "avg_resolution_time_hours": 4.5,
            "last_occurrence": (datetime.utcnow() - timedelta(days=7)).isoformat(),
            "trending": "increasing"
        }
        
        return context
    
    def _calculate_correlation_score(self, related_events: List[Dict[str, Any]]) -> float:
        """Calculate correlation score based on related events"""
        if not related_events:
            return 0.0
        
        # Simple scoring based on number and recency of events
        base_score = min(len(related_events) * 20.0, 80.0)  # Max 80 points for events
        
        # Bonus for recent events
        recent_events = sum(1 for event in related_events 
                          if (datetime.utcnow() - datetime.fromisoformat(event["timestamp"])).hours < 6)
        recency_bonus = recent_events * 5.0
        
        return min(100.0, base_score + recency_bonus)
    
    def _calculate_confidence_adjustment(self, correlation_score: float, related_count: int) -> float:
        """Calculate confidence adjustment based on correlation results"""
        if correlation_score > 70.0:
            return 15.0  # High correlation increases confidence
        elif correlation_score > 40.0:
            return 5.0   # Medium correlation slight increase
        elif related_count == 0:
            return -10.0  # No correlation decreases confidence
        else:
            return 0.0   # Neutral
            return 0.0   # Neutral
