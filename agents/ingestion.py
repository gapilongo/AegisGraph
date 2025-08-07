# agents/ingestion.py
import os
import sys
from datetime import datetime
from typing import Any, Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from agents.base import AgentConfig, BaseAgent
from core.models import AlertSeverity, EnrichedData
from core.state import SOCState
from core.state_manager import SOCStateManager


class IngestionAgent(BaseAgent):
    """
    Ingestion agent responsible for initial alert processing and basic validation.
    """
    
    def initialize(self):
        """Initialize ingestion-specific resources"""
        self.logger.info("Initializing ingestion agent")
        # Initialize any external connections, validate configuration, etc.
        
    def _execute(self, state: SOCState) -> SOCState:
        """
        Process and validate incoming alerts.
        
        Args:
            state: Current SOC state with raw alert data
            
        Returns:
            SOCState: Updated state with initial processing completed
        """
        self.add_agent_note(state, "Starting alert ingestion and validation")
        
        # Extract alert data
        raw_alert = state["raw_alert"]
        alert_id = state["alert_id"]
        
        # Basic alert validation and normalization
        processed_alert = self._process_raw_alert(raw_alert)
        
        # Initial enrichment with basic metadata
        enriched_data = EnrichedData(
            asset_context={"ingestion_timestamp": datetime.utcnow().isoformat()},
            enrichment_timestamp=datetime.utcnow()
        )
        
        # Update state with processed data
        updated_state = SOCStateManager.update_state(
            state,
            raw_alert=processed_alert,
            enriched_data=enriched_data.model_dump(),
            workflow_step="ingestion_complete"
        )
        
        # Add analysis result
        analysis_result = {
            "ingestion_status": "success",
            "alert_normalized": True,
            "basic_validation": "passed"
        }
        
        updated_state = self.add_analysis_result(
            updated_state,
            result=analysis_result,
            confidence=100.0,
            reasoning="Alert successfully ingested and normalized"
        )
        
        self.add_agent_note(updated_state, f"Alert {alert_id} successfully ingested")
        
        return updated_state
    
    def _process_raw_alert(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Process and normalize raw alert data"""
        processed = raw_alert.copy()
        
        # Ensure timestamp is in ISO format
        if "timestamp" in processed:
            if isinstance(processed["timestamp"], datetime):
                processed["timestamp"] = processed["timestamp"].isoformat()
        
        # Normalize severity if present
        if "severity" in processed:
            severity = processed["severity"].lower()
            if severity in ["low", "medium", "high", "critical"]:
                processed["severity"] = severity
            else:
                processed["severity"] = "medium"  # Default
        
        return processed


# agents/triage.py
from typing import Dict, List, Tuple

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


# agents/correlation.py
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List

from agents.base import AgentConfig, BaseAgent
from core.state import SOCState
from core.state_manager import SOCStateManager


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


# agents/analysis.py
import random
from typing import Any, Dict, List, Optional

from agents.base import AgentConfig, BaseAgent
from core.models import TriageStatus
from core.state import SOCState
from core.state_manager import SOCStateManager


class AnalysisAgent(BaseAgent):
    """
    Analysis agent using ReAct pattern for deep investigation and tool orchestration.
    """
    
    def initialize(self):
        """Initialize analysis-specific resources"""
        self.logger.info("Initializing analysis agent")
        
        # Available tools for analysis
        self.available_tools = [
            "malware_scanner",
            "url_reputation",
            "ip_reputation", 
            "file_analysis",
            "network_analysis",
            "behavior_analysis"
        ]
        
        self.max_analysis_loops = 5
        
    def _execute(self, state: SOCState) -> SOCState:
        """
        Perform deep analysis using ReAct (Reason-Act-Observe) pattern.
        
        Args:
            state: Current SOC state
            
        Returns:
            SOCState: Updated state with detailed analysis results
        """
        self.add_agent_note(state, "Starting deep analysis with ReAct pattern")
        
        # Initialize analysis context
        analysis_context = {
            "observations": [],
            "actions_taken": [],
            "hypotheses": [],
            "evidence": {}
        }
        
        updated_state = state
        
        # ReAct loop: Reason -> Act -> Observe
        for loop_iteration in range(self.max_analysis_loops):
            self.logger.debug(f"Analysis loop iteration {loop_iteration + 1}")
            
            # REASON: Analyze current state and determine next action
            next_action = self._reason_next_action(updated_state, analysis_context)
            
            if next_action is None:
                self.add_agent_note(updated_state, "Analysis complete - no further actions needed")
                break
            
            # ACT: Execute the determined action
            action_result = self._execute_action(next_action, updated_state)
            analysis_context["actions_taken"].append({
                "action": next_action,
                "iteration": loop_iteration + 1,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # OBSERVE: Process action results and update context
            observation = self._observe_results(action_result, next_action)
            analysis_context["observations"].append(observation)
            analysis_context["evidence"][next_action] = action_result
            
            # Update state with new findings
            updated_state = self._update_state_with_findings(updated_state, action_result, next_action)
            
            progress_note = f"Loop {loop_iteration + 1}: Executed {next_action}, confidence now {updated_state['confidence_score']:.1f}%"
            updated_state = self.add_agent_note(updated_state, progress_note)
        
        # Finalize analysis with comprehensive results
        final_analysis = self._generate_final_analysis(analysis_context)
        updated_state = self._finalize_analysis_state(updated_state, final_analysis)
        
        return updated_state
    
    def _reason_next_action(self, state: SOCState, context: Dict[str, Any]) -> Optional[str]:
        """
        Reason about what action to take next based on current state and context.
        
        Args:
            state: Current state
            context: Analysis context with history
            
        Returns:
            str: Next action to take, or None if analysis is complete
        """
        raw_alert = state["raw_alert"]
        confidence = state["confidence_score"]
        actions_taken = [action["action"] for action in context["actions_taken"]]
        
        # If confidence is high enough, we can conclude
        if confidence > 85.0 and len(actions_taken) > 2:
            return None
        
        # Determine what analysis is still needed
        if "malware_scanner" not in actions_taken and self._has_file_indicators(raw_alert):
            return "malware_scanner"
        
        if "ip_reputation" not in actions_taken and self._has_ip_indicators(raw_alert):
            return "ip_reputation"
        
        if "url_reputation" not in actions_taken and self._has_url_indicators(raw_alert):
            return "url_reputation"
        
        if "network_analysis" not in actions_taken and confidence < 60.0:
            return "network_analysis"
        
        if "behavior_analysis" not in actions_taken and len(actions_taken) < 2:
            return "behavior_analysis"
        
        # If we've tried multiple tools but confidence is still low, try file analysis
        if "file_analysis" not in actions_taken and confidence < 50.0 and len(actions_taken) > 1:
            return "file_analysis"
        
        return None  # No more actions needed
    
    def _execute_action(self, action: str, state: SOCState) -> Dict[str, Any]:
        """
        Execute the specified analysis action.
        
        Args:
            action: Action to execute
            state: Current state
            
        Returns:
            Dict: Action execution results
        """
        self.use_tool(action)
        raw_alert = state["raw_alert"]
        
        # Simulate different tool executions
        if action == "malware_scanner":
            return self._simulate_malware_scan(raw_alert)
        elif action == "ip_reputation":
            return self._simulate_ip_reputation(raw_alert)
        elif action == "url_reputation":
            return self._simulate_url_reputation(raw_alert)
        elif action == "network_analysis":
            return self._simulate_network_analysis(raw_alert)
        elif action == "behavior_analysis":
            return self._simulate_behavior_analysis(raw_alert)
        elif action == "file_analysis":
            return self._simulate_file_analysis(raw_alert)
        else:
            return {"error": f"Unknown action: {action}"}
    
    def _observe_results(self, action_result: Dict[str, Any], action: str) -> Dict[str, Any]:
        """
        Observe and interpret the results of an action.
        
        Args:
            action_result: Results from action execution
            action: Action that was executed
            
        Returns:
            Dict: Observation summary
        """
        observation = {
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": action_result,
            "impact": "neutral"
        }
        
        # Interpret results to determine impact
        if action_result.get("threat_detected", False):
            observation["impact"] = "increases_confidence"
        elif action_result.get("clean_result", False):
            observation["impact"] = "decreases_confidence"
        elif action_result.get("suspicious_indicators", 0) > 0:
            observation["impact"] = "increases_confidence"
        
        return observation
    
    def _update_state_with_findings(self, state: SOCState, action_result: Dict[str, Any], action: str) -> SOCState:
        """Update state based on analysis findings"""
        current_confidence = state["confidence_score"]
        
        # Calculate confidence adjustment
        confidence_delta = 0.0
        
        if action_result.get("threat_detected", False):
            confidence_delta = 20.0
        elif action_result.get("clean_result", False):
            confidence_delta = -15.0
        elif action_result.get("suspicious_indicators", 0) > 2:
            confidence_delta = 10.0
        elif action_result.get("suspicious_indicators", 0) > 0:
            confidence_delta = 5.0
        
        new_confidence = max(0.0, min(100.0, current_confidence + confidence_delta))
        
        # Update confidence with reasoning
        reasoning = f"{action} analysis: {action_result.get('summary', 'completed')}"
        updated_state = self.update_confidence_score(state, new_confidence, reasoning)
        
        # Add analysis result
        updated_state = self.add_analysis_result(
            updated_state,
            result=action_result,
            confidence=new_confidence,
            reasoning=reasoning
        )
        
        return updated_state
    
    def _generate_final_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive final analysis"""
        actions_taken = context["actions_taken"]
        evidence = context["evidence"]
        
        # Compile threat indicators
        threat_indicators = []
        clean_indicators = []
        
        for action, result in evidence.items():
            if result.get("threat_detected"):
                threat_indicators.append(f"{action}: {result.get('threat_type', 'unknown')}")
            if result.get("clean_result"):
                clean_indicators.append(f"{action}: clean")
        
        return {
            "total_actions": len(actions_taken),
            "tools_used": [action["action"] for action in actions_taken],
            "threat_indicators": threat_indicators,
            "clean_indicators": clean_indicators,
            "analysis_duration": "comprehensive",
            "recommendation": self._generate_recommendation(threat_indicators, clean_indicators)
        }
    
    def _finalize_analysis_state(self, state: SOCState, final_analysis: Dict[str, Any]) -> SOCState:
        """Finalize state with complete analysis results"""
        # Add final analysis as next steps
        next_steps = state.get("next_steps", []).copy()
        next_steps.append(f"Analysis recommendation: {final_analysis['recommendation']}")
        
        # Update triage status if needed
        current_status = state["triage_status"]
        confidence = state["confidence_score"]
        
        if confidence > 80.0 and current_status != TriageStatus.ESCALATED.value:
            new_status = TriageStatus.ESCALATED.value
        elif confidence < 20.0 and len(final_analysis["clean_indicators"]) > 2:
            new_status = TriageStatus.CLOSED.value
        else:
            new_status = current_status
        
        updated_state = SOCStateManager.update_state(
            state,
            next_steps=next_steps,
            triage_status=new_status,
            workflow_step="analysis_complete"
        )
        
        summary_note = f"Deep analysis complete: {len(final_analysis['tools_used'])} tools used, confidence: {confidence:.1f}%"
        updated_state = self.add_agent_note(updated_state, summary_note)
        
        return updated_state
    
    # Simulation methods for different tools
    def _simulate_malware_scan(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate malware scanning results"""
        # Simulate based on alert content
        has_malware = "malware" in str(raw_alert).lower() or random.random() < 0.3
        
        return {
            "tool": "malware_scanner",
            "threat_detected": has_malware,
            "threat_type": "trojan" if has_malware else None,
            "suspicious_indicators": random.randint(0, 5) if has_malware else 0,
            "clean_result": not has_malware,
            "summary": "Malware detected" if has_malware else "No malware found"
        }
    
    def _simulate_ip_reputation(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate IP reputation check"""
        suspicious = random.random() < 0.4
        
        return {
            "tool": "ip_reputation",
            "threat_detected": suspicious,
            "reputation_score": random.randint(1, 40) if suspicious else random.randint(60, 100),
            "threat_categories": ["botnet", "malware"] if suspicious else [],
            "suspicious_indicators": random.randint(1, 3) if suspicious else 0,
            "clean_result": not suspicious,
            "summary": "Suspicious IP reputation" if suspicious else "Clean IP reputation"
        }
    
    def _simulate_url_reputation(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate URL reputation check"""
        malicious = random.random() < 0.35
        
        return {
            "tool": "url_reputation",
            "threat_detected": malicious,
            "url_category": "malware" if malicious else "legitimate",
            "suspicious_indicators": random.randint(2, 4) if malicious else 0,
            "clean_result": not malicious,
            "summary": "Malicious URL detected" if malicious else "URL appears clean"
        }
    
    def _simulate_network_analysis(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate network traffic analysis"""
        anomalous = random.random() < 0.25
        
        return {
            "tool": "network_analysis",
            "threat_detected": anomalous,
            "traffic_anomalies": random.randint(1, 3) if anomalous else 0,
            "suspicious_indicators": random.randint(1, 2) if anomalous else 0,
            "clean_result": not anomalous,
            "summary": "Network anomalies detected" if anomalous else "Normal network patterns"
        }
    
    def _simulate_behavior_analysis(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate behavioral analysis"""
        suspicious = random.random() < 0.5
        
        return {
            "tool": "behavior_analysis",
            "threat_detected": suspicious,
            "behavior_score": random.randint(1, 30) if suspicious else random.randint(70, 100),
            "suspicious_indicators": random.randint(1, 4) if suspicious else 0,
            "clean_result": not suspicious,
            "summary": "Suspicious behavior patterns" if suspicious else "Normal behavior patterns"
        }
    
    def _simulate_file_analysis(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate file analysis"""
        malicious = random.random() < 0.3
        
        return {
            "tool": "file_analysis",
            "threat_detected": malicious,
            "file_verdict": "malicious" if malicious else "benign",
            "suspicious_indicators": random.randint(2, 5) if malicious else random.randint(0, 1),
            "clean_result": not malicious,
            "summary": "Malicious file detected" if malicious else "File analysis clean"
        }
    
    def _generate_recommendation(self, threat_indicators: List[str], clean_indicators: List[str]) -> str:
        """Generate recommendation based on analysis results"""
        threat_count = len(threat_indicators)
        clean_count = len(clean_indicators)
        
        if threat_count > clean_count and threat_count >= 2:
            return "ESCALATE - Multiple threat indicators detected"
        elif clean_count > threat_count and clean_count >= 3:
            return "CLOSE - Multiple clean results, likely false positive"
        elif threat_count > 0:
            return "INVESTIGATE - Some suspicious indicators require human review"
        else:
            return "MONITOR - Continue monitoring for additional indicators"
    
    # Helper methods for reasoning
    def _has_file_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has file-related indicators"""
        content = str(raw_alert).lower()
        return any(indicator in content for indicator in ["file", "executable", "download", "attachment"])
    
    def _has_ip_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has IP-related indicators"""
        content = str(raw_alert).lower()
        return any(indicator in content for indicator in ["ip", "address", "connection", "network"])
    
    def _has_url_indicators(self, raw_alert: Dict[str, Any]) -> bool:
        """Check if alert has URL-related indicators"""
        content = str(raw_alert).lower()
        return any(indicator in content for indicator in ["url", "link", "http", "domain", "website"])