import os
import random
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
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