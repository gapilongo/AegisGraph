"""
SOC workflow with complete ingestion agent integration
Supports the full LangGraph ReAct agent workflow shown in the diagram
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, List

from langgraph.graph import END, StateGraph

from agents.analysis import AnalysisAgent
from agents.base import AgentConfig
from agents.correlation import CorrelationAgent
from agents.ingestion import (
    IngestionAgent,
    create_ingestion_agent,
)
from agents.triage import TriageAgent
from core.state import SOCState
from core.state_manager import SOCStateManager


def create_soc_workflow():
    """Create SOC workflow with full ingestion capabilities"""
    
    # Initialize the state graph
    workflow = StateGraph(SOCState)
    
    # Create agent instances
    agents = {
        'ingestion': create_ingestion_agent(
            polling_interval_seconds=30,
            batch_size=100,
            max_concurrent_polls=3,
            dedup_window_minutes=60,
            dedup_threshold=0.8
        ),
        'triage': TriageAgent(AgentConfig(
            agent_name="triage_agent",
            timeout_seconds=60,
            custom_settings={
                "fp_confidence_threshold": 20.0,
                "tp_confidence_threshold": 75.0,
                "enable_ml_classification": True
            }
        )),
        'correlation': CorrelationAgent(AgentConfig(
            agent_name="correlation_agent",
            timeout_seconds=120,
            custom_settings={
                "correlation_window_hours": 24,
                "max_related_events": 50,
                "enable_threat_intel": True
            }
        )),
        'analysis': AnalysisAgent(AgentConfig(
            agent_name="analysis_agent",
            timeout_seconds=300,
            custom_settings={
                "max_analysis_loops": 7,
                "enable_deep_analysis": True,
                "tool_timeout_seconds": 60
            }
        ))
    }
    
    # Add nodes to the workflow
    for name, agent in agents.items():
        workflow.add_node(name, agent.run)
    
    # Add decision nodes
    def should_continue_after_ingestion(state: SOCState) -> str:
        """Decision after ingestion - always proceed to triage"""
        ingestion_results = state.get("analysis_results", [])
        
        # Check if ingestion was successful
        for result in ingestion_results:
            if (result.get("agent_name") == "ingestion_agent" and 
                result.get("result", {}).get("ingestion_status") == "success"):
                return "triage"
        
        # If no successful ingestion, end the workflow
        return END
    
    def should_continue_after_triage(state: SOCState) -> str:
        """decision function for routing after triage"""
        confidence = state["confidence_score"]
        status = state["triage_status"]
        fp_indicators = state.get("fp_indicators", [])
        
        # If marked as closed (likely FP), end workflow
        if status == "closed":
            return END
        
        # If too many FP indicators, close
        if len(fp_indicators) > 3:
            return "close_alert"
        
        # If high confidence and already escalated, go to human review
        if confidence > 85.0 and status == "escalated":
            return "human_review"
        
        # If medium to high confidence, do correlation
        if confidence > 40.0:
            return "correlation"
        
        # If low confidence, skip correlation and go straight to analysis
        return "analysis"
    
    def should_continue_after_correlation(state: SOCState) -> str:
        """Decision function after correlation"""
        confidence = state["confidence_score"]
        
        # Always proceed to analysis after correlation
        return "analysis"
    
    def should_escalate_after_analysis(state: SOCState) -> str:
        """decision function after analysis"""
        confidence = state["confidence_score"]
        status = state["triage_status"]
        
        # Check analysis results for threats
        analysis_results = state.get("analysis_results", [])
        threat_indicators = 0
        
        for result in analysis_results:
            if result.get("agent_name") == "analysis_agent":
                result_data = result.get("result", {})
                threat_indicators += len(result_data.get("threat_indicators", []))
        
        # High confidence or multiple threat indicators = escalate
        if confidence > 80.0 or threat_indicators >= 2:
            return "escalate"
        
        # Medium confidence = human review
        if confidence > 50.0:
            return "human_review"
        
        # Low confidence = close
        return "close_alert"
    
    def needs_human_review(state: SOCState) -> str:
        """Decision function for human review requirement"""
        confidence = state["confidence_score"]
        
        # If confidence is borderline, needs human review
        if 40.0 <= confidence <= 75.0:
            return "human_review"
        
        # If very high confidence, escalate directly
        if confidence > 75.0:
            return "escalate"
        
        # Low confidence, close
        return "close_alert"
    
    # Add escalation and closure nodes
    def escalate_alert(state: SOCState) -> SOCState:
        """Escalate alert to human analysts"""
        escalation_note = (
            f"Alert escalated - confidence: {state['confidence_score']:.1f}%, "
            f"requires immediate analyst attention"
        )
        
        updated_state = SOCStateManager.update_state(
            state,
            triage_status="escalated",
            workflow_step="escalated"
        )
        
        return SOCStateManager.add_agent_note(
            updated_state,
            "escalation_system",
            escalation_note
        )
    
    def close_alert(state: SOCState) -> SOCState:
        """Close alert as false positive or low priority"""
        closure_reason = "Closed by automated analysis"
        
        if state["confidence_score"] < 20.0:
            closure_reason = "Closed - likely false positive"
        elif len(state.get("fp_indicators", [])) > 2:
            closure_reason = "Closed - multiple false positive indicators"
        
        updated_state = SOCStateManager.update_state(
            state,
            triage_status="closed",
            workflow_step="closed"
        )
        
        return SOCStateManager.add_agent_note(
            updated_state,
            "closure_system",
            closure_reason
        )
    
    def human_review_needed(state: SOCState) -> SOCState:
        """Mark alert for human review"""
        review_note = (
            f"Alert requires human review - confidence: {state['confidence_score']:.1f}%, "
            f"automated analysis inconclusive"
        )
        
        updated_state = SOCStateManager.update_state(
            state,
            triage_status="pending_review",
            workflow_step="human_review"
        )
        
        return SOCStateManager.add_agent_note(
            updated_state,
            "review_system",
            review_note
        )
    
    # Add action nodes
    workflow.add_node("escalate", escalate_alert)
    workflow.add_node("close_alert", close_alert)
    workflow.add_node("human_review", human_review_needed)
    
    # Define workflow flow
    workflow.set_entry_point("ingestion")
    
    # Ingestion -> Triage (always)
    workflow.add_conditional_edges(
        "ingestion",
        should_continue_after_ingestion,
        {
            "triage": "triage",
            END: END
        }
    )
    
    # Triage -> Correlation/Analysis/Close/Human Review
    workflow.add_conditional_edges(
        "triage",
        should_continue_after_triage,
        {
            "correlation": "correlation",
            "analysis": "analysis",
            "close_alert": "close_alert",
            "human_review": "human_review",
            END: END
        }
    )
    
    # Correlation -> Analysis (always)
    workflow.add_conditional_edges(
        "correlation",
        should_continue_after_correlation,
        {
            "analysis": "analysis"
        }
    )
    
    # Analysis -> Escalate/Human Review/Close
    workflow.add_conditional_edges(
        "analysis",
        should_escalate_after_analysis,
        {
            "escalate": "escalate",
            "human_review": "human_review",
            "close_alert": "close_alert"
        }
    )
    
    # Human Review -> Escalate/Close
    workflow.add_conditional_edges(
        "human_review",
        needs_human_review,
        {
            "escalate": "escalate",
            "close_alert": "close_alert",
            "human_review": "human_review"
        }
    )
    
    # All terminal nodes end the workflow
    workflow.add_edge("escalate", END)
    workflow.add_edge("close_alert", END)
    
    return workflow.compile()


async def create_initial_state_from_ingestion() -> SOCState:
    """Create initial state that triggers the ingestion process"""
    
    # Create a minimal alert that will trigger ingestion
    raw_alert = {
        'timestamp': datetime.utcnow(),
        'source': 'ingestion_trigger',
        'event_type': 'polling_cycle',
        'severity': 'low',
        'description': 'Triggered SIEM polling cycle'
    }
    
    return SOCStateManager.create_initial_state(raw_alert)


async def run_continuous_ingestion_workflow(polling_interval_seconds: int = 30):
    """
    Run continuous ingestion workflow
    
    This function demonstrates how the ingestion agent can run continuously,
    polling SIEM systems and processing alerts through the workflow.
    """
    import logging
    
    logger = logging.getLogger("continuous_ingestion")
    
    # Create the workflow
    workflow = create_soc_workflow()
    
    logger.info("Starting continuous ingestion workflow")
    
    try:
        while True:
            try:
                # Create initial state for this polling cycle
                initial_state = await create_initial_state_from_ingestion()
                
                logger.info(f"Starting ingestion cycle: {initial_state['alert_id']}")
                
                # Run the workflow
                final_state = await workflow.ainvoke(initial_state)
                
                # Log results
                workflow_step = final_state.get("workflow_step", "unknown")
                confidence = final_state.get("confidence_score", 0.0)
                
                logger.info(
                    f"Ingestion cycle completed: {final_state['alert_id']} -> "
                    f"{workflow_step} (confidence: {confidence:.1f}%)"
                )
                
                # Extract ingestion metrics if available
                for result in final_state.get("analysis_results", []):
                    if result.get("agent_name") == "ingestion_agent":
                        ingestion_data = result.get("result", {})
                        alerts_count = ingestion_data.get("alerts_ingested", 0)
                        if alerts_count > 0:
                            logger.info(f"Processed {alerts_count} alerts in this cycle")
                
            except Exception as e:
                logger.error(f"Error in ingestion cycle: {e}")
            
            # Wait for next polling interval
            await asyncio.sleep(polling_interval_seconds)
            
    except KeyboardInterrupt:
        logger.info("Continuous ingestion stopped by user")
    except Exception as e:
        logger.error(f"Fatal error in continuous ingestion: {e}")
        raise


class SOC005WorkflowManager:
    """
    Manager class for SOC-005 ingestion workflow operations
    Provides high-level interface for workflow control and monitoring
    """
    
    def __init__(self, polling_interval_seconds: int = 30):
        self.polling_interval = polling_interval_seconds
        self.workflow = create_soc_workflow()
        self.logger = logging.getLogger("soc005_manager")
        self.is_running = False
        self.current_task = None
        self.stats = {
            "cycles_completed": 0,
            "total_alerts_processed": 0,
            "escalated_alerts": 0,
            "closed_alerts": 0,
            "errors": 0,
            "start_time": None
        }
    
    async def start_continuous_operation(self):
        """Start continuous ingestion operations"""
        if self.is_running:
            raise RuntimeError("Workflow manager is already running")
        
        self.is_running = True
        self.stats["start_time"] = datetime.utcnow()
        
        self.logger.info("Starting SOC-005 continuous operations")
        
        try:
            self.current_task = asyncio.create_task(self._run_continuous_loop())
            await self.current_task
        except asyncio.CancelledError:
            self.logger.info("Continuous operations cancelled")
        except Exception as e:
            self.logger.error(f"Fatal error in continuous operations: {e}")
            raise
        finally:
            self.is_running = False
    
    async def stop_continuous_operation(self):
        """Stop continuous ingestion operations"""
        if not self.is_running or not self.current_task:
            return
        
        self.logger.info("Stopping SOC-005 continuous operations")
        self.current_task.cancel()
        
        try:
            await self.current_task
        except asyncio.CancelledError:
            pass
        
        self.is_running = False
        self.current_task = None
    
    async def run_single_cycle(self) -> Dict:
        """Run a single ingestion cycle and return results"""
        try:
            # Create initial state
            initial_state = await create_initial_state_from_ingestion()
            
            # Run workflow
            final_state = await self.workflow.ainvoke(initial_state)
            
            # Extract results
            result = {
                "alert_id": final_state["alert_id"],
                "workflow_step": final_state.get("workflow_step", "unknown"),
                "confidence_score": final_state.get("confidence_score", 0.0),
                "triage_status": final_state.get("triage_status", "unknown"),
                "processing_time": (
                    datetime.fromisoformat(final_state["updated_at"]) - 
                    datetime.fromisoformat(final_state["created_at"])
                ).total_seconds(),
                "alerts_processed": 0
            }
            
            # Extract ingestion metrics
            for analysis_result in final_state.get("analysis_results", []):
                if analysis_result.get("agent_name") == "ingestion_agent":
                    ingestion_data = analysis_result.get("result", {})
                    result["alerts_processed"] = ingestion_data.get("alerts_ingested", 0)
                    result["ingestion_rate"] = ingestion_data.get("processing_rate_alerts_per_second", 0.0)
            
            # Update statistics
            self._update_stats(result)
            
            return result
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error in single cycle: {e}")
            raise
    
    async def _run_continuous_loop(self):
        """Internal continuous loop implementation"""
        while self.is_running:
            try:
                result = await self.run_single_cycle()
                
                self.logger.info(
                    f"Cycle completed: {result['alerts_processed']} alerts, "
                    f"final status: {result['workflow_step']}"
                )
                
            except Exception as e:
                self.logger.error(f"Error in continuous loop: {e}")
            
            # Wait for next cycle
            await asyncio.sleep(self.polling_interval)
    
    def _update_stats(self, cycle_result: Dict):
        """Update internal statistics"""
        self.stats["cycles_completed"] += 1
        self.stats["total_alerts_processed"] += cycle_result.get("alerts_processed", 0)
        
        status = cycle_result.get("workflow_step", "")
        if status == "escalated":
            self.stats["escalated_alerts"] += 1
        elif status == "closed":
            self.stats["closed_alerts"] += 1
    
    def get_statistics(self) -> Dict:
        """Get operational statistics"""
        stats = self.stats.copy()
        
        if stats["start_time"]:
            uptime = (datetime.utcnow() - stats["start_time"]).total_seconds()
            stats["uptime_seconds"] = uptime
            stats["cycles_per_hour"] = (stats["cycles_completed"] / uptime) * 3600 if uptime > 0 else 0
            stats["alerts_per_hour"] = (stats["total_alerts_processed"] / uptime) * 3600 if uptime > 0 else 0
        
        return stats
    
    async def test_siem_connectivity(self) -> Dict[str, bool]:
        """Test connectivity to all configured SIEM systems"""
        # Get ingestion agent from workflow
        ingestion_agent = None
        
        # This is a simplified way to test - in practice you'd want to access
        # the agent more directly or have a dedicated test method
        try:
            initial_state = await create_initial_state_from_ingestion()
            
            # Create a standalone ingestion agent for testing
            test_agent = create_ingestion_agent()
            
            return await test_agent.test_all_siems()
            
        except Exception as e:
            self.logger.error(f"SIEM connectivity test failed: {e}")
            return {}


# Demonstration and testing functions
async def demonstrate_soc005_implementation():
    """
    Demonstrate the complete SOC-005 implementation
    This function shows all acceptance criteria being met
    """
    import logging
    
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("soc005_demo")
    
    logger.info("=== SOC-005 Implementation Demonstration ===")
    
    # Create workflow manager
    manager = SOC005WorkflowManager(polling_interval_seconds=10)  # Fast for demo
    
    try:
        # Test 1: SIEM Connectivity
        logger.info("Testing SIEM connectivity...")
        connectivity_results = await manager.test_siem_connectivity()
        logger.info(f"SIEM connectivity: {connectivity_results}")
        
        # Test 2: Single ingestion cycle
        logger.info("Running single ingestion cycle...")
        cycle_result = await manager.run_single_cycle()
        logger.info(f"Single cycle result: {cycle_result}")
        
        # Test 3: Performance measurement
        logger.info("Testing performance requirements...")
        start_time = time.time()
        
        # Run multiple cycles to test performance
        for i in range(5):
            result = await manager.run_single_cycle()
            logger.info(f"Cycle {i+1}: {result['alerts_processed']} alerts processed")
        
        total_time = time.time() - start_time
        logger.info(f"Performance test: 5 cycles in {total_time:.2f} seconds")
        
        # Test 4: Statistics and monitoring
        stats = manager.get_statistics()
        logger.info(f"Current statistics: {stats}")
        
        # Test 5: Brief continuous operation (10 seconds)
        logger.info("Testing continuous operation for 10 seconds...")
        continuous_task = asyncio.create_task(manager.start_continuous_operation())
        
        await asyncio.sleep(10)
        await manager.stop_continuous_operation()
        
        final_stats = manager.get_statistics()
        logger.info(f"Final statistics: {final_stats}")
        
        logger.info("=== SOC-005 Demonstration Complete ===")
        
        return {
            "connectivity_test": connectivity_results,
            "performance_test": {"cycles": 5, "total_time": total_time},
            "final_statistics": final_stats,
            "status": "success"
        }
        
    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
        return {"status": "failed", "error": str(e)}


if __name__ == "__main__":
    # Run the demonstration
    import logging
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the complete demonstration
    result = asyncio.run(demonstrate_soc005_implementation())
    print(f"\nDemonstration result: {result}")