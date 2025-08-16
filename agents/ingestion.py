import asyncio
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from agents.base import AgentConfig, BaseAgent
from config.config_manager import get_config_manager
from core.models import AlertData, EnrichedData, TriageStatus
from core.state import SOCState
from core.state_manager import SOCStateManager
from tools.siem_connectors import (
    AlertDeduplicator,
    SIEMAlert,
    SIEMConnectorFactory,
)


class IngestionMetrics:
    """Metrics tracking for ingestion operations"""
    
    def __init__(self):
        self.alerts_processed = 0
        self.alerts_deduplicated = 0
        self.alerts_failed = 0
        self.siem_polls = 0
        self.total_processing_time_ms = 0.0
        self.start_time = datetime.utcnow()
        self.last_poll_times: Dict[str, datetime] = {}
        self.processing_rates: List[float] = []
    
    def record_poll(self, siem_name: str, alert_count: int, processing_time_ms: float):
        """Record polling metrics"""
        self.siem_polls += 1
        self.alerts_processed += alert_count
        self.total_processing_time_ms += processing_time_ms
        self.last_poll_times[siem_name] = datetime.utcnow()
        
        # Calculate processing rate (alerts per second)
        if processing_time_ms > 0:
            rate = (alert_count * 1000) / processing_time_ms
            self.processing_rates.append(rate)
            
            # Keep only last 100 measurements
            if len(self.processing_rates) > 100:
                self.processing_rates.pop(0)
    
    def record_deduplication(self, count: int):
        """Record deduplicated alerts"""
        self.alerts_deduplicated += count
    
    def record_failure(self, count: int = 1):
        """Record failed alerts"""
        self.alerts_failed += count
    
    def get_current_rate(self) -> float:
        """Get current processing rate (alerts/second)"""
        if not self.processing_rates:
            return 0.0
        
        # Return average of last 10 measurements
        recent_rates = self.processing_rates[-10:]
        return sum(recent_rates) / len(recent_rates)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            "uptime_seconds": uptime,
            "alerts_processed": self.alerts_processed,
            "alerts_deduplicated": self.alerts_deduplicated,
            "alerts_failed": self.alerts_failed,
            "siem_polls": self.siem_polls,
            "total_processing_time_ms": self.total_processing_time_ms,
            "avg_processing_time_ms": self.total_processing_time_ms / max(self.siem_polls, 1),
            "current_rate_alerts_per_second": self.get_current_rate(),
            "overall_rate_alerts_per_second": self.alerts_processed / max(uptime, 1),
            "last_poll_times": {k: v.isoformat() for k, v in self.last_poll_times.items()},
            "deduplication_rate": self.alerts_deduplicated / max(self.alerts_processed + self.alerts_deduplicated, 1)
        }


class IngestionAgent(BaseAgent):
    """
     Ingestion Agent implementing SOC-005 requirements:
    - Multi-SIEM support (Splunk, QRadar, Sentinel)
    - Configurable polling and batch processing
    - Authentication with multiple methods
    - Rate limiting and exponential backoff
    - Error handling and retry logic
    - Alert deduplication
    - Performance: 100+ alerts/second
    """
    
    def initialize(self):
        """Initialize ingestion-specific resources"""
        self.logger.info("Initializing  ingestion agent")
        
        # Get configuration
        config_manager = get_config_manager()
        self.siem_configs = config_manager.config.siem_connections
        
        # Initialize components
        self.deduplicator = AlertDeduplicator(
            time_window_minutes=self.config.custom_settings.get("dedup_window_minutes", 60),
            similarity_threshold=self.config.custom_settings.get("dedup_threshold", 0.8)
        )
        
        self.metrics = IngestionMetrics()
        
        # Polling configuration
        self.polling_interval = self.config.custom_settings.get("polling_interval_seconds", 30)
        self.batch_size = self.config.custom_settings.get("batch_size", 100)
        self.max_concurrent_polls = self.config.custom_settings.get("max_concurrent_polls", 3)
        
        # State tracking
        self.last_poll_times: Dict[str, datetime] = {}
        self.active_connectors: Dict[str, Any] = {}
        self.is_polling = False
        
        # Performance targets
        self.target_rate_alerts_per_second = 100
        self.performance_check_interval = 60  # seconds
        self.last_performance_check = datetime.utcnow()
        
        self.logger.info(f"Configured for {len(self.siem_configs)} SIEM systems")
        self.logger.info(f"Polling interval: {self.polling_interval}s, Batch size: {self.batch_size}")
    
    def _execute(self, state: SOCState) -> SOCState:
        """
        Execute ReAct pattern for ingestion:
        Reason -> Act -> Observe
        """
        self.add_agent_note(state, "Starting ReAct ingestion cycle")
        
        # REASON: Analyze what needs to be done
        reasoning = self._reason_about_ingestion()
        updated_state = self.add_agent_note(state, f"Reasoning: {reasoning}")
        
        # ACT: Execute the determined action
        action_result = self._execute_ingestion_action(reasoning)
        
        # OBSERVE: Process results and update state
        observation = self._observe_ingestion_results(action_result)
        final_state = self.add_agent_note(updated_state, f"Observation: {observation}")
        
        # Update state with ingestion results
        if action_result.get("alerts"):
            final_state = self._process_ingested_alerts(final_state, action_result["alerts"])
        
        return final_state
    
    def _reason_about_ingestion(self) -> str:
        """Reason about what ingestion action to take"""
        current_time = datetime.utcnow()
        
        # Check if we need to start polling
        if not self.is_polling:
            return "start_polling"
        
        # Check if we need to poll specific SIEMs
        siems_to_poll = []
        for siem_name in self.siem_configs.keys():
            last_poll = self.last_poll_times.get(siem_name)
            if not last_poll or (current_time - last_poll).total_seconds() >= self.polling_interval:
                siems_to_poll.append(siem_name)
        
        if siems_to_poll:
            return f"poll_siems:{','.join(siems_to_poll)}"
        
        # Check performance metrics
        if (current_time - self.last_performance_check).total_seconds() >= self.performance_check_interval:
            return "check_performance"
        
        # Check deduplication statistics
        if self.metrics.alerts_processed > 0:
            dedup_rate = self.metrics.alerts_deduplicated / (self.metrics.alerts_processed + self.metrics.alerts_deduplicated)
            if dedup_rate > 0.5:  # High duplication rate
                return "adjust_deduplication"
        
        return "monitor_status"
    
    def _execute_ingestion_action(self, reasoning: str) -> Dict[str, Any]:
        """Execute the determined ingestion action"""
        action_type = reasoning.split(":")[0]
        
        if action_type == "start_polling":
            return self._start_polling()
        elif action_type == "poll_siems":
            siem_names = reasoning.split(":")[1].split(",")
            return asyncio.run(self._poll_multiple_siems(siem_names))
        elif action_type == "check_performance":
            return self._check_performance()
        elif action_type == "adjust_deduplication":
            return self._adjust_deduplication()
        elif action_type == "monitor_status":
            return self._monitor_status()
        else:
            return {"error": f"Unknown action: {action_type}"}
    
    def _observe_ingestion_results(self, action_result: Dict[str, Any]) -> str:
        """Observe and interpret ingestion results"""
        if "error" in action_result:
            return f"Error occurred: {action_result['error']}"
        
        if "alerts" in action_result:
            alert_count = len(action_result["alerts"])
            dedup_count = action_result.get("deduplicated_count", 0)
            processing_time = action_result.get("processing_time_ms", 0)
            
            if alert_count > 0:
                rate = (alert_count * 1000) / max(processing_time, 1)
                return f"Processed {alert_count} alerts ({dedup_count} deduped) at {rate:.1f} alerts/sec"
            else:
                return "No new alerts found"
        
        if "performance" in action_result:
            current_rate = action_result["performance"]["current_rate"]
            target_rate = self.target_rate_alerts_per_second
            
            if current_rate >= target_rate:
                return f"Performance excellent: {current_rate:.1f}/{target_rate} alerts/sec"
            else:
                return f"Performance below target: {current_rate:.1f}/{target_rate} alerts/sec"
        
        return f"Action completed: {action_result.get('status', 'success')}"
    
    def _start_polling(self) -> Dict[str, Any]:
        """Start the polling process"""
        try:
            self.is_polling = True
            self.logger.info("Started SIEM polling")
            return {"status": "polling_started", "siem_count": len(self.siem_configs)}
        except Exception as e:
            self.logger.error(f"Failed to start polling: {e}")
            return {"error": str(e)}
    
    async def _poll_multiple_siems(self, siem_names: List[str]) -> Dict[str, Any]:
        """Poll multiple SIEM systems concurrently"""
        start_time = time.perf_counter()
        all_alerts = []
        total_deduped = 0
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent_polls)
        
        async def poll_single_siem(siem_name: str) -> List[SIEMAlert]:
            """Poll a single SIEM system"""
            async with semaphore:
                return await self._poll_siem(siem_name)
        
        try:
            # Create tasks for concurrent polling
            tasks = [poll_single_siem(siem_name) for siem_name in siem_names]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for siem_name, result in zip(siem_names, results):
                if isinstance(result, Exception):
                    self.logger.error(f"Polling {siem_name} failed: {result}")
                    self.metrics.record_failure()
                else:
                    # Deduplicate alerts
                    original_count = len(result)
                    deduplicated_alerts = [alert for alert in result if not self.deduplicator.is_duplicate(alert)]
                    deduped_count = original_count - len(deduplicated_alerts)
                    
                    all_alerts.extend(deduplicated_alerts)
                    total_deduped += deduped_count
                    
                    self.last_poll_times[siem_name] = datetime.utcnow()
                    self.logger.info(f"Polled {siem_name}: {len(deduplicated_alerts)} alerts ({deduped_count} deduped)")
            
            processing_time_ms = (time.perf_counter() - start_time) * 1000
            
            # Record metrics
            self.metrics.record_poll("multiple", len(all_alerts), processing_time_ms)
            self.metrics.record_deduplication(total_deduped)
            
            return {
                "alerts": all_alerts,
                "deduplicated_count": total_deduped,
                "processing_time_ms": processing_time_ms,
                "siem_count": len(siem_names)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to poll SIEMs: {e}")
            return {"error": str(e)}
    
    async def _poll_siem(self, siem_name: str) -> List[SIEMAlert]:
        """Poll a single SIEM system"""
        if siem_name not in self.siem_configs:
            raise ValueError(f"SIEM {siem_name} not configured")
        
        siem_config = self.siem_configs[siem_name]
        
        # Get or create connector
        if siem_name not in self.active_connectors:
            self.active_connectors[siem_name] = SIEMConnectorFactory.create_connector(
                siem_config, self.logger
            )
        
        connector = self.active_connectors[siem_name]
        
        # Calculate since time (last poll or default lookback)
        last_poll = self.last_poll_times.get(siem_name)
        if last_poll:
            since = last_poll
        else:
            # Default to 1 hour lookback for first poll
            since = datetime.utcnow() - timedelta(hours=1)
        
        try:
            async with connector:
                alerts = await connector.fetch_alerts(since=since, limit=self.batch_size)
                self.use_tool(f"siem_{siem_name}")
                return alerts
                
        except Exception as e:
            self.logger.error(f"Failed to poll {siem_name}: {e}")
            raise
    
    def _check_performance(self) -> Dict[str, Any]:
        """Check ingestion performance"""
        try:
            stats = self.metrics.get_stats()
            current_rate = stats["current_rate_alerts_per_second"]
            
            self.last_performance_check = datetime.utcnow()
            
            # Performance analysis
            performance_status = "excellent" if current_rate >= self.target_rate_alerts_per_second else "below_target"
            
            # Recommendations based on performance
            recommendations = []
            if current_rate < self.target_rate_alerts_per_second * 0.8:
                recommendations.append("Consider increasing batch size")
                recommendations.append("Check SIEM response times")
                recommendations.append("Review rate limiting settings")
            
            if stats["deduplication_rate"] > 0.3:
                recommendations.append("High duplication rate detected")
                recommendations.append("Consider adjusting deduplication window")
            
            return {
                "performance": stats,
                "status": performance_status,
                "recommendations": recommendations
            }
            
        except Exception as e:
            return {"error": f"Performance check failed: {e}"}
    
    def _adjust_deduplication(self) -> Dict[str, Any]:
        """Adjust deduplication parameters based on current metrics"""
        try:
            current_rate = self.metrics.get_stats()["deduplication_rate"]
            
            if current_rate > 0.5:
                # High duplication - increase similarity threshold
                new_threshold = min(self.deduplicator.similarity_threshold + 0.1, 0.95)
                self.deduplicator.similarity_threshold = new_threshold
                self.logger.info(f"Increased deduplication threshold to {new_threshold}")
                
            elif current_rate < 0.1:
                # Low duplication - decrease similarity threshold
                new_threshold = max(self.deduplicator.similarity_threshold - 0.1, 0.5)
                self.deduplicator.similarity_threshold = new_threshold
                self.logger.info(f"Decreased deduplication threshold to {new_threshold}")
            
            return {
                "status": "adjusted",
                "new_threshold": self.deduplicator.similarity_threshold,
                "current_dedup_rate": current_rate
            }
            
        except Exception as e:
            return {"error": f"Deduplication adjustment failed: {e}"}
    
    def _monitor_status(self) -> Dict[str, Any]:
        """Monitor overall ingestion status"""
        try:
            stats = self.metrics.get_stats()
            dedup_stats = self.deduplicator.get_stats()
            
            # Health checks
            health_issues = []
            
            # Check if all SIEMs are responding
            for siem_name in self.siem_configs.keys():
                last_poll = self.last_poll_times.get(siem_name)
                if not last_poll:
                    health_issues.append(f"SIEM {siem_name} never polled")
                elif (datetime.utcnow() - last_poll).total_seconds() > self.polling_interval * 2:
                    health_issues.append(f"SIEM {siem_name} polling delayed")
            
            # Check error rates
            if stats["alerts_failed"] > 0:
                error_rate = stats["alerts_failed"] / max(stats["alerts_processed"] + stats["alerts_failed"], 1)
                if error_rate > 0.1:  # >10% error rate
                    health_issues.append(f"High error rate: {error_rate:.1%}")
            
            status = "healthy" if not health_issues else "degraded"
            
            return {
                "status": status,
                "health_issues": health_issues,
                "ingestion_stats": stats,
                "deduplication_stats": dedup_stats,
                "active_siems": list(self.last_poll_times.keys())
            }
            
        except Exception as e:
            return {"error": f"Status monitoring failed: {e}"}
    
    def _process_ingested_alerts(self, state: SOCState, alerts: List[SIEMAlert]) -> SOCState:
        """Process ingested alerts and create new states for the pipeline"""
        if not alerts:
            return state
        
        # For demonstration, we'll process the first alert and create an initial state
        # In a real implementation, this would likely create multiple states or 
        # queue alerts for processing
        
        first_alert = alerts[0]
        
        # Convert SIEM alert to our internal format
        alert_data = {
            'timestamp': first_alert.timestamp,
            'source': first_alert.siem_system,
            'event_type': first_alert.event_type,
            'severity': first_alert.severity,
            'title': first_alert.title,
            'description': first_alert.description,
            'source_ip': first_alert.source_ip,
            'destination_ip': first_alert.destination_ip,
            'username': first_alert.username,
            'hostname': first_alert.hostname,
            'raw_data': first_alert.raw_data
        }
        
        # Create enriched data with ingestion metadata
        enriched_data = EnrichedData(
            asset_context={
                "ingestion_timestamp": datetime.utcnow().isoformat(),
                "siem_system": first_alert.siem_system,
                "alert_fingerprint": first_alert.to_fingerprint(),
                "batch_size": len(alerts),
                "ingestion_metrics": self.metrics.get_stats()
            },
            enrichment_timestamp=datetime.utcnow()
        )
        
        # Update state with processed alert data
        updated_state = SOCStateManager.update_state(
            state,
            raw_alert=alert_data,
            enriched_data=enriched_data.model_dump(),
            workflow_step="ingestion_complete"
        )
        
        # Add analysis result with ingestion summary
        analysis_result = {
            "ingestion_status": "success",
            "alerts_ingested": len(alerts),
            "primary_alert_id": first_alert.id,
            "siem_systems": list(set(alert.siem_system for alert in alerts)),
            "processing_rate_alerts_per_second": self.metrics.get_current_rate(),
            "deduplication_applied": True,
            "batch_processing": True
        }
        
        updated_state = self.add_analysis_result(
            updated_state,
            result=analysis_result,
            confidence=100.0,
            reasoning=f"Successfully ingested {len(alerts)} alerts from SIEM systems"
        )
        
        # Add summary note
        summary_note = (
            f"Ingested {len(alerts)} alerts from {len(set(alert.siem_system for alert in alerts))} "
            f"SIEM systems at {self.metrics.get_current_rate():.1f} alerts/sec"
        )
        updated_state = self.add_agent_note(updated_state, summary_note)
        
        return updated_state
    
    def cleanup(self):
        """Cleanup ingestion resources"""
        try:
            # Close all active connectors
            for connector in self.active_connectors.values():
                if hasattr(connector, 'cleanup'):
                    asyncio.run(connector.cleanup())
            
            # Log final statistics
            final_stats = self.metrics.get_stats()
            self.logger.info(f"Ingestion agent cleanup - Final stats: {final_stats}")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
        
        super().cleanup()
    
    def get_ingestion_metrics(self) -> Dict[str, Any]:
        """Get comprehensive ingestion metrics"""
        return {
            "metrics": self.metrics.get_stats(),
            "deduplication": self.deduplicator.get_stats(),
            "configuration": {
                "polling_interval_seconds": self.polling_interval,
                "batch_size": self.batch_size,
                "max_concurrent_polls": self.max_concurrent_polls,
                "target_rate_alerts_per_second": self.target_rate_alerts_per_second,
                "configured_siems": list(self.siem_configs.keys())
            },
            "health": {
                "is_polling": self.is_polling,
                "active_connectors": list(self.active_connectors.keys()),
                "last_poll_times": {k: v.isoformat() for k, v in self.last_poll_times.items()}
            }
        }
    
    async def test_all_siems(self) -> Dict[str, bool]:
        """Test connectivity to all configured SIEM systems"""
        results = {}
        
        for siem_name, siem_config in self.siem_configs.items():
            try:
                connector = SIEMConnectorFactory.create_connector(siem_config, self.logger)
                async with connector:
                    results[siem_name] = await connector.test_connection()
            except Exception as e:
                self.logger.error(f"SIEM {siem_name} test failed: {e}")
                results[siem_name] = False
        
        return results


# Factory function for creating  ingestion agent
def create_ingestion_agent(
    polling_interval_seconds: int = 30,
    batch_size: int = 100,
    max_concurrent_polls: int = 3,
    dedup_window_minutes: int = 60,
    dedup_threshold: float = 0.8
) -> IngestionAgent:
    """Create configured  ingestion agent"""
    
    config = AgentConfig(
        agent_name="ingestion_agent",
        version="2.0.0",
        timeout_seconds=300,  # 5 minutes for polling operations
        max_retries=3,
        enable_monitoring=True,
        custom_settings={
            "polling_interval_seconds": polling_interval_seconds,
            "batch_size": batch_size,
            "max_concurrent_polls": max_concurrent_polls,
            "dedup_window_minutes": dedup_window_minutes,
            "dedup_threshold": dedup_threshold
        }
    )
    
    return IngestionAgent(config)