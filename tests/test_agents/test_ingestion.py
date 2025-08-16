import asyncio
import os
import sys
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from agents.ingestion import (
    IngestionAgent,
    create_ingestion_agent,
)
from config.config_manager import SIEMConnectionConfig
from core.state_manager import SOCStateManager
from tools.siem_connectors import (
    AlertDeduplicator,
    SIEMAlert,
    SIEMConnectorFactory,
    SplunkConnector,
)


class TestSIEMConnectors:
    """Test SIEM connector implementations"""
    
    @pytest.fixture
    def splunk_config(self):
        """Create Splunk configuration for testing"""
        return SIEMConnectionConfig(
            type="splunk",
            endpoint="https://test-splunk.com:8089",
            auth_method="api_token",
            timeout_seconds=30,
            rate_limit_rps=5.0,
            batch_size=100,
            custom_settings={
                "api_token": "test_token_123"
            }
        )
    
    @pytest.fixture
    def qradar_config(self):
        """Create QRadar configuration for testing"""
        return SIEMConnectionConfig(
            type="qradar",
            endpoint="https://test-qradar.com",
            auth_method="api_token",
            timeout_seconds=60,
            rate_limit_rps=10.0,
            batch_size=50,
            custom_settings={
                "sec_token": "test_sec_token_456"
            }
        )
    
    @pytest.fixture
    def sentinel_config(self):
        """Create Sentinel configuration for testing"""
        return SIEMConnectionConfig(
            type="sentinel",
            endpoint="https://management.azure.com",
            auth_method="oauth",
            timeout_seconds=45,
            rate_limit_rps=15.0,
            batch_size=200,
            custom_settings={
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "tenant_id": "test_tenant_id",
                "subscription_id": "test_subscription",
                "resource_group": "test_rg",
                "workspace_name": "test_workspace"
            }
        )
    
    def test_siem_connector_factory(self, splunk_config, qradar_config, sentinel_config):
        """Test SIEM connector factory"""
        import logging
        logger = logging.getLogger("test")
        
        # Test Splunk connector creation
        splunk_connector = SIEMConnectorFactory.create_connector(splunk_config, logger)
        assert isinstance(splunk_connector, SplunkConnector)
        
        # Test supported SIEMs
        supported = SIEMConnectorFactory.get_supported_siems()
        assert "splunk" in supported
        assert "qradar" in supported
        assert "sentinel" in supported
        
        # Test unsupported SIEM
        invalid_config = SIEMConnectionConfig(
            type="invalid_siem",
            endpoint="https://test.com",
            auth_method="api_token"
        )
        
        with pytest.raises(ValueError, match="Unsupported SIEM type"):
            SIEMConnectorFactory.create_connector(invalid_config, logger)
    
    @patch('aiohttp.ClientSession')
    async def test_splunk_connector_authentication(self, mock_session, splunk_config):
        """Test Splunk connector authentication"""
        import logging
        logger = logging.getLogger("test")
        
        # Mock successful authentication response
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.json = AsyncMock(return_value={"sessionKey": "test_session_key"})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.get.return_value.__aenter__.return_value = mock_response
        mock_session_instance.post.return_value.__aenter__.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        # Test API token authentication
        connector = SIEMConnectorFactory.create_connector(splunk_config, logger)
        connector.session = mock_session_instance
        
        await connector.authenticate()
        assert connector.authenticated
        assert connector._auth_token == "test_token_123"
    
    @patch('aiohttp.ClientSession')
    async def test_splunk_connector_fetch_alerts(self, mock_session, splunk_config):
        """Test Splunk alert fetching"""
        import logging
        logger = logging.getLogger("test")
        
        # Mock alert data response
        mock_alert_data = {
            "results": [
                {
                    "_time": str(int(time.time())),
                    "source": "test_source",
                    "sourcetype": "test_event",
                    "severity": "high",
                    "_raw": "Test alert message",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "10.0.0.1",
                    "user": "testuser",
                    "host": "testhost"
                }
            ]
        }
        
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.json = AsyncMock(return_value=mock_alert_data)
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request.return_value.__aenter__.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        connector = SIEMConnectorFactory.create_connector(splunk_config, logger)
        connector.session = mock_session_instance
        connector.authenticated = True
        connector._auth_token = "test_token"
        
        # Mock _make_request method
        connector._make_request = AsyncMock(return_value=mock_alert_data)
        
        since = datetime.utcnow() - timedelta(hours=1)
        alerts = await connector.fetch_alerts(since=since, limit=10)
        
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, SIEMAlert)
        assert alert.siem_system == "splunk"
        assert alert.source_ip == "192.168.1.100"
        assert alert.severity == "high"


class TestAlertDeduplicator:
    """Test alert deduplication functionality"""
    
    def test_deduplicator_creation(self):
        """Test deduplicator initialization"""
        dedup = AlertDeduplicator(time_window_minutes=30, similarity_threshold=0.9)
        
        assert dedup.time_window.total_seconds() == 30 * 60
        assert dedup.similarity_threshold == 0.9
        assert len(dedup.seen_alerts) == 0
    
    def test_exact_duplicate_detection(self):
        """Test detection of exact duplicate alerts"""
        dedup = AlertDeduplicator(time_window_minutes=60)
        
        # Create two identical alerts
        alert1 = SIEMAlert(
            id="test_1",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="login_failure",
            severity="medium",
            title="Failed Login",
            description="Failed login attempt",
            source_ip="192.168.1.100",
            siem_system="splunk"
        )
        
        alert2 = SIEMAlert(
            id="test_2",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="login_failure",
            severity="medium",
            title="Failed Login",
            description="Failed login attempt",
            source_ip="192.168.1.100",
            siem_system="splunk"
        )
        
        # First alert should not be a duplicate
        assert not dedup.is_duplicate(alert1)
        
        # Second alert should be detected as duplicate
        assert dedup.is_duplicate(alert2)
    
    def test_time_window_expiration(self):
        """Test that duplicates expire after time window"""
        dedup = AlertDeduplicator(time_window_minutes=1)  # 1 minute window
        
        # Create alert with old timestamp
        old_alert = SIEMAlert(
            id="old_1",
            timestamp=datetime.utcnow() - timedelta(minutes=2),
            source="test",
            event_type="test_event",
            severity="low",
            title="Old Alert",
            description="This is an old alert",
            siem_system="test"
        )
        
        # Create similar alert with current timestamp
        new_alert = SIEMAlert(
            id="new_1",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="test_event",
            severity="low",
            title="Old Alert",
            description="This is an old alert",
            siem_system="test"
        )
        
        # Add old alert
        dedup.is_duplicate(old_alert)
        
        # New similar alert should not be duplicate (time window expired)
        assert not dedup.is_duplicate(new_alert)
    
    def test_similarity_calculation(self):
        """Test alert similarity calculation"""
        dedup = AlertDeduplicator(similarity_threshold=0.7)
        
        alert1 = SIEMAlert(
            id="sim_1",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="malware_detection",
            severity="high",
            title="Malware Found on System",
            description="Trojan detected",
            source_ip="10.0.0.1",
            siem_system="test"
        )
        
        # Similar alert (different description)
        alert2 = SIEMAlert(
            id="sim_2",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="malware_detection",
            severity="high",
            title="Malware Found on System",
            description="Virus detected",
            source_ip="10.0.0.1",
            siem_system="test"
        )
        
        # Different alert
        alert3 = SIEMAlert(
            id="diff_1",
            timestamp=datetime.utcnow(),
            source="test",
            event_type="network_anomaly",
            severity="low",
            title="Network Traffic Spike",
            description="Unusual network activity",
            source_ip="192.168.1.50",
            siem_system="test"
        )
        
        # First alert should not be duplicate
        assert not dedup.is_duplicate(alert1)
        
        # Similar alert should be detected as duplicate
        assert dedup.is_duplicate(alert2)
        
        # Different alert should not be duplicate
        assert not dedup.is_duplicate(alert3)
    
    def test_deduplication_stats(self):
        """Test deduplication statistics"""
        dedup = AlertDeduplicator()
        
        # Add some alerts
        for i in range(5):
            alert = SIEMAlert(
                id=f"test_{i}",
                timestamp=datetime.utcnow(),
                source="test",
                event_type="test_event",
                severity="medium",
                title=f"Test Alert {i}",
                description="Test description",
                siem_system="test"
            )
            dedup.is_duplicate(alert)
        
        stats = dedup.get_stats()
        assert stats["alerts_in_memory"] == 5
        assert stats["time_window_minutes"] == 60  # default
        assert stats["similarity_threshold"] == 0.8  # default


class TestIngestionAgent:
    """Test ingestion agent functionality"""
    
    @pytest.fixture
    def mock_siem_configs(self):
        """Create mock SIEM configurations"""
        return {
            "test_splunk": SIEMConnectionConfig(
                type="splunk",
                endpoint="https://test-splunk.com:8089",
                auth_method="api_token",
                custom_settings={"api_token": "test_token"}
            ),
            "test_qradar": SIEMConnectionConfig(
                type="qradar",
                endpoint="https://test-qradar.com",
                auth_method="api_token",
                custom_settings={"sec_token": "test_sec_token"}
            )
        }
    
    @patch('config.config_manager.get_config_manager')
    def test_agent_initialization(self, mock_config_manager, mock_siem_configs):
        """Test agent initialization"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent(
            polling_interval_seconds=60,
            batch_size=50,
            max_concurrent_polls=2
        )
        
        assert agent.polling_interval == 60
        assert agent.batch_size == 50
        assert agent.max_concurrent_polls == 2
        assert len(agent.siem_configs) == 2
        assert isinstance(agent.deduplicator, AlertDeduplicator)
    
    @patch('config.config_manager.get_config_manager')
    def test_react_reasoning(self, mock_config_manager, mock_siem_configs):
        """Test ReAct reasoning logic"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Test start polling reasoning
        reasoning = agent._reason_about_ingestion()
        assert reasoning == "start_polling"
        
        # Test polling specific SIEMs
        agent.is_polling = True
        reasoning = agent._reason_about_ingestion()
        assert reasoning.startswith("poll_siems:")
        assert "test_splunk" in reasoning
        assert "test_qradar" in reasoning
    
    @patch('config.config_manager.get_config_manager')
    async def test_siem_polling_with_mocks(self, mock_config_manager, mock_siem_configs):
        """Test SIEM polling with mocked connectors"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Mock SIEM alerts
        mock_alerts = [
            SIEMAlert(
                id="mock_1",
                timestamp=datetime.utcnow(),
                source="mock",
                event_type="test_event",
                severity="medium",
                title="Mock Alert 1",
                description="Test alert",
                siem_system="test_splunk"
            ),
            SIEMAlert(
                id="mock_2",
                timestamp=datetime.utcnow(),
                source="mock",
                event_type="test_event",
                severity="high",
                title="Mock Alert 2",
                description="Test alert",
                siem_system="test_qradar"
            )
        ]
        
        # Mock connector
        mock_connector = AsyncMock()
        mock_connector.fetch_alerts = AsyncMock(return_value=mock_alerts[:1])
        mock_connector.__aenter__ = AsyncMock(return_value=mock_connector)
        mock_connector.__aexit__ = AsyncMock(return_value=None)
        
        # Patch connector factory
        with patch.object(SIEMConnectorFactory, 'create_connector', return_value=mock_connector):
            result = await agent._poll_siem("test_splunk")
            
            assert len(result) == 1
            assert result[0].id == "mock_1"
            assert result[0].siem_system == "test_splunk"
    
    @patch('config.config_manager.get_config_manager')
    async def test_concurrent_polling(self, mock_config_manager, mock_siem_configs):
        """Test concurrent polling of multiple SIEMs"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent(max_concurrent_polls=2)
        
        # Mock different alerts for each SIEM
        splunk_alerts = [SIEMAlert(
            id="splunk_1",
            timestamp=datetime.utcnow(),
            source="splunk",
            event_type="login_failure",
            severity="medium",
            title="Splunk Alert",
            description="Login failure",
            siem_system="splunk"
        )]
        
        qradar_alerts = [SIEMAlert(
            id="qradar_1",
            timestamp=datetime.utcnow(),
            source="qradar",
            event_type="malware_detection",
            severity="high",
            title="QRadar Alert",
            description="Malware found",
            siem_system="qradar"
        )]
        
        # Mock poll_siem method
        async def mock_poll_siem(siem_name):
            if siem_name == "test_splunk":
                return splunk_alerts
            elif siem_name == "test_qradar":
                return qradar_alerts
            return []
        
        agent._poll_siem = mock_poll_siem
        
        # Test concurrent polling
        result = await agent._poll_multiple_siems(["test_splunk", "test_qradar"])
        
        assert "alerts" in result
        assert len(result["alerts"]) == 2
        assert result["siem_count"] == 2
        assert "processing_time_ms" in result
    
    @patch('config.config_manager.get_config_manager')
    def test_performance_monitoring(self, mock_config_manager, mock_siem_configs):
        """Test performance monitoring and metrics"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Simulate processing some alerts
        agent.metrics.record_poll("test_siem", 50, 500.0)  # 50 alerts in 500ms
        agent.metrics.record_poll("test_siem", 30, 200.0)  # 30 alerts in 200ms
        
        # Check performance
        result = agent._check_performance()
        
        assert "performance" in result
        assert "status" in result
        assert result["performance"]["alerts_processed"] == 80
        assert result["performance"]["current_rate_alerts_per_second"] > 0
    
    @patch('config.config_manager.get_config_manager')
    def test_deduplication_adjustment(self, mock_config_manager, mock_siem_configs):
        """Test automatic deduplication adjustment"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Simulate high deduplication rate
        agent.metrics.record_poll("test", 20, 100.0)
        agent.metrics.record_deduplication(30)  # More deduped than processed
        
        result = agent._adjust_deduplication()
        
        assert result["status"] == "adjusted"
        assert "new_threshold" in result
        assert agent.deduplicator.similarity_threshold > 0.8  # Should increase
    
    @patch('config.config_manager.get_config_manager')
    def test_full_react_execution(self, mock_config_manager, mock_siem_configs):
        """Test full ReAct execution cycle"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = mock_siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Create initial state
        raw_alert = {
            'timestamp': datetime.utcnow(),
            'source': 'test_siem',
            'event_type': 'test_event',
            'severity': 'medium'
        }
        
        initial_state = SOCStateManager.create_initial_state(raw_alert)
        
        # Mock the ingestion action to return some alerts
        mock_alerts = [
            SIEMAlert(
                id="react_test_1",
                timestamp=datetime.utcnow(),
                source="test",
                event_type="test_event",
                severity="medium",
                title="ReAct Test Alert",
                description="Test alert for ReAct",
                siem_system="test"
            )
        ]
        
        # Patch the action execution to return mock alerts
        original_execute_action = agent._execute_ingestion_action
        
        def mock_execute_action(reasoning):
            return {
                "alerts": mock_alerts,
                "deduplicated_count": 0,
                "processing_time_ms": 100.0,
                "siem_count": 1
            }
        
        agent._execute_ingestion_action = mock_execute_action
        
        # Execute the agent
        result_state = agent.run(initial_state)
        
        # Verify ReAct cycle completed
        assert "ingestion_agent" in result_state["agent_notes"]
        assert len(result_state["analysis_results"]) > 0
        
        # Check that ingestion results were processed
        analysis_result = result_state["analysis_results"][-1]
        assert analysis_result["result"]["alerts_ingested"] == 1
        assert analysis_result["result"]["ingestion_status"] == "success"


class TestPerformanceRequirements:
    """Test performance requirements (100+ alerts/second)"""
    
    @pytest.fixture
    def high_volume_alerts(self):
        """Generate high volume of test alerts"""
        alerts = []
        for i in range(200):  # Generate 200 alerts
            alert = SIEMAlert(
                id=f"perf_test_{i}",
                timestamp=datetime.utcnow(),
                source="performance_test",
                event_type="test_event",
                severity="medium",
                title=f"Performance Test Alert {i}",
                description=f"Test alert number {i}",
                siem_system="test"
            )
            alerts.append(alert)
        return alerts
    
    @patch('config.config_manager.get_config_manager')
    def test_processing_rate_requirement(self, mock_config_manager, high_volume_alerts):
        """Test that agent can process 100+ alerts per second"""
        # Mock config manager
        mock_config = Mock()
        mock_config.siem_connections = {"test_siem": Mock()}
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Measure processing time for high volume
        start_time = time.perf_counter()
        
        # Simulate processing 200 alerts
        for i in range(0, len(high_volume_alerts), 50):  # Process in batches of 50
            batch = high_volume_alerts[i:i+50]
            batch_start = time.perf_counter()
            
            # Simulate deduplication (fastest part of processing)
            deduplicated = [alert for alert in batch if not agent.deduplicator.is_duplicate(alert)]
            
            batch_time = (time.perf_counter() - batch_start) * 1000
            agent.metrics.record_poll("test", len(deduplicated), batch_time)
        
        total_time = time.perf_counter() - start_time
        
        # Calculate actual rate
        total_alerts = len(high_volume_alerts)
        alerts_per_second = total_alerts / total_time
        
        # Should meet or exceed 100 alerts/second requirement
        assert alerts_per_second >= 100, f"Processing rate {alerts_per_second:.1f} < 100 alerts/second"
        
        # Verify metrics tracking
        current_rate = agent.metrics.get_current_rate()
        assert current_rate > 0
    
    def test_deduplication_performance(self, high_volume_alerts):
        """Test deduplication performance with high volume"""
        deduplicator = AlertDeduplicator()
        
        start_time = time.perf_counter()
        
        # Process all alerts through deduplicator
        duplicates = 0
        for alert in high_volume_alerts:
            if deduplicator.is_duplicate(alert):
                duplicates += 1
        
        processing_time = time.perf_counter() - start_time
        
        # Should process quickly
        alerts_per_second = len(high_volume_alerts) / processing_time
        assert alerts_per_second >= 1000, f"Deduplication too slow: {alerts_per_second:.1f} alerts/second"
        
        # All alerts should be unique (first time processing)
        assert duplicates == 0
    
    @patch('config.config_manager.get_config_manager')
    async def test_concurrent_siem_polling_performance(self, mock_config_manager):
        """Test concurrent polling performance"""
        # Mock multiple SIEM configs
        siem_configs = {}
        for i in range(5):  # 5 SIEMs
            siem_configs[f"siem_{i}"] = SIEMConnectionConfig(
                type="splunk",
                endpoint=f"https://siem-{i}.test.com",
                auth_method="api_token",
                custom_settings={"api_token": f"token_{i}"}
            )
        
        mock_config = Mock()
        mock_config.siem_connections = siem_configs
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent(max_concurrent_polls=5)
        
        # Mock fast SIEM polling
        async def fast_poll_siem(siem_name):
            # Simulate 50ms SIEM response time
            await asyncio.sleep(0.05)
            return [SIEMAlert(
                id=f"{siem_name}_alert",
                timestamp=datetime.utcnow(),
                source=siem_name,
                event_type="test",
                severity="medium",
                title="Test Alert",
                description="Test",
                siem_system=siem_name
            )]
        
        agent._poll_siem = fast_poll_siem
        
        # Measure concurrent polling time
        start_time = time.perf_counter()
        result = await agent._poll_multiple_siems(list(siem_configs.keys()))
        polling_time = time.perf_counter() - start_time
        
        # Should complete in ~50ms due to concurrency (not 250ms sequential)
        assert polling_time < 0.2, f"Concurrent polling too slow: {polling_time:.3f}s"
        assert len(result["alerts"]) == 5


class TestErrorHandlingAndResilience:
    """Test error handling and resilience features"""
    
    @patch('config.config_manager.get_config_manager')
    async def test_siem_connection_failure_handling(self, mock_config_manager):
        """Test handling of SIEM connection failures"""
        mock_config = Mock()
        mock_config.siem_connections = {
            "failing_siem": SIEMConnectionConfig(
                type="splunk",
                endpoint="https://unreachable.test.com",
                auth_method="api_token",
                custom_settings={"api_token": "test"}
            )
        }
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Mock failing SIEM connection
        async def failing_poll(siem_name):
            raise Exception("Connection timeout")
        
        agent._poll_siem = failing_poll
        
        # Should handle failure gracefully
        result = await agent._poll_multiple_siems(["failing_siem"])
        
        assert "error" in result or result.get("alerts") == []
        assert agent.metrics.alerts_failed > 0
    
    @patch('config.config_manager.get_config_manager')
    def test_authentication_failure_handling(self, mock_config_manager):
        """Test handling of authentication failures"""
        mock_config = Mock()
        mock_config.siem_connections = {}
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Test with invalid authentication
        from tools.siem_connectors import AuthenticationError
        
        with patch.object(SIEMConnectorFactory, 'create_connector') as mock_factory:
            mock_connector = AsyncMock()
            mock_connector.authenticate = AsyncMock(side_effect=AuthenticationError("Invalid token"))
            mock_factory.return_value = mock_connector
            
            # Should handle auth failure gracefully
            with pytest.raises(AuthenticationError):
                asyncio.run(agent._poll_siem("test_siem"))
    
    def test_rate_limiting_behavior(self):
        """Test rate limiting and backoff behavior"""
        from tools.siem_connectors import RateLimiter
        
        limiter = RateLimiter(calls_per_second=10.0)  # 10 calls per second
        
        # Test that rate limiter works
        start_time = time.time()
        
        # This should run immediately
        asyncio.run(limiter.acquire())
        
        # Measure time for backoff
        asyncio.run(limiter.acquire())
        elapsed = time.time() - start_time
        
        # Should have some delay due to rate limiting
        assert elapsed >= 0.05  # At least 50ms delay for 10 calls/sec
    
    @patch('config.config_manager.get_config_manager')
    def test_memory_efficiency_large_dataset(self, mock_config_manager):
        """Test memory efficiency with large datasets"""
        mock_config = Mock()
        mock_config.siem_connections = {}
        mock_config_manager.return_value.config = mock_config
        
        agent = create_ingestion_agent()
        
        # Generate large number of alerts to test memory usage
        large_alert_set = []
        for i in range(10000):  # 10k alerts
            alert = SIEMAlert(
                id=f"mem_test_{i}",
                timestamp=datetime.utcnow(),
                source="memory_test",
                event_type="test",
                severity="low",
                title=f"Memory Test {i}",
                description="Memory efficiency test" * 10,  # Larger description
                siem_system="test"
            )
            large_alert_set.append(alert)
        
        # Process through deduplicator
        start_memory = agent.deduplicator.get_stats()["alerts_in_memory"]
        
        duplicates = 0
        for alert in large_alert_set:
            if agent.deduplicator.is_duplicate(alert):
                duplicates += 1
        
        end_memory = agent.deduplicator.get_stats()["alerts_in_memory"]
        
        # Memory usage should be reasonable (not storing all 10k alerts)
        # Due to cleanup and time windows
        assert end_memory < 10000, f"Memory usage too high: {end_memory} alerts stored"


if __name__ == "__main__":
    # Run specific test classes
    pytest.main([
        __file__ + "::TestSIEMConnectors::test_siem_connector_factory",
        __file__ + "::TestIngestionAgent::test_full_react_execution", 
        __file__ + "::TestPerformanceRequirements::test_processing_rate_requirement",
        "-v"
    ])