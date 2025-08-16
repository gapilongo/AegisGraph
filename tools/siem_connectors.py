import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp
import requests
from pydantic import BaseModel, Field

from config.config_manager import SIEMConnectionConfig
from core.exceptions import SOCStateError


class AuthenticationError(Exception):
    """Raised when SIEM authentication fails"""
    pass


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""
    pass


class SIEMAlert(BaseModel):
    """Standardized SIEM alert model"""
    id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    siem_system: str
    
    def to_fingerprint(self) -> str:
        """Generate fingerprint for deduplication"""
        fingerprint_data = f"{self.source_ip}{self.destination_ip}{self.event_type}{self.title}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()


class RateLimiter:
    """Rate limiter with exponential backoff"""
    
    def __init__(self, calls_per_second: float):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call_time = 0.0
        self.backoff_factor = 1.0
        self.max_backoff = 60.0
    
    async def acquire(self):
        """Acquire rate limit token"""
        current_time = time.time()
        elapsed = current_time - self.last_call_time
        
        wait_time = (self.min_interval * self.backoff_factor) - elapsed
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        
        self.last_call_time = time.time()
    
    def increase_backoff(self):
        """Increase backoff after error"""
        self.backoff_factor = min(self.backoff_factor * 2, self.max_backoff)
    
    def reset_backoff(self):
        """Reset backoff after success"""
        self.backoff_factor = 1.0


class BaseSIEMConnector(ABC):
    """Base class for SIEM connectors"""
    
    def __init__(self, config: SIEMConnectionConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.rate_limiter = RateLimiter(config.rate_limit_rps)
        self.session: Optional[aiohttp.ClientSession] = None
        self.authenticated = False
        self._auth_token: Optional[str] = None
        self._auth_expires: Optional[datetime] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()
    
    async def initialize(self):
        """Initialize the connector"""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'SOC-Framework/1.0'}
        )
        
        await self.authenticate()
        self.logger.info(f"Initialized {self.config.type} connector to {self.config.endpoint}")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        self.logger.info(f"Cleaned up {self.config.type} connector")
    
    @abstractmethod
    async def authenticate(self):
        """Authenticate with SIEM system"""
        pass
    
    @abstractmethod
    async def fetch_alerts(self, since: datetime, limit: int = None) -> List[SIEMAlert]:
        """Fetch alerts from SIEM system"""
        pass
    
    async def test_connection(self) -> bool:
        """Test connection to SIEM system"""
        try:
            await self.authenticate()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make rate-limited HTTP request with retry logic"""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                await self.rate_limiter.acquire()
                
                # Check if we need to re-authenticate
                if self._auth_expires and datetime.utcnow() > self._auth_expires:
                    await self.authenticate()
                
                url = urljoin(self.config.endpoint, endpoint)
                
                async with self.session.request(method, url, **kwargs) as response:
                    if response.status == 401:
                        # Re-authenticate and retry
                        await self.authenticate()
                        async with self.session.request(method, url, **kwargs) as retry_response:
                            retry_response.raise_for_status()
                            self.rate_limiter.reset_backoff()
                            return await retry_response.json()
                    
                    elif response.status == 429:
                        # Rate limited
                        self.rate_limiter.increase_backoff()
                        raise RateLimitExceeded(f"Rate limit exceeded for {self.config.type}")
                    
                    response.raise_for_status()
                    self.rate_limiter.reset_backoff()
                    return await response.json()
                    
            except Exception as e:
                self.logger.warning(f"Request attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    raise
                
                # Exponential backoff
                await asyncio.sleep(2 ** attempt)
        
        raise Exception("Max retries exceeded")


class SplunkConnector(BaseSIEMConnector):
    """Splunk SIEM connector"""
    
    async def authenticate(self):
        """Authenticate with Splunk"""
        if self.config.auth_method == "api_token":
            # Use stored API token
            self._auth_token = self.config.custom_settings.get("api_token")
            if not self._auth_token:
                raise AuthenticationError("Splunk API token not configured")
            
            # Test the token
            headers = {"Authorization": f"Bearer {self._auth_token}"}
            try:
                async with self.session.get(
                    urljoin(self.config.endpoint, "/services/server/info"),
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    self.authenticated = True
                    self.logger.info("Splunk authentication successful")
            except Exception as e:
                raise AuthenticationError(f"Splunk authentication failed: {e}")
        
        elif self.config.auth_method == "basic_auth":
            # Use username/password authentication
            username = self.config.custom_settings.get("username")
            password = self.config.custom_settings.get("password")
            
            if not username or not password:
                raise AuthenticationError("Splunk username/password not configured")
            
            auth_data = {
                "username": username,
                "password": password,
                "output_mode": "json"
            }
            
            try:
                async with self.session.post(
                    urljoin(self.config.endpoint, "/services/auth/login"),
                    data=auth_data
                ) as response:
                    response.raise_for_status()
                    result = await response.json()
                    self._auth_token = result["sessionKey"]
                    self.authenticated = True
                    self.logger.info("Splunk authentication successful")
            except Exception as e:
                raise AuthenticationError(f"Splunk authentication failed: {e}")
        
        else:
            raise AuthenticationError(f"Unsupported Splunk auth method: {self.config.auth_method}")
    
    async def fetch_alerts(self, since: datetime, limit: int = None) -> List[SIEMAlert]:
        """Fetch alerts from Splunk"""
        if not self.authenticated:
            await self.authenticate()
        
        # Build Splunk search query
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
        search_query = f'''
        search earliest={since_str} 
        | where _time >= strptime("{since_str}", "%Y-%m-%dT%H:%M:%S")
        | eval severity=case(
            match(upper(severity), "CRITICAL|HIGH"), "high",
            match(upper(severity), "MEDIUM|MODERATE"), "medium", 
            match(upper(severity), "LOW|INFO"), "low",
            1=1, "medium"
        )
        | table _time, source, sourcetype, host, severity, _raw, src_ip, dest_ip, user
        '''
        
        if limit:
            search_query += f" | head {limit}"
        
        # Execute search
        search_data = {
            "search": search_query,
            "output_mode": "json",
            "exec_mode": "oneshot"
        }
        
        headers = {"Authorization": f"Splunk {self._auth_token}"}
        
        try:
            response_data = await self._make_request(
                "POST",
                "/services/search/jobs/export",
                data=search_data,
                headers=headers
            )
            
            alerts = []
            if "results" in response_data:
                for result in response_data["results"]:
                    alert = SIEMAlert(
                        id=f"splunk_{result.get('_cd', hash(str(result)))}",
                        timestamp=datetime.fromtimestamp(float(result["_time"])),
                        source=result.get("source", "splunk"),
                        event_type=result.get("sourcetype", "unknown"),
                        severity=result.get("severity", "medium"),
                        title=f"Splunk Alert - {result.get('sourcetype', 'Unknown')}",
                        description=result.get("_raw", "")[:500],  # Truncate description
                        source_ip=result.get("src_ip"),
                        destination_ip=result.get("dest_ip"),
                        username=result.get("user"),
                        hostname=result.get("host"),
                        raw_data=result,
                        siem_system="splunk"
                    )
                    alerts.append(alert)
            
            self.logger.info(f"Fetched {len(alerts)} alerts from Splunk")
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to fetch Splunk alerts: {e}")
            raise


class QRadarConnector(BaseSIEMConnector):
    """IBM QRadar SIEM connector"""
    
    async def authenticate(self):
        """Authenticate with QRadar"""
        if self.config.auth_method == "api_token":
            self._auth_token = self.config.custom_settings.get("sec_token")
            if not self._auth_token:
                raise AuthenticationError("QRadar SEC token not configured")
            
            # Test the token
            headers = {"SEC": self._auth_token}
            try:
                async with self.session.get(
                    urljoin(self.config.endpoint, "/api/system/about"),
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    self.authenticated = True
                    self.logger.info("QRadar authentication successful")
            except Exception as e:
                raise AuthenticationError(f"QRadar authentication failed: {e}")
        
        else:
            raise AuthenticationError(f"Unsupported QRadar auth method: {self.config.auth_method}")
    
    async def fetch_alerts(self, since: datetime, limit: int = None) -> List[SIEMAlert]:
        """Fetch alerts from QRadar"""
        if not self.authenticated:
            await self.authenticate()
        
        # QRadar uses milliseconds since epoch
        since_ms = int(since.timestamp() * 1000)
        
        # Build QRadar API query
        params = {
            "filter": f"start_time > {since_ms}",
            "fields": "id,start_time,offense_type,severity,description,source_address_ids,destination_address_ids,username_count",
            "sort": "-start_time"
        }
        
        if limit:
            params["limit"] = limit
        
        headers = {"SEC": self._auth_token, "Accept": "application/json"}
        
        try:
            response_data = await self._make_request(
                "GET",
                "/api/siem/offenses",
                params=params,
                headers=headers
            )
            
            alerts = []
            for offense in response_data:
                # Map QRadar severity (1-10) to our standard levels
                qradar_severity = offense.get("severity", 5)
                if qradar_severity >= 8:
                    severity = "critical"
                elif qradar_severity >= 6:
                    severity = "high"
                elif qradar_severity >= 4:
                    severity = "medium"
                else:
                    severity = "low"
                
                alert = SIEMAlert(
                    id=f"qradar_{offense['id']}",
                    timestamp=datetime.fromtimestamp(offense["start_time"] / 1000),
                    source="qradar",
                    event_type=str(offense.get("offense_type", "unknown")),
                    severity=severity,
                    title=f"QRadar Offense #{offense['id']}",
                    description=offense.get("description", "")[:500],
                    source_ip=None,  # Would need additional API call to resolve
                    destination_ip=None,
                    username=None,
                    hostname=None,
                    raw_data=offense,
                    siem_system="qradar"
                )
                alerts.append(alert)
            
            self.logger.info(f"Fetched {len(alerts)} alerts from QRadar")
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to fetch QRadar alerts: {e}")
            raise


class SentinelConnector(BaseSIEMConnector):
    """Microsoft Sentinel SIEM connector"""
    
    async def authenticate(self):
        """Authenticate with Sentinel using OAuth"""
        if self.config.auth_method == "oauth":
            # OAuth 2.0 authentication
            client_id = self.config.custom_settings.get("client_id")
            client_secret = self.config.custom_settings.get("client_secret")
            tenant_id = self.config.custom_settings.get("tenant_id")
            
            if not all([client_id, client_secret, tenant_id]):
                raise AuthenticationError("Sentinel OAuth credentials not configured")
            
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            
            token_data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default"
            }
            
            try:
                async with self.session.post(token_url, data=token_data) as response:
                    response.raise_for_status()
                    result = await response.json()
                    self._auth_token = result["access_token"]
                    
                    # Set expiration (subtract 5 minutes for safety)
                    expires_in = result.get("expires_in", 3600)
                    self._auth_expires = datetime.utcnow() + timedelta(seconds=expires_in - 300)
                    
                    self.authenticated = True
                    self.logger.info("Sentinel authentication successful")
            except Exception as e:
                raise AuthenticationError(f"Sentinel authentication failed: {e}")
        
        else:
            raise AuthenticationError(f"Unsupported Sentinel auth method: {self.config.auth_method}")
    
    async def fetch_alerts(self, since: datetime, limit: int = None) -> List[SIEMAlert]:
        """Fetch alerts from Sentinel"""
        if not self.authenticated:
            await self.authenticate()
        
        # Sentinel KQL query
        since_str = since.isoformat() + "Z"
        
        kql_query = f'''
        SecurityAlert
        | where TimeGenerated >= datetime({since_str})
        | order by TimeGenerated desc
        | project TimeGenerated, AlertName, AlertSeverity, Description, Entities, ExtendedProperties
        '''
        
        if limit:
            kql_query += f" | limit {limit}"
        
        # Sentinel workspace details
        subscription_id = self.config.custom_settings.get("subscription_id")
        resource_group = self.config.custom_settings.get("resource_group")
        workspace_name = self.config.custom_settings.get("workspace_name")
        
        if not all([subscription_id, resource_group, workspace_name]):
            raise Exception("Sentinel workspace details not configured")
        
        query_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/query"
        
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
            "Content-Type": "application/json"
        }
        
        query_data = {"query": kql_query}
        
        try:
            response_data = await self._make_request(
                "POST",
                query_url,
                json=query_data,
                headers=headers
            )
            
            alerts = []
            if "tables" in response_data and response_data["tables"]:
                table = response_data["tables"][0]
                columns = [col["name"] for col in table["columns"]]
                
                for row in table["rows"]:
                    row_data = dict(zip(columns, row))
                    
                    # Map Sentinel severity
                    sentinel_severity = row_data.get("AlertSeverity", "Medium")
                    severity_map = {
                        "High": "high",
                        "Medium": "medium", 
                        "Low": "low",
                        "Informational": "low"
                    }
                    severity = severity_map.get(sentinel_severity, "medium")
                    
                    alert = SIEMAlert(
                        id=f"sentinel_{hash(str(row_data))}",
                        timestamp=datetime.fromisoformat(row_data["TimeGenerated"].replace("Z", "+00:00")),
                        source="sentinel",
                        event_type="security_alert",
                        severity=severity,
                        title=row_data.get("AlertName", "Sentinel Alert"),
                        description=row_data.get("Description", "")[:500],
                        source_ip=None,  # Would extract from Entities
                        destination_ip=None,
                        username=None,
                        hostname=None,
                        raw_data=row_data,
                        siem_system="sentinel"
                    )
                    alerts.append(alert)
            
            self.logger.info(f"Fetched {len(alerts)} alerts from Sentinel")
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to fetch Sentinel alerts: {e}")
            raise


class SIEMConnectorFactory:
    """Factory for creating SIEM connectors"""
    
    _connectors = {
        "splunk": SplunkConnector,
        "qradar": QRadarConnector,
        "sentinel": SentinelConnector
    }
    
    @classmethod
    def create_connector(cls, config: SIEMConnectionConfig, logger: logging.Logger) -> BaseSIEMConnector:
        """Create appropriate SIEM connector"""
        connector_class = cls._connectors.get(config.type.lower())
        if not connector_class:
            raise ValueError(f"Unsupported SIEM type: {config.type}")
        
        return connector_class(config, logger)
    
    @classmethod
    def get_supported_siems(cls) -> List[str]:
        """Get list of supported SIEM systems"""
        return list(cls._connectors.keys())


class AlertDeduplicator:
    """Alert deduplication with configurable criteria"""
    
    def __init__(self, time_window_minutes: int = 60, similarity_threshold: float = 0.8):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.similarity_threshold = similarity_threshold
        self.seen_alerts: Dict[str, SIEMAlert] = {}
        self.cleanup_interval = timedelta(hours=1)
        self.last_cleanup = datetime.utcnow()
    
    def is_duplicate(self, alert: SIEMAlert) -> bool:
        """Check if alert is a duplicate"""
        self._cleanup_old_alerts()
        
        fingerprint = alert.to_fingerprint()
        current_time = datetime.utcnow()
        
        # Check exact fingerprint match within time window
        if fingerprint in self.seen_alerts:
            seen_alert = self.seen_alerts[fingerprint]
            time_diff = current_time - seen_alert.timestamp
            
            if time_diff <= self.time_window:
                return True
        
        # Check similarity with existing alerts
        for seen_fingerprint, seen_alert in self.seen_alerts.items():
            time_diff = current_time - seen_alert.timestamp
            
            if time_diff <= self.time_window:
                similarity = self._calculate_similarity(alert, seen_alert)
                if similarity >= self.similarity_threshold:
                    return True
        
        # Not a duplicate, store it
        self.seen_alerts[fingerprint] = alert
        return False
    
    def _calculate_similarity(self, alert1: SIEMAlert, alert2: SIEMAlert) -> float:
        """Calculate similarity between two alerts"""
        if alert1.siem_system != alert2.siem_system:
            return 0.0
        
        # Simple similarity based on common fields
        similarity_score = 0.0
        total_weight = 0.0
        
        # Event type similarity (weight: 30%)
        if alert1.event_type == alert2.event_type:
            similarity_score += 0.3
        total_weight += 0.3
        
        # Source IP similarity (weight: 25%)
        if alert1.source_ip and alert2.source_ip:
            if alert1.source_ip == alert2.source_ip:
                similarity_score += 0.25
        total_weight += 0.25
        
        # Title similarity (weight: 25%)
        if alert1.title and alert2.title:
            title_similarity = self._string_similarity(alert1.title, alert2.title)
            similarity_score += 0.25 * title_similarity
        total_weight += 0.25
        
        # Severity similarity (weight: 20%)
        if alert1.severity == alert2.severity:
            similarity_score += 0.2
        total_weight += 0.2
        
        return similarity_score / total_weight if total_weight > 0 else 0.0
    
    def _string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using simple ratio"""
        if not str1 or not str2:
            return 0.0
        
        # Simple word overlap similarity
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def _cleanup_old_alerts(self):
        """Remove old alerts from memory"""
        current_time = datetime.utcnow()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - self.time_window
        
        # Remove alerts older than time window
        to_remove = [
            fingerprint for fingerprint, alert in self.seen_alerts.items()
            if alert.timestamp < cutoff_time
        ]
        
        for fingerprint in to_remove:
            del self.seen_alerts[fingerprint]
        
        self.last_cleanup = current_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        return {
            "alerts_in_memory": len(self.seen_alerts),
            "time_window_minutes": self.time_window.total_seconds() / 60,
            "similarity_threshold": self.similarity_threshold,
            "last_cleanup": self.last_cleanup.isoformat()
        }