# config/settings.py
import os
from typing import Optional


class Settings:
    """Application settings with enhanced configuration management"""
    
    def __init__(self):
        self._config_manager = None
    
    @property
    def config_manager(self):
        """Lazy-load config manager"""
        if self._config_manager is None:
            try:
                from config.config_manager import get_config_manager
                self._config_manager = get_config_manager()
            except Exception:
                # Fallback if config manager is not available
                self._config_manager = None
        return self._config_manager
    
    @property
    def config(self):
        """Get current configuration"""
        if self.config_manager:
            return self.config_manager.config
        return None
    
    # Performance monitoring
    @property
    def ENABLE_PERFORMANCE_MONITORING(self) -> bool:
        if self.config:
            return self.config.enable_metrics_collection
        return os.getenv("ENABLE_PERFORMANCE_MONITORING", "true").lower() == "true"
    
    @property 
    def PERFORMANCE_THRESHOLD_MS(self) -> float:
        return float(os.getenv("PERFORMANCE_THRESHOLD_MS", "10.0"))
    
    # State management
    @property
    def STATE_SCHEMA_VERSION(self) -> str:
        if self.config:
            return self.config.config_version
        return "1.0.0"
    
    @property
    def MAX_PROCESSING_HISTORY_SIZE(self) -> int:
        return int(os.getenv("MAX_PROCESSING_HISTORY_SIZE", "1000"))
    
    # Logging
    @property
    def LOG_LEVEL(self) -> str:
        if self.config:
            return self.config.log_level
        return os.getenv("LOG_LEVEL", "INFO")
    
    @property
    def ENABLE_STRUCTURED_LOGGING(self) -> bool:
        return os.getenv("ENABLE_STRUCTURED_LOGGING", "true").lower() == "true"
    
    # Database settings
    @property
    def DATABASE_URL(self) -> str:
        if self.config and self.config.database:
            db_config = self.config.database
            password_part = f":{db_config.password}" if db_config.password else ""
            return f"postgresql://{db_config.username}{password_part}@{db_config.host}:{db_config.port}/{db_config.database}"
        
        # Fallback to environment variables
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        database = os.getenv("DB_NAME", "soc_framework")
        username = os.getenv("DB_USER", "soc_user")
        password = os.getenv("DB_PASSWORD", "")
        password_part = f":{password}" if password else ""
        return f"postgresql://{username}{password_part}@{host}:{port}/{database}"
    
    # Redis settings
    @property
    def REDIS_URL(self) -> str:
        if self.config and self.config.redis:
            redis_config = self.config.redis
            protocol = "rediss" if redis_config.ssl else "redis"
            auth = f":{redis_config.password}@" if redis_config.password else ""
            return f"{protocol}://{auth}{redis_config.host}:{redis_config.port}/{redis_config.database}"
        
        # Fallback to environment variables
        host = os.getenv("REDIS_HOST", "localhost")
        port = os.getenv("REDIS_PORT", "6379")
        database = os.getenv("REDIS_DB", "0")
        password = os.getenv("REDIS_PASSWORD", "")
        ssl = os.getenv("REDIS_SSL", "false").lower() == "true"
        protocol = "rediss" if ssl else "redis"
        auth = f":{password}@" if password else ""
        return f"{protocol}://{auth}{host}:{port}/{database}"
    
    # Security settings
    @property
    def SECRET_KEY(self) -> str:
        if self.config and self.config.security:
            return self.config.security.encryption_key_id
        return os.getenv("SECRET_KEY", "default_secret_key_change_in_production")
    
    @property
    def TOKEN_EXPIRY_HOURS(self) -> int:
        if self.config and self.config.security:
            return self.config.security.token_expiry_hours
        return int(os.getenv("TOKEN_EXPIRY_HOURS", "24"))
    
    # Performance settings
    @property
    def MAX_CONCURRENT_AGENTS(self) -> int:
        if self.config and self.config.performance:
            return self.config.performance.max_concurrent_agents
        return int(os.getenv("MAX_CONCURRENT_AGENTS", "10"))
    
    @property
    def AGENT_TIMEOUT_SECONDS(self) -> int:
        if self.config and self.config.performance:
            return self.config.performance.agent_timeout_seconds
        return int(os.getenv("AGENT_TIMEOUT_SECONDS", "300"))
    
    # Environment info
    @property
    def ENVIRONMENT(self) -> str:
        if self.config:
            return self.config.environment.value
        return os.getenv("ENVIRONMENT", "dev")
    
    @property
    def DEBUG(self) -> bool:
        if self.config:
            return self.config.debug
        return os.getenv("DEBUG", "false").lower() == "true"


settings = Settings()


# Conditional performance monitoring
def maybe_monitor_performance(func):
    """Apply performance monitoring only if enabled"""
    if settings.ENABLE_PERFORMANCE_MONITORING:
        from utils.performance import (
            benchmark_operation,
            validate_performance_requirement,
        )
        return validate_performance_requirement(settings.PERFORMANCE_THRESHOLD_MS)(
            benchmark_operation(func)
        )
    return func