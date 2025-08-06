import os
from typing import Optional


class Settings:
    """Application settings with performance monitoring control"""
    
    # Performance monitoring
    ENABLE_PERFORMANCE_MONITORING: bool = os.getenv("ENABLE_PERFORMANCE_MONITORING", "true").lower() == "true"
    PERFORMANCE_THRESHOLD_MS: float = float(os.getenv("PERFORMANCE_THRESHOLD_MS", "10.0"))
    
    # State management
    STATE_SCHEMA_VERSION: str = "1.0.0"
    MAX_PROCESSING_HISTORY_SIZE: int = int(os.getenv("MAX_PROCESSING_HISTORY_SIZE", "1000"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    ENABLE_STRUCTURED_LOGGING: bool = os.getenv("ENABLE_STRUCTURED_LOGGING", "true").lower() == "true"

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