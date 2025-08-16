import json
import logging
import logging.handlers
import os
import re
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog
from structlog.processors import JSONRenderer


class LogLevel(str, Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SensitiveDataMasker:
    """Handles masking of sensitive data in logs"""
    
    def __init__(self):
        # Patterns for sensitive data detection with proper capture groups
        self.patterns = {
            'password': [
                (re.compile(r'("password"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("passwd"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("pwd"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'(password=)[^\s&]*', re.IGNORECASE), r'\1***MASKED***'),
            ],
            'token': [
                (re.compile(r'("token"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("access_token"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("refresh_token"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'(token=)[^\s&]*', re.IGNORECASE), r'\1***MASKED***'),
                (re.compile(r'(Bearer\s+)[^\s]*', re.IGNORECASE), r'\1***MASKED***'),
            ],
            'key': [
                (re.compile(r'("key"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("api_key"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'("secret_key"\s*:\s*")[^"]*(")', re.IGNORECASE), r'\1***MASKED***\2'),
                (re.compile(r'(api_key=)[^\s&]*', re.IGNORECASE), r'\1***MASKED***'),
            ],
            'email': [
                (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '***EMAIL_MASKED***'),
            ],
            'ssn': [
                (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '***SSN_MASKED***'),
                (re.compile(r'\b\d{9}\b'), '***SSN_MASKED***'),
            ],
            'credit_card': [
                (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), '***CARD_MASKED***'),
            ],
            'ip_address': [
                (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), '***IP_MASKED***'),
            ]
        }
    
    def mask_sensitive_data(self, text: str, mask_pii: bool = True) -> str:
        """
        Mask sensitive data in text
        
        Args:
            text: Text to mask
            mask_pii: Whether to mask PII (email, SSN, etc.)
            
        Returns:
            str: Text with sensitive data masked
        """
        if not isinstance(text, str):
            text = str(text)
        
        masked_text = text
        
        # Always mask credentials
        for category in ['password', 'token', 'key']:
            for pattern, replacement in self.patterns[category]:
                masked_text = pattern.sub(replacement, masked_text)
        
        # Optionally mask PII
        if mask_pii:
            for category in ['email', 'ssn', 'credit_card', 'ip_address']:
                for pattern, replacement in self.patterns[category]:
                    masked_text = pattern.sub(replacement, masked_text)
        
        return masked_text


class CorrelationIDProcessor:
    """Manages correlation IDs for request tracking"""
    
    def __init__(self):
        self._local = threading.local()
    
    def generate_correlation_id(self) -> str:
        """Generate a new correlation ID"""
        return str(uuid.uuid4())
    
    def set_correlation_id(self, correlation_id: str = None):
        """Set correlation ID for current thread"""
        if correlation_id is None:
            correlation_id = self.generate_correlation_id()
        self._local.correlation_id = correlation_id
        return correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID for current thread"""
        return getattr(self._local, 'correlation_id', None)
    
    def clear_correlation_id(self):
        """Clear correlation ID for current thread"""
        if hasattr(self._local, 'correlation_id'):
            delattr(self._local, 'correlation_id')
    
    @contextmanager
    def correlation_context(self, correlation_id: str = None):
        """Context manager for correlation ID"""
        old_id = self.get_correlation_id()
        new_id = self.set_correlation_id(correlation_id)
        try:
            yield new_id
        finally:
            if old_id:
                self.set_correlation_id(old_id)
            else:
                self.clear_correlation_id()


# Global correlation ID processor
correlation_processor = CorrelationIDProcessor()


def add_correlation_id(logger, method_name, event_dict):
    """Structlog processor to add correlation ID"""
    correlation_id = correlation_processor.get_correlation_id()
    if correlation_id:
        event_dict['correlation_id'] = correlation_id
    return event_dict


def add_timestamp(logger, method_name, event_dict):
    """Structlog processor to add ISO timestamp"""
    event_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    return event_dict


def add_logger_name(logger, method_name, event_dict):
    """Structlog processor to add logger name"""
    event_dict['logger'] = logger.name
    return event_dict


def add_level(logger, method_name, event_dict):
    """Structlog processor to add log level"""
    event_dict['level'] = method_name.upper()
    return event_dict


def add_process_info(logger, method_name, event_dict):
    """Structlog processor to add process information"""
    event_dict['process_id'] = os.getpid()
    event_dict['thread_id'] = threading.get_ident()
    return event_dict


class SensitiveDataProcessor:
    """Structlog processor for masking sensitive data"""

    def __init__(self, mask_pii: bool = True, sensitive_keys=None):
        self.masker = SensitiveDataMasker()
        self.mask_pii = mask_pii
        self.sensitive_keys = set(
            sensitive_keys or {
                'password', 'passwd', 'pwd',
                'token', 'access_token', 'refresh_token',
                'key', 'api_key', 'secret_key'
            }
        )
        self.skip_keys = {
            'timestamp', 'level', 'logger',
            'process_id', 'thread_id', 'correlation_id'
        }

    def __call__(self, logger, method_name, event_dict):
        """Process event dict to mask sensitive data"""
        return self._mask_dict_values(event_dict, root=True)

    def _mask_dict_values(self, data_dict, root=False):
        """Recursively mask values in a dictionary"""
        if not isinstance(data_dict, dict):
            return data_dict

        masked_dict = {}
        for key, value in data_dict.items():
            key_str = str(key) if not isinstance(key, str) else key
            lkey = key_str.lower()

            # Skip masking system fields if root level
            if root and lkey in self.skip_keys:
                masked_dict[key] = value
                continue

            if lkey in self.sensitive_keys:
                masked_dict[key] = '***MASKED***'
            else:
                masked_dict[key] = self._mask_value(value)

        return masked_dict

    def _mask_value(self, value):
        """Mask value based on type"""
        if isinstance(value, dict):
            return self._mask_dict_values(value)
        elif isinstance(value, list):
            return [self._mask_value(v) for v in value]
        elif isinstance(value, str) and self.mask_pii:
            # Only call masker if PII masking is enabled
            return self.masker.mask_sensitive_data(value, True)
        else:
            return value



class PerformanceProcessor:
    """Structlog processor for performance tracking"""
    
    def __call__(self, logger, method_name, event_dict):
        """Add performance tracking if available"""
        # Check if this is a performance-related log
        if 'execution_time_ms' in event_dict:
            event_dict['performance'] = {
                'execution_time_ms': event_dict['execution_time_ms'],
                'is_slow': event_dict['execution_time_ms'] > 5000  # 5 second threshold
            }
        
        return event_dict


class SOCLoggerConfig:
    """Configuration for SOC logging system"""
    
    def __init__(self,
                 log_level: LogLevel = LogLevel.INFO,
                 mask_pii: bool = True,
                 enable_file_logging: bool = True,
                 log_file_path: str = "logs/soc_framework.log",
                 max_file_size_mb: int = 100,
                 backup_count: int = 5,
                 enable_console_logging: bool = True,
                 json_format: bool = True,
                 enable_correlation_ids: bool = True,
                 centralized_logging_endpoint: Optional[str] = None):
        """
        Initialize logging configuration
        
        Args:
            log_level: Minimum log level
            mask_pii: Whether to mask PII in logs
            enable_file_logging: Enable file-based logging
            log_file_path: Path for log files
            max_file_size_mb: Maximum file size before rotation
            backup_count: Number of backup files to keep
            enable_console_logging: Enable console output
            json_format: Use JSON format for structured logging
            enable_correlation_ids: Enable correlation ID tracking
            centralized_logging_endpoint: Endpoint for centralized logging
        """
        # Validate log level
        if isinstance(log_level, str):
            try:
                log_level = LogLevel(log_level.upper())
            except ValueError:
                raise ValueError(f"Invalid log level: {log_level}. Must be one of: {[l.value for l in LogLevel]}")
        elif not isinstance(log_level, LogLevel):
            raise ValueError(f"log_level must be LogLevel enum or string, got {type(log_level)}")
            
        self.log_level = log_level
        self.mask_pii = mask_pii
        self.enable_file_logging = enable_file_logging
        self.log_file_path = Path(log_file_path)
        self.max_file_size_mb = max_file_size_mb
        self.backup_count = backup_count
        self.enable_console_logging = enable_console_logging
        self.json_format = json_format
        self.enable_correlation_ids = enable_correlation_ids
        self.centralized_logging_endpoint = centralized_logging_endpoint
        
        # Ensure log directory exists
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)


class CentralizedLoggingHandler(logging.Handler):
    """Handler for sending logs to centralized logging systems"""
    
    def __init__(self, endpoint: str, timeout: float = 5.0):
        super().__init__()
        self.endpoint = endpoint
        self.timeout = timeout
        self.session = None
        self._init_session()
    
    def _init_session(self):
        """Initialize HTTP session for centralized logging"""
        try:
            import requests
            self.session = requests.Session()
            self.session.timeout = self.timeout
        except ImportError:
            print("requests package required for centralized logging")
            self.session = None
    
    def emit(self, record):
        """Emit log record to centralized system"""
        if not self.session:
            return
        
        try:
            # Format record as JSON
            log_data = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno,
            }
            
            # Add extra fields if available
            if hasattr(record, 'correlation_id'):
                log_data['correlation_id'] = record.correlation_id
            
            # Send to centralized system
            self.session.post(
                self.endpoint,
                json=log_data,
                timeout=self.timeout
            )
            
        except Exception as e:
            # Don't let logging errors break the application
            print(f"Failed to send log to centralized system: {e}")


class SOCLogger:
    """Main SOC logging class with structured logging support"""
    
    def __init__(self, config: SOCLoggerConfig):
        self.config = config
        self.masker = SensitiveDataMasker()
        self._configured = False
        self._performance_start_times = {}
        self._logger_cache = {}  # Add logger cache
        
        # Configure logging
        self._configure_logging()
    
    def _configure_logging(self):
        """Configure the logging system"""
        if self._configured:
            return
        
        # Configure structlog
        processors = [
            add_timestamp,
            add_logger_name,
            add_level,
            add_process_info,
        ]
        
        if self.config.enable_correlation_ids:
            processors.append(add_correlation_id)
        
        # Add masking processor BEFORE rendering
        if self.config.mask_pii:
            processors.append(SensitiveDataProcessor(mask_pii=self.config.mask_pii))
        
        processors.append(PerformanceProcessor())
        
        # Add JSON renderer LAST
        if self.config.json_format:
            processors.append(JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        # Configure standard library logging
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config.log_level.value))
        
        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Console handler
        if self.config.enable_console_logging:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, self.config.log_level.value))
            
            if self.config.json_format:
                console_handler.setFormatter(logging.Formatter('%(message)s'))
            else:
                console_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
            
            root_logger.addHandler(console_handler)
        
        # File handler with rotation
        if self.config.enable_file_logging:
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.log_file_path,
                maxBytes=self.config.max_file_size_mb * 1024 * 1024,
                backupCount=self.config.backup_count
            )
            file_handler.setLevel(getattr(logging, self.config.log_level.value))
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            root_logger.addHandler(file_handler)
        
        # Centralized logging handler
        if self.config.centralized_logging_endpoint:
            centralized_handler = CentralizedLoggingHandler(
                self.config.centralized_logging_endpoint
            )
            centralized_handler.setLevel(getattr(logging, self.config.log_level.value))
            root_logger.addHandler(centralized_handler)
        
        self._configured = True
    
    def get_logger(self, name: str) -> structlog.BoundLogger:
        """
        Get a structured logger instance with caching
        
        Args:
            name: Logger name (typically module name)
            
        Returns:
            structlog.BoundLogger: Configured logger instance
        """
        if name not in self._logger_cache:
            self._logger_cache[name] = structlog.get_logger(name)
        return self._logger_cache[name]
    
    def mask_sensitive_data(self, text: str) -> str:
        """
        Mask sensitive data in text
        
        Args:
            text: Text to mask
            
        Returns:
            str: Text with sensitive data masked
        """
        return self.masker.mask_sensitive_data(text, self.config.mask_pii)
    
    def start_performance_timer(self, operation_id: str = None) -> str:
        """
        Start a performance timer
        
        Args:
            operation_id: Optional operation identifier
            
        Returns:
            str: Operation ID for stopping the timer
        """
        if operation_id is None:
            operation_id = str(uuid.uuid4())
        
        self._performance_start_times[operation_id] = time.perf_counter()
        return operation_id
    
    def stop_performance_timer(self, operation_id: str, logger: structlog.BoundLogger,
                             operation_name: str = "operation") -> float:
        """
        Stop performance timer and log the result
        
        Args:
            operation_id: Operation identifier from start_performance_timer
            logger: Logger instance to use
            operation_name: Name of the operation for logging
            
        Returns:
            float: Execution time in milliseconds
        """
        if operation_id not in self._performance_start_times:
            logger.warning("Performance timer not found", operation_id=operation_id)
            return 0.0
        
        start_time = self._performance_start_times.pop(operation_id)
        execution_time_ms = (time.perf_counter() - start_time) * 1000
        
        log_data = {
            'operation': operation_name,
            'execution_time_ms': round(execution_time_ms, 2),
            'operation_id': operation_id
        }
        
        if execution_time_ms > 5000:  # Log as warning if > 5 seconds
            logger.warning("Slow operation detected", **log_data)
        else:
            logger.info("Operation completed", **log_data)
        
        return execution_time_ms
    
    @contextmanager
    def performance_context(self, logger: structlog.BoundLogger,
                          operation_name: str = "operation"):
        """
        Context manager for performance timing
        
        Args:
            logger: Logger instance to use
            operation_name: Name of the operation
            
        Yields:
            str: Operation ID
        """
        operation_id = self.start_performance_timer()
        try:
            yield operation_id
        finally:
            self.stop_performance_timer(operation_id, logger, operation_name)
    
    def set_correlation_id(self, correlation_id: str = None) -> str:
        """Set correlation ID for current thread"""
        return correlation_processor.set_correlation_id(correlation_id)
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID for current thread"""
        return correlation_processor.get_correlation_id()
    
    def correlation_context(self, correlation_id: str = None):
        """Context manager for correlation ID"""
        return correlation_processor.correlation_context(correlation_id)


# Global logger instance
_soc_logger: Optional[SOCLogger] = None
_logger_cache = {}  # Global logger cache


def configure_logging(config: SOCLoggerConfig = None) -> SOCLogger:
    """
    Configure the global SOC logging system
    
    Args:
        config: Logging configuration (uses defaults if None)
        
    Returns:
        SOCLogger: Configured logging instance
    """
    global _soc_logger, _logger_cache
    
    if config is None:
        # Get configuration from environment or use defaults
        log_level = LogLevel(os.getenv('SOC_LOG_LEVEL', 'INFO'))
        mask_pii = os.getenv('SOC_MASK_PII', 'true').lower() == 'true'
        
        config = SOCLoggerConfig(
            log_level=log_level,
            mask_pii=mask_pii,
            enable_file_logging=os.getenv('SOC_ENABLE_FILE_LOGGING', 'true').lower() == 'true',
            log_file_path=os.getenv('SOC_LOG_FILE_PATH', 'logs/soc_framework.log'),
            enable_console_logging=os.getenv('SOC_ENABLE_CONSOLE_LOGGING', 'true').lower() == 'true',
            json_format=os.getenv('SOC_JSON_FORMAT', 'true').lower() == 'true',
            centralized_logging_endpoint=os.getenv('SOC_CENTRALIZED_LOGGING_ENDPOINT')
        )
    
    _soc_logger = SOCLogger(config)
    _logger_cache.clear()  # Clear cache when reconfiguring
    return _soc_logger


def get_logger(name: str = None) -> structlog.BoundLogger:
    """
    Get a logger instance with caching
    
    Args:
        name: Logger name (uses calling module if None)
        
    Returns:
        structlog.BoundLogger: Logger instance
    """
    global _logger_cache
    
    if _soc_logger is None:
        configure_logging()
    
    if name is None:
        # Try to get calling module name
        import inspect
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'unknown')
    
    if name not in _logger_cache:
        _logger_cache[name] = _soc_logger.get_logger(name)
    
    return _logger_cache[name]


def set_correlation_id(correlation_id: str = None) -> str:
    """Set correlation ID for current thread"""
    if _soc_logger is None:
        configure_logging()
    return _soc_logger.set_correlation_id(correlation_id)


def get_correlation_id() -> Optional[str]:
    """Get correlation ID for current thread"""
    if _soc_logger is None:
        return None
    return _soc_logger.get_correlation_id()


def correlation_context(correlation_id: str = None):
    """Context manager for correlation ID"""
    if _soc_logger is None:
        configure_logging()
    return _soc_logger.correlation_context(correlation_id)


def performance_context(logger: structlog.BoundLogger, operation_name: str = "operation"):
    """Context manager for performance timing"""
    if _soc_logger is None:
        configure_logging()
    return _soc_logger.performance_context(logger, operation_name)


# Decorator for automatic performance logging
def log_performance(operation_name: str = None, logger_name: str = None):
    """Decorator for automatic performance logging"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if _soc_logger is None:
                configure_logging()
            
            logger = get_logger(logger_name or func.__module__)
            op_name = operation_name or f"{func.__name__}"
            
            with performance_context(logger, op_name):
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Integration with existing performance utilities
def enhance_performance_monitoring():
    """Enhance existing performance utilities with logging"""
    try:
        from utils.performance import benchmark_operation
        
        def logged_benchmark_operation(func):
            """Enhanced benchmark operation with logging"""
            def wrapper(*args, **kwargs):
                logger = get_logger(func.__module__)
                
                with performance_context(logger, func.__name__):
                    return func(*args, **kwargs)
            
            return wrapper
        
        # Monkey patch the existing decorator
        import utils.performance
        utils.performance.benchmark_operation = logged_benchmark_operation
        
    except ImportError:
        pass  # Performance utilities not available