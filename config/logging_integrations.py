import json
import logging
import time
from typing import Any, Dict, Optional

import structlog


class SecurityAuditLogger:
    """Specialized logger for security audit events"""
    
    def __init__(self):
        self.logger = structlog.get_logger("security.audit")
    
    def log_alert_created(self, alert_id: str, source: str, event_type: str, 
                         severity: str, **kwargs):
        """Log alert creation event"""
        self.logger.info(
            "Alert created",
            event_category="alert_lifecycle",
            action="created",
            alert_id=alert_id,
            source=source,
            event_type=event_type,
            severity=severity,
            **kwargs
        )
    
    def log_alert_triaged(self, alert_id: str, triage_status: str, 
                         confidence_score: float, agent_name: str, **kwargs):
        """Log alert triage event"""
        self.logger.info(
            "Alert triaged",
            event_category="alert_lifecycle",
            action="triaged",
            alert_id=alert_id,
            triage_status=triage_status,
            confidence_score=confidence_score,
            agent_name=agent_name,
            **kwargs
        )
    
    def log_alert_escalated(self, alert_id: str, escalation_reason: str,
                          escalated_to: str, **kwargs):
        """Log alert escalation event"""
        self.logger.warning(
            "Alert escalated",
            event_category="alert_lifecycle",
            action="escalated",
            alert_id=alert_id,
            escalation_reason=escalation_reason,
            escalated_to=escalated_to,
            **kwargs
        )
    
    def log_false_positive(self, alert_id: str, fp_indicators: list,
                          confidence_score: float, **kwargs):
        """Log false positive detection"""
        self.logger.info(
            "False positive detected",
            event_category="detection",
            action="false_positive",
            alert_id=alert_id,
            fp_indicators=fp_indicators,
            confidence_score=confidence_score,
            **kwargs
        )
    
    def log_human_feedback(self, alert_id: str, feedback_type: str,
                          feedback_value: Any, analyst_id: str = None, **kwargs):
        """Log human feedback event"""
        self.logger.info(
            "Human feedback received",
            event_category="feedback",
            action="feedback_received",
            alert_id=alert_id,
            feedback_type=feedback_type,
            feedback_value=feedback_value,
            analyst_id=analyst_id,
            **kwargs
        )
    
    def log_agent_error(self, agent_name: str, error_type: str, error_message: str,
                       alert_id: str = None, **kwargs):
        """Log agent error event"""
        self.logger.error(
            "Agent error occurred",
            event_category="system",
            action="agent_error",
            agent_name=agent_name,
            error_type=error_type,
            error_message=error_message,
            alert_id=alert_id,
            **kwargs
        )
    
    def log_system_health(self, component: str, status: str, metrics: Dict[str, Any],
                         **kwargs):
        """Log system health event"""
        self.logger.info(
            "System health check",
            event_category="system",
            action="health_check",
            component=component,
            status=status,
            metrics=metrics,
            **kwargs
        )


class PerformanceLogger:
    """Specialized logger for performance monitoring"""
    
    def __init__(self):
        self.logger = structlog.get_logger("performance")
    
    def log_agent_execution(self, agent_name: str, execution_time_ms: float,
                           alert_id: str, success: bool = True, **kwargs):
        """Log agent execution performance"""
        level = "info" if success else "error"
        getattr(self.logger, level)(
            "Agent execution completed",
            category="agent_performance",
            agent_name=agent_name,
            execution_time_ms=execution_time_ms,
            alert_id=alert_id,
            success=success,
            is_slow=execution_time_ms > 5000,
            **kwargs
        )
    
    def log_state_operation(self, operation: str, execution_time_ms: float,
                          state_size_bytes: int = None, **kwargs):
        """Log state operation performance"""
        self.logger.info(
            "State operation completed",
            category="state_performance",
            operation=operation,
            execution_time_ms=execution_time_ms,
            state_size_bytes=state_size_bytes,
            meets_requirement=execution_time_ms < 10.0,
            **kwargs
        )
    
    def log_tool_usage(self, tool_name: str, execution_time_ms: float,
                      success: bool = True, **kwargs):
        """Log tool usage performance"""
        level = "info" if success else "warning"
        getattr(self.logger, level)(
            "Tool execution completed",
            category="tool_performance",
            tool_name=tool_name,
            execution_time_ms=execution_time_ms,
            success=success,
            **kwargs
        )


class ComplianceLogger:
    """Specialized logger for compliance and audit requirements"""
    
    def __init__(self):
        self.logger = structlog.get_logger("compliance")
    
    def log_data_access(self, user_id: str, resource: str, action: str,
                       success: bool = True, **kwargs):
        """Log data access for compliance"""
        level = "info" if success else "warning"
        getattr(self.logger, level)(
            "Data access event",
            compliance_category="data_access",
            user_id=user_id,
            resource=resource,
            action=action,
            success=success,
            **kwargs
        )
    
    def log_configuration_change(self, component: str, change_type: str,
                               old_value: Any, new_value: Any, changed_by: str,
                               **kwargs):
        """Log configuration changes"""
        self.logger.warning(
            "Configuration changed",
            compliance_category="configuration",
            component=component,
            change_type=change_type,
            old_value=str(old_value),
            new_value=str(new_value),
            changed_by=changed_by,
            **kwargs
        )
    
    def log_retention_event(self, data_type: str, action: str, record_count: int,
                          retention_policy: str, **kwargs):
        """Log data retention events"""
        self.logger.info(
            "Data retention event",
            compliance_category="retention",
            data_type=data_type,
            action=action,
            record_count=record_count,
            retention_policy=retention_policy,
            **kwargs
        )


class LoggingMiddleware:
    """Middleware for automatic request/response logging"""
    
    def __init__(self):
        self.logger = structlog.get_logger("middleware")
        self.performance_logger = PerformanceLogger()
    
    def log_request_start(self, request_id: str, endpoint: str,
                         method: str, user_id: str = None, **kwargs):
        """Log request start"""
        self.logger.info(
            "Request started",
            request_id=request_id,
            endpoint=endpoint,
            method=method,
            user_id=user_id,
            **kwargs
        )
    
    def log_request_end(self, request_id: str, status_code: int,
                       execution_time_ms: float, **kwargs):
        """Log request completion"""
        level = "info" if status_code < 400 else "warning"
        getattr(self.logger, level)(
            "Request completed",
            request_id=request_id,
            status_code=status_code,
            execution_time_ms=execution_time_ms,
            **kwargs
        )


# Enhanced formatter for ELK Stack integration
class ELKFormatter(logging.Formatter):
    """Formatter optimized for ELK Stack ingestion"""
    
    def format(self, record):
        """Format log record for ELK Stack"""
        # Convert LogRecord to dictionary
        log_data = {
            '@timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': record.process,
            'thread_id': record.thread,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
        
        # Add custom fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                          'pathname', 'filename', 'module', 'exc_info', 
                          'exc_text', 'stack_info', 'lineno', 'funcName',
                          'created', 'msecs', 'relativeCreated', 'thread',
                          'threadName', 'processName', 'process', 'getMessage']:
                log_data[key] = value
        
        return json.dumps(log_data)


# Splunk formatter
class SplunkFormatter(logging.Formatter):
    """Formatter optimized for Splunk ingestion"""
    
    def format(self, record):
        """Format log record for Splunk"""
        # Splunk-friendly key-value format
        kvp_parts = []
        
        # Standard fields
        kvp_parts.extend([
            f'timestamp="{self.formatTime(record)}"',
            f'level="{record.levelname}"',
            f'logger="{record.name}"',
            f'message="{record.getMessage()}"',
            f'module="{record.module}"',
            f'function="{record.funcName}"',
            f'line="{record.lineno}"'
        ])
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id'):
            kvp_parts.append(f'correlation_id="{record.correlation_id}"')
        
        # Add custom fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                          'pathname', 'filename', 'module', 'exc_info', 
                          'exc_text', 'stack_info', 'lineno', 'funcName',
                          'created', 'msecs', 'relativeCreated', 'thread',
                          'threadName', 'processName', 'process', 'getMessage',
                          'correlation_id']:
                # Escape quotes in values
                safe_value = str(value).replace('"', '\\"')
                kvp_parts.append(f'{key}="{safe_value}"')
        
        return ' '.join(kvp_parts)


# Log retention manager
class LogRetentionManager:
    """Manages log file retention and cleanup"""
    
    def __init__(self, retention_days: int = 30):
        self.retention_days = retention_days
        self.logger = structlog.get_logger("log_retention")
    
    def cleanup_old_logs(self, log_directory: str):
        """Clean up old log files based on retention policy"""
        import os
        from datetime import datetime, timedelta
        from pathlib import Path
        
        log_dir = Path(log_directory)
        if not log_dir.exists():
            return
        
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        cleaned_count = 0
        total_size_mb = 0
        
        for log_file in log_dir.glob("*.log*"):
            if log_file.is_file():
                file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_time < cutoff_date:
                    file_size = log_file.stat().st_size / (1024 * 1024)  # MB
                    total_size_mb += file_size
                    
                    try:
                        log_file.unlink()
                        cleaned_count += 1
                        self.logger.info(
                            "Log file cleaned up",
                            file_path=str(log_file),
                            file_size_mb=round(file_size, 2),
                            age_days=(datetime.now() - file_time).days
                        )
                    except Exception as e:
                        self.logger.error(
                            "Failed to clean up log file",
                            file_path=str(log_file),
                            error=str(e)
                        )
        
        if cleaned_count > 0:
            self.logger.info(
                "Log cleanup completed",
                files_cleaned=cleaned_count,
                total_size_mb=round(total_size_mb, 2),
                retention_days=self.retention_days
            )


# Health check logger
class HealthCheckLogger:
    """Logger for system health monitoring"""
    
    def __init__(self):
        self.logger = structlog.get_logger("health")
    
    def log_component_health(self, component: str, status: str,
                           response_time_ms: float = None,
                           error: str = None, **metrics):
        """Log component health status"""
        level = "info" if status == "healthy" else "error"
        
        log_data = {
            "component": component,
            "status": status,
            "check_timestamp": time.time()
        }
        
        if response_time_ms is not None:
            log_data["response_time_ms"] = response_time_ms
        
        if error:
            log_data["error"] = error
        
        log_data.update(metrics)
        
        getattr(self.logger, level)(
            f"Component {status}",
            **log_data
        )


# Integration decorators
def audit_log(event_type: str, resource: str = None):
    """Decorator to automatically audit log function calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            audit_logger = SecurityAuditLogger()
            
            # Extract correlation ID if available
            from config.logging_config import get_correlation_id
            correlation_id = get_correlation_id()
            
            # Log function start
            audit_logger.logger.info(
                f"Function {func.__name__} started",
                event_type=event_type,
                resource=resource,
                function_name=func.__name__,
                correlation_id=correlation_id
            )
            
            try:
                result = func(*args, **kwargs)
                
                # Log success
                audit_logger.logger.info(
                    f"Function {func.__name__} completed successfully",
                    event_type=event_type,
                    resource=resource,
                    function_name=func.__name__,
                    correlation_id=correlation_id
                )
                
                return result
                
            except Exception as e:
                # Log error
                audit_logger.log_agent_error(
                    agent_name=func.__name__,
                    error_type=type(e).__name__,
                    error_message=str(e)
                )
                raise
        
        return wrapper
    return decorator


def performance_log(threshold_ms: float = 5000):
    """Decorator to automatically log performance metrics"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            perf_logger = PerformanceLogger()
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                perf_logger.logger.info(
                    f"Function {func.__name__} performance",
                    function_name=func.__name__,
                    execution_time_ms=round(execution_time_ms, 2),
                    is_slow=execution_time_ms > threshold_ms,
                    meets_threshold=execution_time_ms <= threshold_ms
                )
                
                return result
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                perf_logger.logger.error(
                    f"Function {func.__name__} failed",
                    function_name=func.__name__,
                    execution_time_ms=round(execution_time_ms, 2),
                    error=str(e)
                )
                raise
        
        return wrapper
    return decorator


# Global logger instances for easy access
security_audit_logger = SecurityAuditLogger()
performance_logger = PerformanceLogger()
compliance_logger = ComplianceLogger()
health_logger = HealthCheckLogger()


# Integration with existing framework
def integrate_with_agents():
    """Integrate logging with the agent framework"""
    try:
        # Import agent base after it's available
        from agents.base import BaseAgent

        # Monkey patch agent execution to add logging
        original_run = BaseAgent.run
        
        def logged_run(self, state):
            """Enhanced run method with logging"""
            from config.logging_config import correlation_context, get_logger
            
            logger = get_logger(f"agents.{self.config.agent_name}")
            
            # Use alert_id as correlation ID if available
            correlation_id = state.get('alert_id')
            
            with correlation_context(correlation_id):
                # Log agent start
                logger.info(
                    "Agent execution started",
                    agent_name=self.config.agent_name,
                    alert_id=state.get('alert_id'),
                    workflow_step=state.get('workflow_step'),
                    confidence_score=state.get('confidence_score', 0.0)
                )
                
                start_time = time.perf_counter()
                
                try:
                    result = original_run(self, state)
                    execution_time_ms = (time.perf_counter() - start_time) * 1000
                    
                    # Log successful completion
                    performance_logger.log_agent_execution(
                        agent_name=self.config.agent_name,
                        execution_time_ms=execution_time_ms,
                        alert_id=state.get('alert_id'),
                        success=True
                    )
                    
                    logger.info(
                        "Agent execution completed",
                        agent_name=self.config.agent_name,
                        alert_id=result.get('alert_id'),
                        final_confidence=result.get('confidence_score', 0.0),
                        execution_time_ms=round(execution_time_ms, 2)
                    )
                    
                    return result
                    
                except Exception as e:
                    execution_time_ms = (time.perf_counter() - start_time) * 1000
                    
                    # Log error
                    security_audit_logger.log_agent_error(
                        agent_name=self.config.agent_name,
                        error_type=type(e).__name__,
                        error_message=str(e),
                        alert_id=state.get('alert_id')
                    )
                    
                    performance_logger.log_agent_execution(
                        agent_name=self.config.agent_name,
                        execution_time_ms=execution_time_ms,
                        alert_id=state.get('alert_id'),
                        success=False
                    )
                    
                    raise
        
        # Apply the patch
        BaseAgent.run = logged_run
        
    except ImportError:
        pass  # Agents not available yet


def integrate_with_state_manager():
    """Integrate logging with the state manager"""
    try:
        from core.state_manager import SOCStateManager

        # Patch state operations
        original_create = SOCStateManager.create_initial_state
        original_update = SOCStateManager.update_state
        
        @staticmethod
        def logged_create_initial_state(raw_alert_data):
            """Enhanced create_initial_state with logging"""
            from config.logging_config import get_logger
            logger = get_logger("core.state_manager")
            
            start_time = time.perf_counter()
            
            try:
                state = original_create(raw_alert_data)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                # Log state creation
                security_audit_logger.log_alert_created(
                    alert_id=state['alert_id'],
                    source=raw_alert_data.get('source', 'unknown'),
                    event_type=raw_alert_data.get('event_type', 'unknown'),
                    severity=raw_alert_data.get('severity', 'unknown')
                )
                
                performance_logger.log_state_operation(
                    operation="create_initial_state",
                    execution_time_ms=execution_time_ms
                )
                
                return state
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                logger.error(
                    "State creation failed",
                    operation="create_initial_state",
                    execution_time_ms=execution_time_ms,
                    error=str(e)
                )
                raise
        
        @staticmethod
        def logged_update_state(state, updates=None, **kwargs):
            """Enhanced update_state with logging"""
            start_time = time.perf_counter()
            
            try:
                updated_state = original_update(state, updates, **kwargs)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                performance_logger.log_state_operation(
                    operation="update_state",
                    execution_time_ms=execution_time_ms
                )
                
                # Log specific state changes
                if updates and 'triage_status' in updates:
                    security_audit_logger.log_alert_triaged(
                        alert_id=state['alert_id'],
                        triage_status=updates['triage_status'],
                        confidence_score=updated_state.get('confidence_score', 0.0),
                        agent_name=updated_state.get('current_agent', 'unknown')
                    )
                
                return updated_state
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                performance_logger.logger.error(
                    "State update failed",
                    operation="update_state",
                    execution_time_ms=execution_time_ms,
                    error=str(e)
                )
                raise
        
        # Apply patches
        SOCStateManager.create_initial_state = logged_create_initial_state
        SOCStateManager.update_state = logged_update_state
        
    except ImportError:
        pass  # State manager not available yet