"""
Integration module to automatically integrate logging with existing framework components.
This module patches existing components to add comprehensive logging support.
"""

import functools
import time
from typing import Any, Dict

from config.logging_config import configure_logging, correlation_context, get_logger
from config.logging_integrations import (
    compliance_logger,
    performance_logger,
    security_audit_logger,
)


def integrate_logging_with_framework():
    """
    Integrate logging with all framework components.
    Call this once during application startup.
    """
    # Configure logging if not already done
    configure_logging()
    
    # Integrate with different components
    integrate_with_agents()
    integrate_with_state_manager()
    integrate_with_config_manager()
    integrate_with_performance_utils()
    
    logger = get_logger("logging_integration")
    logger.info("Logging integration completed for all framework components")


def integrate_with_agents():
    """Integrate logging with the agent framework"""
    try:
        from agents.base import BaseAgent

        # Patch BaseAgent.run method
        original_run = BaseAgent.run
        
        def logged_run(self, state):
            """Enhanced run method with comprehensive logging"""
            logger = get_logger(f"agents.{self.config.agent_name}")
            
            # Use alert_id as correlation ID if available
            correlation_id = state.get('alert_id')
            
            with correlation_context(correlation_id):
                # Log agent start
                logger.info(
                    "Agent execution started",
                    agent_name=self.config.agent_name,
                    agent_version=self.config.version,
                    alert_id=state.get('alert_id'),
                    workflow_step=state.get('workflow_step'),
                    input_confidence=state.get('confidence_score', 0.0),
                    triage_status=state.get('triage_status')
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
                    
                    # Log state changes
                    confidence_delta = result.get('confidence_score', 0.0) - state.get('confidence_score', 0.0)
                    
                    logger.info(
                        "Agent execution completed successfully",
                        agent_name=self.config.agent_name,
                        alert_id=result.get('alert_id'),
                        output_confidence=result.get('confidence_score', 0.0),
                        confidence_delta=round(confidence_delta, 2),
                        final_triage_status=result.get('triage_status'),
                        execution_time_ms=round(execution_time_ms, 2),
                        version_increment=result.get('version', 0) - state.get('version', 0)
                    )
                    
                    # Audit log for triage changes
                    if result.get('triage_status') != state.get('triage_status'):
                        security_audit_logger.log_alert_triaged(
                            alert_id=result.get('alert_id'),
                            triage_status=result.get('triage_status'),
                            confidence_score=result.get('confidence_score', 0.0),
                            agent_name=self.config.agent_name
                        )
                    
                    return result
                    
                except Exception as e:
                    execution_time_ms = (time.perf_counter() - start_time) * 1000
                    
                    # Log error with full context
                    logger.error(
                        "Agent execution failed",
                        agent_name=self.config.agent_name,
                        alert_id=state.get('alert_id'),
                        execution_time_ms=round(execution_time_ms, 2),
                        error_type=type(e).__name__,
                        error_message=str(e),
                        workflow_step=state.get('workflow_step')
                    )
                    
                    # Audit log for error
                    security_audit_logger.log_agent_error(
                        agent_name=self.config.agent_name,
                        error_type=type(e).__name__,
                        error_message=str(e),
                        alert_id=state.get('alert_id')
                    )
                    
                    # Performance log for failure
                    performance_logger.log_agent_execution(
                        agent_name=self.config.agent_name,
                        execution_time_ms=execution_time_ms,
                        alert_id=state.get('alert_id'),
                        success=False
                    )
                    
                    raise
        
        # Apply the patch
        BaseAgent.run = logged_run
        
        # Patch tool usage for better tracking
        original_use_tool = BaseAgent.use_tool
        
        def logged_use_tool(self, tool_name: str):
            """Enhanced use_tool with logging"""
            logger = get_logger(f"agents.{self.config.agent_name}")
            
            start_time = time.perf_counter()
            original_use_tool(self, tool_name)
            execution_time_ms = (time.perf_counter() - start_time) * 1000
            
            logger.debug(
                "Tool usage recorded",
                agent_name=self.config.agent_name,
                tool_name=tool_name,
                execution_time_ms=round(execution_time_ms, 2)
            )
            
            performance_logger.log_tool_usage(
                tool_name=tool_name,
                execution_time_ms=execution_time_ms,
                success=True
            )
        
        BaseAgent.use_tool = logged_use_tool
        
        logger = get_logger("logging_integration")
        logger.info("Agent framework logging integration completed")
        
    except ImportError:
        logger = get_logger("logging_integration")
        logger.warning("Agent framework not available for logging integration")


def integrate_with_state_manager():
    """Integrate logging with the state manager"""
    try:
        from core.state_manager import SOCStateManager

        # Patch state creation
        original_create = SOCStateManager.create_initial_state
        
        @staticmethod
        def logged_create_initial_state(raw_alert_data):
            """Enhanced create_initial_state with logging"""
            logger = get_logger("core.state_manager")
            
            start_time = time.perf_counter()
            
            try:
                state = original_create(raw_alert_data)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                # Log state creation with alert details
                logger.info(
                    "Initial state created",
                    alert_id=state['alert_id'],
                    source=raw_alert_data.get('source', 'unknown'),
                    event_type=raw_alert_data.get('event_type', 'unknown'),
                    severity=raw_alert_data.get('severity', 'unknown'),
                    execution_time_ms=round(execution_time_ms, 2),
                    state_version=state.get('version', 1),
                    schema_version=state.get('schema_version')
                )
                
                # Audit log for alert creation
                security_audit_logger.log_alert_created(
                    alert_id=state['alert_id'],
                    source=raw_alert_data.get('source', 'unknown'),
                    event_type=raw_alert_data.get('event_type', 'unknown'),
                    severity=raw_alert_data.get('severity', 'unknown')
                )
                
                # Performance log
                performance_logger.log_state_operation(
                    operation="create_initial_state",
                    execution_time_ms=execution_time_ms,
                    state_size_bytes=len(str(state))
                )
                
                return state
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                logger.error(
                    "State creation failed",
                    operation="create_initial_state",
                    execution_time_ms=round(execution_time_ms, 2),
                    error_type=type(e).__name__,
                    error_message=str(e),
                    source=raw_alert_data.get('source', 'unknown')
                )
                raise
        
        # Patch state updates
        original_update = SOCStateManager.update_state
        
        @staticmethod
        def logged_update_state(state, updates=None, **kwargs):
            """Enhanced update_state with logging"""
            logger = get_logger("core.state_manager")
            
            start_time = time.perf_counter()
            old_version = state.get('version', 0)
            old_confidence = state.get('confidence_score', 0.0)
            old_status = state.get('triage_status')
            
            try:
                updated_state = original_update(state, updates, **kwargs)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                # Collect change information
                changes = {}
                if updates:
                    changes.update(updates)
                changes.update(kwargs)
                
                new_version = updated_state.get('version', 0)
                new_confidence = updated_state.get('confidence_score', 0.0)
                new_status = updated_state.get('triage_status')
                
                logger.debug(
                    "State updated",
                    alert_id=state.get('alert_id'),
                    version_change=f"{old_version} -> {new_version}",
                    confidence_change=f"{old_confidence:.1f} -> {new_confidence:.1f}",
                    status_change=f"{old_status} -> {new_status}" if old_status != new_status else None,
                    execution_time_ms=round(execution_time_ms, 2),
                    fields_changed=list(changes.keys()),
                    current_agent=updated_state.get('current_agent')
                )
                
                # Performance log
                performance_logger.log_state_operation(
                    operation="update_state",
                    execution_time_ms=execution_time_ms,
                    state_size_bytes=len(str(updated_state))
                )
                
                # Audit log for specific changes
                if new_status != old_status and new_status:
                    security_audit_logger.log_alert_triaged(
                        alert_id=state.get('alert_id'),
                        triage_status=new_status,
                        confidence_score=new_confidence,
                        agent_name=updated_state.get('current_agent', 'unknown')
                    )
                
                # Check for false positive detection
                if (new_confidence < 20.0 and old_confidence >= 20.0 and 
                    updated_state.get('fp_indicators')):
                    security_audit_logger.log_false_positive(
                        alert_id=state.get('alert_id'),
                        fp_indicators=updated_state.get('fp_indicators', []),
                        confidence_score=new_confidence
                    )
                
                return updated_state
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                logger.error(
                    "State update failed",
                    alert_id=state.get('alert_id'),
                    operation="update_state",
                    execution_time_ms=round(execution_time_ms, 2),
                    error_type=type(e).__name__,
                    error_message=str(e),
                    attempted_changes=list(changes.keys()) if 'changes' in locals() else None
                )
                raise
        
        # Apply patches
        SOCStateManager.create_initial_state = logged_create_initial_state
        SOCStateManager.update_state = logged_update_state
        
        logger = get_logger("logging_integration")
        logger.info("State manager logging integration completed")
        
    except ImportError:
        logger = get_logger("logging_integration")
        logger.warning("State manager not available for logging integration")


def integrate_with_config_manager():
    """Integrate logging with the configuration manager"""
    try:
        from config.config_manager import ConfigManager

        # Patch configuration loading
        original_load = ConfigManager.load_configuration
        
        def logged_load_configuration(self):
            """Enhanced load_configuration with logging"""
            logger = get_logger("config.manager")
            
            start_time = time.perf_counter()
            
            try:
                config = original_load(self)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                logger.info(
                    "Configuration loaded successfully",
                    environment=config.environment.value,
                    config_file=str(self.config_file_path) if self.config_file_path.exists() else None,
                    env_file=str(self.env_file_path) if self.env_file_path.exists() else None,
                    execution_time_ms=round(execution_time_ms, 2),
                    siem_connections=len(config.siem_connections),
                    debug_mode=config.debug
                )
                
                # Compliance log for configuration access
                compliance_logger.log_data_access(
                    user_id="system",
                    resource="configuration",
                    action="load",
                    success=True
                )
                
                return config
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                logger.error(
                    "Configuration loading failed",
                    execution_time_ms=round(execution_time_ms, 2),
                    error_type=type(e).__name__,
                    error_message=str(e),
                    config_file=str(self.config_file_path),
                    environment=self.environment.value
                )
                
                # Compliance log for failed access
                compliance_logger.log_data_access(
                    user_id="system",
                    resource="configuration",
                    action="load",
                    success=False
                )
                
                raise
        
        ConfigManager.load_configuration = logged_load_configuration
        
        logger = get_logger("logging_integration")
        logger.info("Configuration manager logging integration completed")
        
    except ImportError:
        logger = get_logger("logging_integration")
        logger.warning("Configuration manager not available for logging integration")


def integrate_with_performance_utils():
    """Integrate logging with performance utilities"""
    try:
        import utils.performance as perf_utils

        # Enhance existing decorators with logging
        original_benchmark = perf_utils.benchmark_operation
        
        def logged_benchmark_operation(func):
            """Enhanced benchmark operation with logging"""
            logger = get_logger(func.__module__)
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                operation_id = f"{func.__module__}.{func.__name__}"
                
                with correlation_context():
                    logger.debug(
                        "Performance benchmark started",
                        operation=operation_id,
                        function_name=func.__name__,
                        module=func.__module__
                    )
                    
                    start_time = time.perf_counter()
                    
                    try:
                        result = func(*args, **kwargs)
                        execution_time_ms = (time.perf_counter() - start_time) * 1000
                        
                        # Log performance metrics
                        performance_logger.logger.info(
                            "Benchmark operation completed",
                            operation=operation_id,
                            execution_time_ms=round(execution_time_ms, 2),
                            function_name=func.__name__,
                            module=func.__module__,
                            success=True
                        )
                        
                        return result
                        
                    except Exception as e:
                        execution_time_ms = (time.perf_counter() - start_time) * 1000
                        
                        performance_logger.logger.error(
                            "Benchmark operation failed",
                            operation=operation_id,
                            execution_time_ms=round(execution_time_ms, 2),
                            function_name=func.__name__,
                            module=func.__module__,
                            error_type=type(e).__name__,
                            error_message=str(e),
                            success=False
                        )
                        
                        raise
            
            return wrapper
        
        # Monkey patch the existing decorator
        perf_utils.benchmark_operation = logged_benchmark_operation
        
        logger = get_logger("logging_integration")
        logger.info("Performance utilities logging integration completed")
        
    except ImportError:
        logger = get_logger("logging_integration")
        logger.warning("Performance utilities not available for logging integration")


def setup_workflow_logging():
    """Set up logging for LangGraph workflow execution"""
    try:
        from core.workflow import create_soc_workflow

        # This would patch workflow execution if needed
        # For now, individual agents are already patched above
        
        logger = get_logger("logging_integration")
        logger.info("Workflow logging setup completed")
        
    except ImportError:
        logger = get_logger("logging_integration")
        logger.warning("Workflow components not available for logging integration")


def log_application_startup():
    """Log application startup information"""
    import os
    import platform
    import sys
    from datetime import datetime
    
    logger = get_logger("application.startup")
    
    startup_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "hostname": platform.node(),
        "process_id": os.getpid(),
        "working_directory": os.getcwd(),
        "command_line": " ".join(sys.argv)
    }
    
    # Add environment info
    env_vars = {
        key: value for key, value in os.environ.items() 
        if key.startswith('SOC_') and 'PASSWORD' not in key and 'SECRET' not in key
    }
    startup_info["environment_variables"] = env_vars
    
    logger.info("SOC Framework application started", **startup_info)
    
    # Audit log for application startup
    security_audit_logger.logger.info(
        "Application lifecycle event",
        event_category="application",
        action="startup",
        **startup_info
    )

def log_application_shutdown():
    """Log application shutdown information"""
    import os
    import platform
    import sys
    from datetime import datetime
    
    logger = get_logger("application.shutdown")
    
    shutdown_info = {
        "timestamp": datetime.utcnow().isoformat(),
        "process_id": os.getpid(),
        "hostname": platform.node()
    }
    
    logger.info("SOC Framework application shutting down", **shutdown_info)
    
    # Audit log for application shutdown
    security_audit_logger.logger.info(
        "Application lifecycle event",
        event_category="application",
        action="shutdown",
        **shutdown_info
    )

# Automatic integration on import
def auto_integrate():
    """Automatically integrate logging when this module is imported"""
    try:
        integrate_logging_with_framework()
    except Exception as e:
        # Don't fail application startup due to logging integration issues
        import logging
        logging.getLogger("logging_integration").warning(
            f"Failed to auto-integrate logging: {e}"
        )


# Health check integration
def setup_health_monitoring():
    """Set up health monitoring with logging"""
    import threading
    import time

    from config.logging_integrations import health_logger
    
    def health_check_worker():
        """Background worker for health monitoring"""
        while True:
            try:
                # Check logging system health
                test_logger = get_logger("health_check")
                start_time = time.perf_counter()
                
                test_logger.debug("Health check test message")
                
                response_time_ms = (time.perf_counter() - start_time) * 1000
                
                health_logger.log_component_health(
                    component="logging_system",
                    status="healthy",
                    response_time_ms=response_time_ms
                )
                
                # Sleep for 5 minutes between checks
                time.sleep(300)
                
            except Exception as e:
                health_logger.log_component_health(
                    component="logging_system",
                    status="unhealthy",
                    error=str(e)
                )
                time.sleep(60)  # Shorter interval when unhealthy
    
    # Start health monitoring in background
    health_thread = threading.Thread(target=health_check_worker, daemon=True)
    health_thread.start()


# Context processors for enhanced logging
class AlertContextProcessor:
    """Processor to add alert context to all logs within an alert processing session"""
    
    def __init__(self, alert_id: str, alert_source: str = None, event_type: str = None):
        self.alert_id = alert_id
        self.alert_source = alert_source
        self.event_type = event_type
    
    def __call__(self, logger, method_name, event_dict):
        """Add alert context to log event"""
        event_dict['alert_id'] = self.alert_id
        if self.alert_source:
            event_dict['alert_source'] = self.alert_source
        if self.event_type:
            event_dict['alert_event_type'] = self.event_type
        return event_dict


def alert_logging_context(alert_id: str, alert_source: str = None, event_type: str = None):
    """Context manager for alert-specific logging"""
    import structlog

    # Add alert context processor
    processor = AlertContextProcessor(alert_id, alert_source, event_type)
    
    # This would need to be implemented with structlog's context system
    # For now, we'll use correlation ID as the main context mechanism
    return correlation_context(alert_id)


# Export main integration function
__all__ = [
    'integrate_logging_with_framework',
    'log_application_startup', 
    'log_application_shutdown',
    'setup_health_monitoring',
    'alert_logging_context'
]