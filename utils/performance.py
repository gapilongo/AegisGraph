# utils/performance.py
import functools
import logging
import time
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])


def benchmark_operation(func: F) -> F:
    """
    Decorator that measures and logs the execution time of a function.
    
    This is the core performance monitoring decorator that always measures
    execution time when applied.
    
    Args:
        func: Function to benchmark
        
    Returns:
        Wrapped function with timing instrumentation
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            end_time = time.perf_counter()
            execution_time_ms = (end_time - start_time) * 1000
            
            logger.debug(
                f"Function '{func.__name__}' executed in {execution_time_ms:.2f}ms"
            )
    
    return wrapper


def validate_performance_requirement(max_time_ms: float) -> Callable[[F], F]:
    """
    Decorator factory that validates function execution time against requirements.
    
    Raises a warning if execution time exceeds the specified threshold.
    
    Args:
        max_time_ms: Maximum allowed execution time in milliseconds
        
    Returns:
        Decorator function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                execution_time_ms = (end_time - start_time) * 1000
                
                if execution_time_ms > max_time_ms:
                    logger.warning(
                        f"PERFORMANCE WARNING: Function '{func.__name__}' took "
                        f"{execution_time_ms:.2f}ms (threshold: {max_time_ms}ms)"
                    )
                else:
                    logger.debug(
                        f"Performance OK: '{func.__name__}' took {execution_time_ms:.2f}ms "
                        f"(<{max_time_ms}ms threshold)"
                    )
        
        return wrapper
    return decorator


def conditional_decorator(decorator_func: Callable, condition: bool) -> Callable[[F], F]:
    """
    Applies a decorator conditionally based on a boolean condition.
    
    This is the core pattern for conditional decorators - the decorator is only
    applied if the condition is True, otherwise the function is returned unchanged.
    
    Args:
        decorator_func: The decorator to apply conditionally
        condition: Boolean condition determining if decorator should be applied
        
    Returns:
        Decorator that may or may not modify the function
    """
    def decorator(func: F) -> F:
        if condition:
            # Apply the decorator
            return decorator_func(func)
        else:
            # Return function unchanged
            return func
    
    return decorator


# Memory profiling decorator
def monitor_memory_usage(func: F) -> F:
    """
    Decorator that monitors memory usage of a function.
    
    Requires psutil package for memory monitoring.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            import os

            import psutil
            
            process = psutil.Process(os.getpid())
            
            # Get memory usage before
            memory_before = process.memory_info().rss / 1024 / 1024  # MB
            
            result = func(*args, **kwargs)
            
            # Get memory usage after
            memory_after = process.memory_info().rss / 1024 / 1024  # MB
            memory_delta = memory_after - memory_before
            
            logger.debug(
                f"Function '{func.__name__}' memory usage: "
                f"{memory_before:.1f}MB -> {memory_after:.1f}MB "
                f"(delta: {memory_delta:+.1f}MB)"
            )
            
            return result
            
        except ImportError:
            logger.warning("psutil not available, skipping memory monitoring")
            return func(*args, **kwargs)
    
    return wrapper


# Profile with cProfile decorator
def profile_execution(func: F) -> F:
    """
    Decorator that profiles function execution using cProfile.
    
    Provides detailed execution statistics including call counts and time spent
    in different functions.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            import cProfile
            import io
            import pstats

            # Create profiler
            profiler = cProfile.Profile()
            
            # Profile the function execution
            profiler.enable()
            result = func(*args, **kwargs)
            profiler.disable()
            
            # Generate profile report
            stream = io.StringIO()
            stats = pstats.Stats(profiler, stream=stream)
            stats.sort_stats('cumulative')
            stats.print_stats(10)  # Top 10 functions
            
            logger.debug(f"Profile report for '{func.__name__}':\n{stream.getvalue()}")
            
            return result
            
        except ImportError:
            logger.warning("cProfile not available, skipping profiling")
            return func(*args, **kwargs)
    
    return wrapper


# Retry decorator with performance monitoring
def retry_with_monitoring(max_attempts: int = 3, delay: float = 1.0) -> Callable[[F], F]:
    """
    Decorator that retries function execution on failure while monitoring performance.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Delay between retries in seconds
        
    Returns:
        Decorator function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                start_time = time.perf_counter()
                
                try:
                    result = func(*args, **kwargs)
                    
                    execution_time_ms = (time.perf_counter() - start_time) * 1000
                    
                    if attempt > 0:
                        logger.info(
                            f"Function '{func.__name__}' succeeded on attempt {attempt + 1} "
                            f"after {execution_time_ms:.2f}ms"
                        )
                    
                    return result
                    
                except Exception as e:
                    last_exception = e
                    execution_time_ms = (time.perf_counter() - start_time) * 1000
                    
                    logger.warning(
                        f"Function '{func.__name__}' failed on attempt {attempt + 1} "
                        f"after {execution_time_ms:.2f}ms: {e}"
                    )
                    
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        logger.error(
                            f"Function '{func.__name__}' failed after {max_attempts} attempts"
                        )
                        raise last_exception
            
            raise last_exception  # This should never be reached, but just in case
        
        return wrapper
    return decorator


# Rate limiting decorator
def rate_limit(calls_per_second: float) -> Callable[[F], F]:
    """
    Decorator that limits the rate of function calls.
    
    Args:
        calls_per_second: Maximum number of calls allowed per second
        
    Returns:
        Decorator function
    """
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]  # Use list to allow modification in nested function
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                logger.debug(
                    f"Rate limiting '{func.__name__}': sleeping for {sleep_time:.3f}s"
                )
                time.sleep(sleep_time)
            
            last_called[0] = time.time()
            
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            execution_time_ms = (time.perf_counter() - start_time) * 1000
            
            logger.debug(
                f"Rate-limited call to '{func.__name__}' executed in {execution_time_ms:.2f}ms"
            )
            
            return result
        
        return wrapper
    return decorator


# Circuit breaker decorator for external services
class CircuitBreakerState:
    """State tracking for circuit breaker pattern"""
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN


def circuit_breaker(failure_threshold: int = 5, timeout: float = 60.0) -> Callable[[F], F]:
    """
    Decorator implementing circuit breaker pattern with performance monitoring.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        timeout: Time to wait before attempting to close circuit (seconds)
        
    Returns:
        Decorator function
    """
    circuit_state = CircuitBreakerState(failure_threshold, timeout)
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            
            # Check if circuit should transition from OPEN to HALF_OPEN
            if (circuit_state.state == "OPEN" and 
                current_time - circuit_state.last_failure_time > circuit_state.timeout):
                circuit_state.state = "HALF_OPEN"
                logger.info(f"Circuit breaker for '{func.__name__}' transitioning to HALF_OPEN")
            
            # Fail fast if circuit is OPEN
            if circuit_state.state == "OPEN":
                logger.warning(f"Circuit breaker OPEN for '{func.__name__}' - failing fast")
                raise Exception(f"Circuit breaker is OPEN for {func.__name__}")
            
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                # Success - reset failure count and close circuit
                if circuit_state.state == "HALF_OPEN":
                    logger.info(f"Circuit breaker for '{func.__name__}' closing after successful call")
                
                circuit_state.failure_count = 0
                circuit_state.state = "CLOSED"
                
                logger.debug(
                    f"Circuit breaker call to '{func.__name__}' succeeded in {execution_time_ms:.2f}ms"
                )
                
                return result
                
            except Exception as e:
                execution_time_ms = (time.perf_counter() - start_time) * 1000
                
                # Failure - increment count and potentially open circuit
                circuit_state.failure_count += 1
                circuit_state.last_failure_time = current_time
                
                logger.warning(
                    f"Circuit breaker call to '{func.__name__}' failed in {execution_time_ms:.2f}ms: {e}"
                )
                
                if circuit_state.failure_count >= circuit_state.failure_threshold:
                    circuit_state.state = "OPEN"
                    logger.error(
                        f"Circuit breaker OPENED for '{func.__name__}' after "
                        f"{circuit_state.failure_count} failures"
                    )
                
                raise
        
        return wrapper
    return decorator

class PerformanceError(Exception):
    """Raised when performance requirements are not met"""
    pass