"""Centralized retry logic with exponential backoff"""
import asyncio
import time
from typing import Callable, Any, Optional
from functools import wraps


class RetryStrategy:
    """Retry strategy configuration"""
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number"""
        delay = self.base_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)


def retry_with_backoff(
    strategy: Optional[RetryStrategy] = None,
    exceptions: tuple = (Exception,)
):
    """Decorator for retrying async functions with exponential backoff"""
    if strategy is None:
        strategy = RetryStrategy()
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(strategy.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < strategy.max_attempts - 1:
                        delay = strategy.get_delay(attempt)
                        await asyncio.sleep(delay)
                    else:
                        # Last attempt failed
                        raise last_exception
            
            raise last_exception
        
        return wrapper
    return decorator


def sync_retry_with_backoff(
    strategy: Optional[RetryStrategy] = None,
    exceptions: tuple = (Exception,)
):
    """Decorator for retrying sync functions with exponential backoff"""
    if strategy is None:
        strategy = RetryStrategy()
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(strategy.max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < strategy.max_attempts - 1:
                        delay = strategy.get_delay(attempt)
                        time.sleep(delay)
                    else:
                        raise last_exception
            
            raise last_exception
        
        return wrapper
    return decorator
