"""Rate limiting for AWS Bedrock API calls"""
import asyncio
import time
from typing import Optional
from collections import deque


class CircuitBreaker:
    """Circuit breaker to prevent cascading failures"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half_open
    
    def record_success(self):
        """Record successful request"""
        self.failures = 0
        self.state = "closed"
    
    def record_failure(self):
        """Record failed request"""
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.failures >= self.failure_threshold:
            self.state = "open"
    
    def can_proceed(self) -> bool:
        """Check if request can proceed"""
        if self.state == "closed":
            return True
        
        if self.state == "open":
            # Check if timeout has passed
            if time.time() - self.last_failure_time >= self.timeout:
                self.state = "half_open"
                return True
            return False
        
        # half_open state - allow one request through
        return True


class BedrockRateLimiter:
    """Rate limiter for AWS Bedrock API calls with circuit breaker"""
    
    def __init__(self, requests_per_minute: int = 50, burst_size: int = 10):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.semaphore = asyncio.Semaphore(burst_size)
        self.request_times = deque()
        self.circuit_breaker = CircuitBreaker()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        # Check circuit breaker
        if not self.circuit_breaker.can_proceed():
            raise Exception("Circuit breaker is open - too many failures")
        
        async with self.semaphore:
            # Sliding window rate limiting
            current_time = time.time()
            
            # Remove requests older than 1 minute
            while self.request_times and current_time - self.request_times[0] > 60:
                self.request_times.popleft()
            
            # Check if we've hit the rate limit
            if len(self.request_times) >= self.requests_per_minute:
                # Calculate wait time
                oldest_request = self.request_times[0]
                wait_time = 60 - (current_time - oldest_request)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self.request_times.append(time.time())
    
    def record_success(self):
        """Record successful API call"""
        self.circuit_breaker.record_success()
    
    def record_failure(self):
        """Record failed API call"""
        self.circuit_breaker.record_failure()
