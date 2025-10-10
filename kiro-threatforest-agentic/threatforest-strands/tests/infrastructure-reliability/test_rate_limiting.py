"""Tests for rate limiting and retry logic (Tasks 3.1, 3.3)"""
import unittest
import asyncio
import time
from threatforest.core.rate_limiter import BedrockRateLimiter, CircuitBreaker
from threatforest.core.retry import RetryStrategy, retry_with_backoff, sync_retry_with_backoff


class TestCircuitBreaker(unittest.TestCase):
    """Test CircuitBreaker functionality"""
    
    def test_circuit_breaker_closed_state(self):
        """Test circuit breaker starts in closed state"""
        cb = CircuitBreaker(failure_threshold=3)
        self.assertEqual(cb.state, "closed")
        self.assertTrue(cb.can_proceed())
    
    def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures"""
        cb = CircuitBreaker(failure_threshold=3)
        
        cb.record_failure()
        cb.record_failure()
        self.assertTrue(cb.can_proceed())
        
        cb.record_failure()
        self.assertEqual(cb.state, "open")
        self.assertFalse(cb.can_proceed())
    
    def test_circuit_breaker_resets_on_success(self):
        """Test circuit breaker resets on success"""
        cb = CircuitBreaker(failure_threshold=3)
        
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        
        self.assertEqual(cb.state, "closed")
        self.assertEqual(cb.failures, 0)


class TestBedrockRateLimiter(unittest.TestCase):
    """Test BedrockRateLimiter functionality"""
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initializes correctly"""
        limiter = BedrockRateLimiter(requests_per_minute=50, burst_size=10)
        self.assertEqual(limiter.requests_per_minute, 50)
        self.assertEqual(limiter.burst_size, 10)
    
    def test_rate_limiter_acquire(self):
        """Test rate limiter acquire method"""
        async def test():
            limiter = BedrockRateLimiter(requests_per_minute=100, burst_size=5)
            await limiter.acquire()
            self.assertEqual(len(limiter.request_times), 1)
        
        asyncio.run(test())
    
    def test_rate_limiter_records_success(self):
        """Test rate limiter records success"""
        limiter = BedrockRateLimiter()
        limiter.record_success()
        self.assertEqual(limiter.circuit_breaker.failures, 0)


class TestRetryStrategy(unittest.TestCase):
    """Test RetryStrategy functionality"""
    
    def test_retry_strategy_initialization(self):
        """Test retry strategy initializes with defaults"""
        strategy = RetryStrategy()
        self.assertEqual(strategy.max_attempts, 3)
        self.assertEqual(strategy.base_delay, 1.0)
    
    def test_retry_strategy_exponential_delay(self):
        """Test exponential backoff calculation"""
        strategy = RetryStrategy(base_delay=1.0, exponential_base=2.0)
        
        self.assertEqual(strategy.get_delay(0), 1.0)
        self.assertEqual(strategy.get_delay(1), 2.0)
        self.assertEqual(strategy.get_delay(2), 4.0)
    
    def test_retry_strategy_max_delay(self):
        """Test max delay cap"""
        strategy = RetryStrategy(base_delay=1.0, max_delay=5.0, exponential_base=2.0)
        
        self.assertEqual(strategy.get_delay(10), 5.0)


class TestRetryDecorator(unittest.TestCase):
    """Test retry decorator functionality"""
    
    def test_retry_with_backoff_success(self):
        """Test retry decorator with successful call"""
        call_count = [0]
        
        @retry_with_backoff(RetryStrategy(max_attempts=3))
        async def test_func():
            call_count[0] += 1
            return "success"
        
        async def run_test():
            result = await test_func()
            return result
        
        result = asyncio.run(run_test())
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 1)
    
    def test_retry_with_backoff_retries(self):
        """Test retry decorator retries on failure"""
        call_count = [0]
        
        @retry_with_backoff(RetryStrategy(max_attempts=3, base_delay=0.01))
        async def test_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Test error")
            return "success"
        
        async def run_test():
            result = await test_func()
            return result
        
        result = asyncio.run(run_test())
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)
    
    def test_sync_retry_with_backoff(self):
        """Test sync retry decorator"""
        call_count = [0]
        
        @sync_retry_with_backoff(RetryStrategy(max_attempts=2, base_delay=0.01))
        def test_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("Test error")
            return "success"
        
        result = test_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 2)


if __name__ == '__main__':
    unittest.main()
