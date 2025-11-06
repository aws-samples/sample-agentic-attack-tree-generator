"""Tests for BedrockService with integrated caching"""
import unittest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import shutil

from threatforest.core.bedrock_service import BedrockService


class TestBedrockService(unittest.TestCase):
    """Test BedrockService functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cache_dir = self.temp_dir / "cache"
        self.cache_dir.mkdir()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    @patch('threatforest.core.bedrock_service.BedrockResponseCache')
    def test_service_initialization(self, mock_cache, mock_client_manager):
        """Test service initializes correctly"""
        service = BedrockService(enable_cache=True)
        
        self.assertIsNotNone(service.client_manager)
        self.assertIsNotNone(service.cache)
        self.assertTrue(service.enable_cache)
    
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    def test_service_without_cache(self, mock_client_manager):
        """Test service works without cache"""
        service = BedrockService(enable_cache=False)
        
        self.assertIsNone(service.cache)
        self.assertFalse(service.enable_cache)
    
    @patch('threatforest.core.bedrock_service.BedrockRateLimiter')
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    def test_invoke_model_without_cache(self, mock_client_manager, mock_rate_limiter):
        """Test model invocation without cache"""
        # Setup mocks
        mock_client = Mock()
        mock_response = {
            'body': Mock(read=lambda: json.dumps({
                'content': [{'text': 'Test response'}]
            }).encode())
        }
        mock_client.invoke_model.return_value = mock_response
        mock_client_manager.return_value.get_client.return_value = mock_client
        
        mock_limiter = Mock()
        async def mock_acquire():
            pass
        mock_limiter.acquire = mock_acquire
        mock_rate_limiter.return_value = mock_limiter
        
        # Test
        service = BedrockService(enable_cache=False)
        service.client = mock_client
        service.rate_limiter = mock_limiter
        
        result = asyncio.run(service.invoke_model(
            model_id="test-model",
            prompt="Test prompt"
        ))
        
        self.assertEqual(result, "Test response")
        mock_client.invoke_model.assert_called_once()
    
    @patch('threatforest.core.bedrock_service.BedrockRateLimiter')
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    @patch('threatforest.core.bedrock_service.BedrockResponseCache')
    def test_invoke_model_with_cache_miss(self, mock_cache_class, mock_client_manager, mock_rate_limiter):
        """Test model invocation with cache miss"""
        # Setup mocks
        mock_client = Mock()
        mock_response = {
            'body': Mock(read=lambda: json.dumps({
                'content': [{'text': 'Test response'}]
            }).encode())
        }
        mock_client.invoke_model.return_value = mock_response
        mock_client_manager.return_value.get_client.return_value = mock_client
        
        mock_limiter = Mock()
        async def mock_acquire():
            pass
        mock_limiter.acquire = mock_acquire
        mock_rate_limiter.return_value = mock_limiter
        
        mock_cache = Mock()
        mock_cache.get.return_value = None  # Cache miss
        mock_cache_class.return_value = mock_cache
        
        # Test
        service = BedrockService(enable_cache=True)
        service.client = mock_client
        service.rate_limiter = mock_limiter
        service.cache = mock_cache
        
        result = asyncio.run(service.invoke_model(
            model_id="test-model",
            prompt="Test prompt"
        ))
        
        self.assertEqual(result, "Test response")
        mock_cache.get.assert_called_once()
        mock_cache.set.assert_called_once()
        mock_client.invoke_model.assert_called_once()
    
    @patch('threatforest.core.bedrock_service.BedrockRateLimiter')
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    @patch('threatforest.core.bedrock_service.BedrockResponseCache')
    def test_invoke_model_with_cache_hit(self, mock_cache_class, mock_client_manager, mock_rate_limiter):
        """Test model invocation with cache hit"""
        # Setup mocks
        mock_client = Mock()
        mock_client_manager.return_value.get_client.return_value = mock_client
        
        mock_limiter = Mock()
        mock_rate_limiter.return_value = mock_limiter
        
        mock_cache = Mock()
        mock_cache.get.return_value = "Cached response"  # Cache hit
        mock_cache_class.return_value = mock_cache
        
        # Test
        service = BedrockService(enable_cache=True)
        service.client = mock_client
        service.rate_limiter = mock_limiter
        service.cache = mock_cache
        
        result = asyncio.run(service.invoke_model(
            model_id="test-model",
            prompt="Test prompt"
        ))
        
        self.assertEqual(result, "Cached response")
        mock_cache.get.assert_called_once()
        mock_cache.set.assert_not_called()
        mock_client.invoke_model.assert_not_called()
    
    def test_generate_cache_key(self):
        """Test cache key generation"""
        service = BedrockService(enable_cache=False)
        
        key1 = service._generate_cache_key("model1", "prompt1", 1000, 0.7)
        key2 = service._generate_cache_key("model1", "prompt1", 1000, 0.7)
        key3 = service._generate_cache_key("model1", "prompt2", 1000, 0.7)
        
        # Same inputs should generate same key
        self.assertEqual(key1, key2)
        
        # Different inputs should generate different keys
        self.assertNotEqual(key1, key3)
    
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    @patch('threatforest.core.bedrock_service.BedrockResponseCache')
    def test_get_cache_stats(self, mock_cache_class, mock_client_manager):
        """Test getting cache statistics"""
        mock_cache = Mock()
        mock_cache.get_stats.return_value = {
            'hits': 10,
            'misses': 5,
            'hit_rate': 0.67
        }
        mock_cache_class.return_value = mock_cache
        
        service = BedrockService(enable_cache=True)
        service.cache = mock_cache
        
        stats = service.get_cache_stats()
        
        self.assertIsNotNone(stats)
        self.assertEqual(stats['hits'], 10)
        self.assertEqual(stats['misses'], 5)
    
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    def test_get_cache_stats_without_cache(self, mock_client_manager):
        """Test getting cache stats when cache disabled"""
        service = BedrockService(enable_cache=False)
        
        stats = service.get_cache_stats()
        
        self.assertIsNone(stats)
    
    @patch('threatforest.core.bedrock_service.BedrockClientManager')
    @patch('threatforest.core.bedrock_service.BedrockResponseCache')
    def test_clear_cache(self, mock_cache_class, mock_client_manager):
        """Test clearing cache"""
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        service = BedrockService(enable_cache=True)
        service.cache = mock_cache
        
        service.clear_cache()
        
        mock_cache.clear.assert_called_once()


if __name__ == '__main__':
    unittest.main()
