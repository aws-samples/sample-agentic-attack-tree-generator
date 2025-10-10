"""Tests for BedrockResponseCache (Tasks 12.1-12.5)"""
import unittest
import tempfile
import time
from pathlib import Path
from threatforest.core import BedrockResponseCache


class TestBedrockResponseCache(unittest.TestCase):
    """Test BedrockResponseCache functionality"""
    
    def setUp(self):
        """Create temporary cache directory"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cache = BedrockResponseCache(cache_dir=self.temp_dir, enabled=True)
    
    def test_cache_initialization(self):
        """Test cache initialization"""
        self.assertTrue(self.cache.enabled)
        self.assertTrue(self.cache.cache_dir.exists())
    
    def test_cache_miss(self):
        """Test cache miss returns None"""
        result = self.cache.get("model-1", "test prompt")
        
        self.assertIsNone(result)
        self.assertEqual(self.cache.misses, 1)
        self.assertEqual(self.cache.hits, 0)
    
    def test_cache_set_and_get(self):
        """Test setting and getting cached response"""
        response = {"content": [{"text": "test response"}]}
        
        self.cache.set("model-1", "test prompt", response)
        result = self.cache.get("model-1", "test prompt")
        
        self.assertIsNotNone(result)
        self.assertEqual(result, response)
        self.assertEqual(self.cache.hits, 1)
    
    def test_cache_key_generation(self):
        """Test cache key is deterministic"""
        key1 = self.cache._generate_key("model-1", "prompt", param1="value1")
        key2 = self.cache._generate_key("model-1", "prompt", param1="value1")
        
        self.assertEqual(key1, key2)
    
    def test_cache_key_different_params(self):
        """Test different params generate different keys"""
        key1 = self.cache._generate_key("model-1", "prompt", param1="value1")
        key2 = self.cache._generate_key("model-1", "prompt", param1="value2")
        
        self.assertNotEqual(key1, key2)
    
    def test_cache_expiration(self):
        """Test cache entry expiration"""
        response = {"content": [{"text": "test"}]}
        
        # Set with 1 second TTL
        self.cache.set("model-1", "prompt", response, ttl=1)
        
        # Should be cached
        result = self.cache.get("model-1", "prompt")
        self.assertIsNotNone(result)
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        result = self.cache.get("model-1", "prompt")
        self.assertIsNone(result)
    
    def test_cache_clear(self):
        """Test clearing cache"""
        self.cache.set("model-1", "prompt1", {"data": "test1"})
        self.cache.set("model-2", "prompt2", {"data": "test2"})
        
        self.cache.clear()
        
        result1 = self.cache.get("model-1", "prompt1")
        result2 = self.cache.get("model-2", "prompt2")
        
        self.assertIsNone(result1)
        self.assertIsNone(result2)
        self.assertEqual(self.cache.hits, 0)
        self.assertEqual(self.cache.misses, 2)
    
    def test_cache_statistics(self):
        """Test cache statistics"""
        self.cache.set("model-1", "prompt", {"data": "test"})
        self.cache.get("model-1", "prompt")  # Hit
        self.cache.get("model-2", "other")   # Miss
        
        stats = self.cache.get_stats()
        
        self.assertEqual(stats['hits'], 1)
        self.assertEqual(stats['misses'], 1)
        self.assertEqual(stats['hit_rate'], "50.0%")
        self.assertEqual(stats['entry_count'], 1)
    
    def test_cache_disabled(self):
        """Test cache when disabled"""
        cache = BedrockResponseCache(cache_dir=self.temp_dir, enabled=False)
        
        cache.set("model-1", "prompt", {"data": "test"})
        result = cache.get("model-1", "prompt")
        
        self.assertIsNone(result)
        self.assertFalse(cache.enabled)


if __name__ == '__main__':
    unittest.main()
