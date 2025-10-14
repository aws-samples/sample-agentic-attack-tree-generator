"""Response caching for Bedrock API calls"""
import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    response: Dict[str, Any]
    timestamp: float
    ttl: int  # seconds
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        return time.time() - self.timestamp > self.ttl


class BedrockResponseCache:
    """Cache for Bedrock API responses"""
    
    DEFAULT_TTL = 86400  # 24 hours
    MAX_CACHE_SIZE_MB = 100
    
    def __init__(self, cache_dir: Optional[Path] = None, enabled: bool = True):
        """Initialize cache
        
        Args:
            cache_dir: Cache directory (default: ~/.threatforest/cache)
            enabled: Whether caching is enabled
        """
        self.enabled = enabled
        self.cache_dir = cache_dir or Path.home() / ".threatforest" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.hits = 0
        self.misses = 0
    
    def _generate_key(self, model_id: str, prompt: str, **kwargs) -> str:
        """Generate cache key from request parameters"""
        # Create deterministic key from model + prompt + params
        key_data = f"{model_id}:{prompt}:{json.dumps(kwargs, sort_keys=True)}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, model_id: str, prompt: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Get cached response
        
        Args:
            model_id: Bedrock model ID
            prompt: Request prompt
            **kwargs: Additional request parameters
            
        Returns:
            Cached response or None
        """
        if not self.enabled:
            return None
        
        key = self._generate_key(model_id, prompt, **kwargs)
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            self.misses += 1
            return None
        
        try:
            with open(cache_file, 'r') as f:
                entry_data = json.load(f)
                entry = CacheEntry(**entry_data)
            
            if entry.is_expired():
                cache_file.unlink()
                self.misses += 1
                return None
            
            self.hits += 1
            return entry.response
            
        except (json.JSONDecodeError, KeyError, OSError):
            self.misses += 1
            return None
    
    def set(self, model_id: str, prompt: str, response: Dict[str, Any], 
            ttl: Optional[int] = None, **kwargs):
        """Store response in cache
        
        Args:
            model_id: Bedrock model ID
            prompt: Request prompt
            response: API response to cache
            ttl: Time to live in seconds (default: 24 hours)
            **kwargs: Additional request parameters
        """
        if not self.enabled:
            return
        
        key = self._generate_key(model_id, prompt, **kwargs)
        cache_file = self.cache_dir / f"{key}.json"
        
        entry = CacheEntry(
            key=key,
            response=response,
            timestamp=time.time(),
            ttl=ttl or self.DEFAULT_TTL
        )
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(asdict(entry), f)
            
            # Check cache size and evict if needed
            self._evict_if_needed()
            
        except OSError:
            pass  # Fail silently on cache write errors
    
    def clear(self):
        """Clear all cache entries"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except OSError:
                pass
        
        self.hits = 0
        self.misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        # Calculate cache size
        cache_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))
        cache_size_mb = cache_size / (1024 * 1024)
        
        # Count entries
        entry_count = len(list(self.cache_dir.glob("*.json")))
        
        return {
            "enabled": self.enabled,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.1f}%",
            "cache_size_mb": f"{cache_size_mb:.2f}",
            "entry_count": entry_count
        }
    
    def _evict_if_needed(self):
        """Evict oldest entries if cache exceeds size limit"""
        cache_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))
        cache_size_mb = cache_size / (1024 * 1024)
        
        if cache_size_mb > self.MAX_CACHE_SIZE_MB:
            # Get all cache files sorted by modification time
            cache_files = sorted(
                self.cache_dir.glob("*.json"),
                key=lambda f: f.stat().st_mtime
            )
            
            # Remove oldest 20% of files
            to_remove = len(cache_files) // 5
            for cache_file in cache_files[:to_remove]:
                try:
                    cache_file.unlink()
                except OSError:
                    pass
