import threading
import time
import hashlib
from collections import OrderedDict
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List


class BaseLRUCache(ABC):
    """Memory-aware LRU cache with O(1) operations using OrderedDict"""
    
    def __init__(self, max_memory_mb: int = 100):
        # maintains insertion order enabling eviction
        self.cache = OrderedDict()  # O(1) for all operations
        self.max_memory_bytes = max_memory_mb * 1024 * 1024 # Convert MB to bytes
        self.current_memory = 0 # Tracks current memory usage
        self.hits = 0 # Successful cache retrievals
        self.misses = 0 # Cache misses
        self.evictions = 0
        self.lock = threading.RLock()  # RLock for re-entrant access


    @abstractmethod
    def _estimate_size(self, item: Any) -> int:
        """Subclasses must implement size estimation"""
        pass
    

    def _fast_hash(self, text: str) -> str:
        """Fast hash function"""

        # Best for In-memory, short-lived caches. 
        # Different across restarts, WILL CHANGE between Python processes
        return str(hash(text) & 0x7FFFFFFF) # Ensure positive hash.
        # return hashlib.sha256(text.encode()).hexdigest() # Persistent storage, distributed systems, security-sensitive. SLOWER


    def _evict_if_needed(self, new_size: int):
        """Evict LRU items based on memory pressure - O(1) with OrderedDict"""
        target_memory = self.max_memory_bytes * 0.8 # Keep 20% buffer
        
        while (self.current_memory + new_size > target_memory and 
               len(self.cache) > 1):
            # OrderedDict.popitem(last=False) is O(1) - removes from the front (oldest)
            oldest_key, oldest_value = self.cache.popitem(last=False)
            self.current_memory -= self._estimate_size(oldest_value)
            self.evictions += 1
    

    def get(self, key: str) -> Optional[Any]:
        """Get item with LRU tracking - O(1)"""
        with self.lock: # RLock allows re-entrancy, All operations are atomic
            # Recently accessed items move to the end of the OrderedDict
            # Least recently used items stay at the front
            # When eviction needed: _evict_if_needed removes from the front (oldest)
            if key in self.cache:
                # Move to end (most recent) - O(1) with OrderedDict
                value = self.cache.pop(key)  # O(1) Remove from current position

                # Check expiration if applicable
                if hasattr(self, '_check_expiration') and not self._check_expiration(value):
                    del self.cache[key]
                    self.current_memory -= self._estimate_size(value)
                    self.misses += 1
                    return None

                # Only move to end if not expired
                self.cache[key] = value # O(1) Add to end (most recent)
                self.hits += 1
                return value
            
            self.misses += 1
            return None
    

    def put(self, key: str, value: Any, **kwargs):
        """Put item with memory management - O(1)"""
        with self.lock:
            item_size = self._estimate_size(value)
            
            # Remove if already exists
            if key in self.cache:
                old_value = self.cache.pop(key)
                self.current_memory -= self._estimate_size(old_value)
            
            # Apply any preprocessing
            processed_value = self._preprocess_value(value, **kwargs)
            
            # Evict if necessary
            self._evict_if_needed(item_size)
            
            # Add to end (most recent)
            self.cache[key] = processed_value
            self.current_memory += item_size
    

    def _preprocess_value(self, value: Any, **kwargs) -> Any:
        """Override in subclasses for value preprocessing"""
        return value
    

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_ratio = self.hits / total_requests if total_requests > 0 else 0.0
            mem_pct = (self.current_memory / self.max_memory_bytes) * 100
            
            return {
                "status": "healthy" if mem_pct < 90 and hit_ratio > 0.3 else "degraded",
                "entries": len(self.cache),
                "memory_mb": self.current_memory / (1024 * 1024),
                "max_memory_mb": self.max_memory_bytes / (1024 * 1024),
                "memory_usage_percent": mem_pct,
                "hit_ratio": hit_ratio,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "efficiency_score": hit_ratio * (1.0 - (self.evictions / max(total_requests, 1)))
            }
    

    def clear(self):
        """Clear cache and reset counters"""
        with self.lock:
            self.cache.clear()
            self.current_memory = 0
            self.hits = 0
            self.misses = 0


class VectorLRUCache(BaseLRUCache):
    """Optimized cache for embedding vectors"""
    
    def _estimate_size(self, embedding: List[float]) -> int:
        """Estimate memory usage of embedding vector"""
        return len(embedding) * 4  # 4 bytes per float32, Example: 768-dimensional embedding = 768 × 4 = 3,072 bytes ≈ 3KB


    # Input is a question text so need calling _fast_hash
    def get(self, text: str) -> Optional[List[float]]:
        # key: _fast_hash, value: embedding (Embedding vector- List[float])
        cache_key = self._fast_hash(text)
        return super().get(cache_key)
    

    def put(self, text: str, embedding: List[float]):
        cache_key = self._fast_hash(text)
        super().put(cache_key, embedding)


class QueryLRUCache(BaseLRUCache):
    """Cache for query responses with expiration"""
   
    def _estimate_size(self, data: Dict) -> int:
        """Estimate memory usage of cached response"""
        base_size = 200  # Dict overhead
        response_size = len(data.get('response_text', '')) * 2  # Unicode
        question_size = len(data.get('question_text', '')) * 2
        return base_size + response_size + question_size
    

    def _preprocess_value(self, value: Any, ttl_seconds: int = 3600) -> Dict:
        """Add expiration timestamp"""
        current_time = int(time.time())
        return {
            **value,
            'expires_at': current_time + ttl_seconds,
            'cached_at': current_time
        }
    

    def _check_expiration(self, value: Dict) -> bool:
        """Check if value has expired"""
        return value['expires_at'] > int(time.time())
    

    def clear_expired(self) -> int:
        """Remove expired entries"""

        # Query cache stores temporary data with TTL
        with self.lock:
            current_time = int(time.time())
            expired_keys = [
                key for key, value in self.cache.items() 
                if value['expires_at'] <= current_time
            ]
            
            for key in expired_keys:
                removed_value = self.cache.pop(key)
                self.current_memory -= self._estimate_size(removed_value)
            
            return len(expired_keys)