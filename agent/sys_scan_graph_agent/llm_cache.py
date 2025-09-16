from __future__ import annotations
"""Enhanced caching system with TTL-based memoization for LLM operations.

This module provides sophisticated caching capabilities for the LLM pipeline,
including TTL-based expiration, cache invalidation, performance metrics,
and intelligent cache key generation.
"""

from typing import Dict, Any, Optional, List, Tuple, Callable, TypeVar, Generic
import hashlib
import json
import time
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from threading import Lock
from functools import wraps
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)

T = TypeVar('T')

@dataclass
class CacheEntry:
    """A cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    ttl_seconds: Optional[int]
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if the entry has expired."""
        if self.ttl_seconds is None:
            return False
        return time.time() - self.created_at > self.ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of the cache entry in seconds."""
        return time.time() - self.created_at

    def touch(self):
        """Update last accessed time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1

class TTLCache:
    """TTL-based cache with advanced features."""

    def __init__(self, max_size: int = 1000, default_ttl: Optional[int] = 3600,
                 enable_persistence: bool = False, persistence_path: Optional[Path] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.enable_persistence = enable_persistence
        self.persistence_path = persistence_path or Path("cache/llm_cache.pkl")
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

        if enable_persistence:
            self._load_persistent_cache()

    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired:
                self._remove_entry(key)
                self._misses += 1
                return None

            entry.touch()
            self._hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None,
            metadata: Optional[Dict[str, Any]] = None) -> None:
        """Put a value in the cache."""
        ttl = ttl_seconds or self.default_ttl

        # Estimate size (rough approximation)
        size_bytes = len(pickle.dumps(value)) if value is not None else 0

        entry = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            ttl_seconds=ttl,
            size_bytes=size_bytes,
            metadata=metadata or {}
        )

        with self._lock:
            # Check if we need to evict entries
            if key not in self._cache and len(self._cache) >= self.max_size:
                self._evict_entries()

            self._cache[key] = entry

            if self.enable_persistence:
                self._save_persistent_cache()

    def remove(self, key: str) -> bool:
        """Remove an entry from the cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if self.enable_persistence:
                    self._save_persistent_cache()
                return True
            return False

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()
            if self.enable_persistence:
                self._save_persistent_cache()

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns number of entries removed."""
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired]
            for key in expired_keys:
                del self._cache[key]
            if expired_keys and self.enable_persistence:
                self._save_persistent_cache()
            return len(expired_keys)

    def _evict_entries(self) -> None:
        """Evict entries based on LRU policy."""
        if not self._cache:
            return

        # Sort by last accessed time (oldest first)
        entries = sorted(self._cache.items(), key=lambda x: x[1].last_accessed)
        to_evict = max(1, len(self._cache) - self.max_size + 1)

        for i in range(to_evict):
            if i < len(entries):
                key, _ = entries[i]
                del self._cache[key]
                self._evictions += 1

    def _remove_entry(self, key: str) -> None:
        """Remove an entry from the cache."""
        if key in self._cache:
            del self._cache[key]

    def _load_persistent_cache(self) -> None:
        """Load cache from persistent storage."""
        try:
            if self.persistence_path.exists():
                with open(self.persistence_path, 'rb') as f:
                    data = pickle.load(f)
                    # Only load non-expired entries
                    current_time = time.time()
                    for key, entry in data.items():
                        if not entry.is_expired:
                            self._cache[key] = entry
                logger.info(f"Loaded {len(self._cache)} entries from persistent cache")
        except Exception as e:
            logger.warning(f"Failed to load persistent cache: {e}")

    def _save_persistent_cache(self) -> None:
        """Save cache to persistent storage."""
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persistence_path, 'wb') as f:
                pickle.dump(self._cache, f)
        except Exception as e:
            logger.warning(f"Failed to save persistent cache: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_size = sum(entry.size_bytes for entry in self._cache.values())
            avg_age = sum(entry.age_seconds for entry in self._cache.values()) / len(self._cache) if self._cache else 0

            return {
                'entries': len(self._cache),
                'max_size': self.max_size,
                'total_size_bytes': total_size,
                'hits': self._hits,
                'misses': self._misses,
                'evictions': self._evictions,
                'hit_rate': self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0,
                'average_age_seconds': avg_age,
                'default_ttl': self.default_ttl
            }

class LLMCache:
    """Specialized cache for LLM operations with intelligent key generation."""

    def __init__(self, cache: Optional[TTLCache] = None):
        self.cache = cache or TTLCache(max_size=500, default_ttl=1800)  # 30 minutes default
        self.operation_ttls = {
            'summarize': 3600,      # 1 hour
            'refine_rules': 7200,  # 2 hours
            'triage': 1800,        # 30 minutes
        }

    def generate_key(self, operation: str, *args, **kwargs) -> str:
        """Generate a deterministic cache key for LLM operations."""
        # Create a normalized representation of the arguments
        key_data = {
            'operation': operation,
            'args': self._normalize_args(args),
            'kwargs': self._normalize_kwargs(kwargs)
        }

        # Create hash of the key data
        key_json = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_json.encode()).hexdigest()

    def _normalize_args(self, args: Tuple) -> List:
        """Normalize positional arguments for consistent hashing."""
        normalized = []
        for arg in args:
            if hasattr(arg, 'model_dump'):  # Pydantic models
                normalized.append(arg.model_dump())
            elif hasattr(arg, '__dict__'):  # Regular objects
                normalized.append(vars(arg))
            else:
                normalized.append(arg)
        return normalized

    def _normalize_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize keyword arguments for consistent hashing."""
        normalized = {}
        for key, value in kwargs.items():
            if hasattr(value, 'model_dump'):  # Pydantic models
                normalized[key] = value.model_dump()
            elif hasattr(value, '__dict__'):  # Regular objects
                normalized[key] = vars(value)
            else:
                normalized[key] = value
        return normalized

    def get(self, operation: str, *args, **kwargs) -> Optional[Any]:
        """Get cached result for an LLM operation."""
        key = self.generate_key(operation, *args, **kwargs)
        result = self.cache.get(key)

        if result is not None:
            logger.debug(f"Cache hit for {operation} operation")
        else:
            logger.debug(f"Cache miss for {operation} operation")

        return result

    def put(self, operation: str, result: Any, *args, **kwargs) -> None:
        """Cache result for an LLM operation."""
        key = self.generate_key(operation, *args, **kwargs)
        ttl = self.operation_ttls.get(operation, self.cache.default_ttl)

        metadata = {
            'operation': operation,
            'cached_at': datetime.now().isoformat(),
            'ttl_seconds': ttl
        }

        self.cache.put(key, result, ttl_seconds=ttl, metadata=metadata)
        logger.debug(f"Cached result for {operation} operation (TTL: {ttl}s)")

    def invalidate_operation(self, operation: str) -> int:
        """Invalidate all cached results for a specific operation. Returns count of invalidated entries."""
        invalidated = 0
        with self.cache._lock:
            keys_to_remove = []
            for key, entry in self.cache._cache.items():
                if entry.metadata.get('operation') == operation:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.cache._cache[key]
                invalidated += 1

        if invalidated > 0 and self.cache.enable_persistence:
            self.cache._save_persistent_cache()

        logger.info(f"Invalidated {invalidated} cache entries for operation: {operation}")
        return invalidated

    def cleanup(self) -> int:
        """Clean up expired entries. Returns number of entries removed."""
        return self.cache.cleanup_expired()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        stats = self.cache.get_stats()
        stats['operation_ttls'] = self.operation_ttls
        return stats

# Global LLM cache instance
_llm_cache: Optional[LLMCache] = None

def get_llm_cache() -> LLMCache:
    """Get the global LLM cache instance."""
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMCache()
    return _llm_cache

def cached_llm_operation(operation_name: str):
    """Decorator for caching LLM operations."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            cache = get_llm_cache()

            # Try to get from cache first
            cached_result = cache.get(operation_name, *args, **kwargs)
            if cached_result is not None:
                return cached_result

            # Execute the function
            result = func(*args, **kwargs)

            # Cache the result
            cache.put(operation_name, result, *args, **kwargs)

            return result
        return wrapper
    return decorator

def invalidate_cache_operation(operation: str) -> int:
    """Invalidate all cached results for a specific operation."""
    cache = get_llm_cache()
    return cache.invalidate_operation(operation)

def cleanup_llm_cache() -> int:
    """Clean up expired cache entries."""
    cache = get_llm_cache()
    return cache.cleanup()

__all__ = [
    'CacheEntry',
    'TTLCache',
    'LLMCache',
    'get_llm_cache',
    'cached_llm_operation',
    'invalidate_cache_operation',
    'cleanup_llm_cache'
]