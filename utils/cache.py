"""
Caching utilities for NetWatch SIEM
Provides in-memory and Redis-based caching for improved performance
"""

import time
import json
import hashlib
from functools import wraps
from typing import Any, Optional, Callable
import threading

class MemoryCache:
    """Thread-safe in-memory cache with TTL support"""
    
    def __init__(self, default_ttl=300):
        self.cache = {}
        self.timestamps = {}
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                if time.time() - self.timestamps[key] < self.default_ttl:
                    return self.cache[key]
                else:
                    # Expired, remove it
                    del self.cache[key]
                    del self.timestamps[key]
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        with self.lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()
            if ttl:
                self.default_ttl = ttl
    
    def delete(self, key: str) -> None:
        """Delete key from cache"""
        with self.lock:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
    
    def size(self) -> int:
        """Get cache size"""
        with self.lock:
            return len(self.cache)

# Global cache instance
cache = MemoryCache(default_ttl=300)

def cache_key(*args, **kwargs) -> str:
    """Generate cache key from arguments"""
    key_data = {
        'args': args,
        'kwargs': sorted(kwargs.items())
    }
    key_string = json.dumps(key_data, sort_keys=True)
    return hashlib.md5(key_string.encode()).hexdigest()

def cached(ttl: int = 300, key_func: Optional[Callable] = None):
    """Decorator for caching function results"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key_str = key_func(*args, **kwargs)
            else:
                cache_key_str = f"{func.__name__}:{cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            result = cache.get(cache_key_str)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key_str, result, ttl)
            return result
        
        return wrapper
    return decorator

def invalidate_cache(pattern: str) -> None:
    """Invalidate cache entries matching pattern"""
    with cache.lock:
        keys_to_delete = [key for key in cache.cache.keys() if pattern in key]
        for key in keys_to_delete:
            cache.delete(key)

class DatabaseCache:
    """Database-specific caching utilities"""
    
    @staticmethod
    def get_device_stats_key():
        return "device_stats"
    
    @staticmethod
    def get_alert_stats_key():
        return "alert_stats"
    
    @staticmethod
    def get_network_health_key():
        return "network_health"
    
    @staticmethod
    def get_device_list_key():
        return "device_list"
    
    @staticmethod
    def get_analytics_key(analytics_type: str):
        return f"analytics:{analytics_type}"

# Cache TTL constants (in seconds)
CACHE_TTL = {
    'device_stats': 60,      # 1 minute
    'alert_stats': 30,       # 30 seconds
    'network_health': 120,   # 2 minutes
    'device_list': 30,       # 30 seconds
    'analytics': 300,        # 5 minutes
    'config': 600,           # 10 minutes
    'rules': 300,            # 5 minutes
}

def get_cache_ttl(cache_type: str) -> int:
    """Get TTL for cache type"""
    return CACHE_TTL.get(cache_type, 300)

def cache_dashboard_stats(stats: dict) -> None:
    """Cache dashboard statistics"""
    cache.set(DatabaseCache.get_device_stats_key(), stats, CACHE_TTL['device_stats'])

def get_cached_dashboard_stats() -> Optional[dict]:
    """Get cached dashboard statistics"""
    return cache.get(DatabaseCache.get_device_stats_key())

def cache_network_health(health_data: dict) -> None:
    """Cache network health data"""
    cache.set(DatabaseCache.get_network_health_key(), health_data, CACHE_TTL['network_health'])

def get_cached_network_health() -> Optional[dict]:
    """Get cached network health data"""
    return cache.get(DatabaseCache.get_network_health_key())

def cache_analytics(analytics_type: str, data: dict) -> None:
    """Cache analytics data"""
    cache.set(DatabaseCache.get_analytics_key(analytics_type), data, CACHE_TTL['analytics'])

def get_cached_analytics(analytics_type: str) -> Optional[dict]:
    """Get cached analytics data"""
    return cache.get(DatabaseCache.get_analytics_key(analytics_type))

def invalidate_device_cache() -> None:
    """Invalidate all device-related cache"""
    invalidate_cache("device")
    invalidate_cache("stats")

def invalidate_alert_cache() -> None:
    """Invalidate all alert-related cache"""
    invalidate_cache("alert")
    invalidate_cache("stats")

def invalidate_analytics_cache() -> None:
    """Invalidate all analytics cache"""
    invalidate_cache("analytics")
