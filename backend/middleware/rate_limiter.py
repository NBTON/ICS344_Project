"""
Token Bucket Rate Limiter

This module implements a token bucket rate limiter for DoS protection.
Each client (identified by IP address) has separate rate limits for
different types of operations.

Rate Limits (from ARCHITECTURE.md):
- messages: 30 per minute
- key_exchange: 5 per minute
- api_general: 100 per minute
"""

import time
from typing import Dict, Optional
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.
    
    Tokens are added at a constant rate up to a maximum capacity.
    Each request consumes one token. If no tokens are available,
    the request is rejected.
    """
    rate: float  # tokens per second
    capacity: float  # maximum tokens
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Initialize with full bucket."""
        self.tokens = self.capacity
    
    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume (default: 1).
        
        Returns:
            bool: True if tokens were consumed, False if not enough tokens.
        """
        now = time.time()
        
        # Add tokens based on time elapsed
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        # Try to consume tokens
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False
    
    def get_tokens(self) -> float:
        """Get current token count (after refill)."""
        now = time.time()
        elapsed = now - self.last_update
        return min(self.capacity, self.tokens + elapsed * self.rate)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit type."""
    rate_per_minute: int
    burst_multiplier: float = 1.5
    
    @property
    def rate_per_second(self) -> float:
        """Get rate in tokens per second."""
        return self.rate_per_minute / 60.0
    
    @property
    def capacity(self) -> float:
        """Get bucket capacity (allows for burst)."""
        return self.rate_per_minute * self.burst_multiplier


# Default rate limit configurations
DEFAULT_RATE_LIMITS = {
    'messages': RateLimitConfig(rate_per_minute=30),
    'key_exchange': RateLimitConfig(rate_per_minute=5),
    'api_general': RateLimitConfig(rate_per_minute=100),
    'login_attempts': RateLimitConfig(rate_per_minute=5, burst_multiplier=1.0),
}


class RateLimiter:
    """
    Per-IP rate limiter using token bucket algorithm.
    
    This class manages rate limits for different operation types
    across multiple clients identified by IP address.
    
    Thread-safe implementation using locks.
    """
    
    def __init__(
        self,
        rate_limits: Optional[Dict[str, RateLimitConfig]] = None,
        cleanup_interval: int = 300
    ):
        """
        Initialize the rate limiter.
        
        Args:
            rate_limits: Dictionary of rate limit configurations.
            cleanup_interval: Seconds between bucket cleanups (default: 5 minutes).
        """
        self._rate_limits = rate_limits or DEFAULT_RATE_LIMITS
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
        
        # Nested dict: limit_type -> ip -> TokenBucket
        self._buckets: Dict[str, Dict[str, TokenBucket]] = {
            limit_type: {} for limit_type in self._rate_limits
        }
        
        # Thread safety
        self._lock = Lock()
    
    def is_allowed(self, ip: str, limit_type: str = 'api_general') -> bool:
        """
        Check if a request is allowed under rate limits.
        
        Args:
            ip: Client IP address.
            limit_type: Type of operation ('messages', 'key_exchange', 'api_general').
        
        Returns:
            bool: True if request is allowed, False if rate limited.
        """
        if limit_type not in self._rate_limits:
            limit_type = 'api_general'
        
        with self._lock:
            # Periodic cleanup of old buckets
            self._maybe_cleanup()
            
            # Get or create bucket for this IP
            bucket = self._get_or_create_bucket(ip, limit_type)
            
            return bucket.consume(1.0)
    
    def _get_or_create_bucket(self, ip: str, limit_type: str) -> TokenBucket:
        """Get existing bucket or create new one."""
        buckets = self._buckets[limit_type]
        
        if ip not in buckets:
            config = self._rate_limits[limit_type]
            buckets[ip] = TokenBucket(
                rate=config.rate_per_second,
                capacity=config.capacity
            )
        
        return buckets[ip]
    
    def _maybe_cleanup(self):
        """Clean up old buckets if cleanup interval has passed."""
        now = time.time()
        
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        
        # Remove buckets that haven't been used recently
        # (buckets with full tokens haven't been used)
        for limit_type in self._buckets:
            config = self._rate_limits[limit_type]
            to_remove = []
            
            for ip, bucket in self._buckets[limit_type].items():
                # If bucket is full, it hasn't been used recently
                if bucket.get_tokens() >= config.capacity * 0.99:
                    to_remove.append(ip)
            
            for ip in to_remove:
                del self._buckets[limit_type][ip]
    
    def reset(self, ip: str, limit_type: Optional[str] = None):
        """
        Reset rate limit for an IP.
        
        Args:
            ip: Client IP address.
            limit_type: Specific limit type to reset, or None for all.
        """
        with self._lock:
            if limit_type:
                if limit_type in self._buckets and ip in self._buckets[limit_type]:
                    del self._buckets[limit_type][ip]
            else:
                for lt in self._buckets:
                    if ip in self._buckets[lt]:
                        del self._buckets[lt][ip]
    
    def get_remaining(self, ip: str, limit_type: str = 'api_general') -> float:
        """
        Get remaining tokens for an IP.
        
        Args:
            ip: Client IP address.
            limit_type: Type of operation.
        
        Returns:
            float: Number of remaining tokens.
        """
        if limit_type not in self._rate_limits:
            limit_type = 'api_general'
        
        with self._lock:
            if ip in self._buckets.get(limit_type, {}):
                return self._buckets[limit_type][ip].get_tokens()
            else:
                return self._rate_limits[limit_type].capacity
    
    def get_reset_time(self, ip: str, limit_type: str = 'api_general') -> float:
        """
        Get time until bucket is full again.
        
        Args:
            ip: Client IP address.
            limit_type: Type of operation.
        
        Returns:
            float: Seconds until rate limit resets.
        """
        if limit_type not in self._rate_limits:
            limit_type = 'api_general'
        
        config = self._rate_limits[limit_type]
        remaining = self.get_remaining(ip, limit_type)
        tokens_needed = config.capacity - remaining
        
        if tokens_needed <= 0:
            return 0
        
        return tokens_needed / config.rate_per_second
    
    def get_stats(self) -> Dict:
        """
        Get rate limiter statistics.
        
        Returns:
            dict: Statistics about tracked IPs and buckets.
        """
        with self._lock:
            stats = {}
            for limit_type in self._buckets:
                stats[limit_type] = {
                    'tracked_ips': len(self._buckets[limit_type]),
                    'config': {
                        'rate_per_minute': self._rate_limits[limit_type].rate_per_minute,
                        'capacity': self._rate_limits[limit_type].capacity
                    }
                }
            return stats


# Singleton instance
_rate_limiter_instance: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """
    Get the global RateLimiter instance.
    
    Returns:
        RateLimiter: The singleton RateLimiter instance.
    """
    global _rate_limiter_instance
    if _rate_limiter_instance is None:
        _rate_limiter_instance = RateLimiter()
    return _rate_limiter_instance


# Simple test when run directly
if __name__ == "__main__":
    print("Testing Rate Limiter implementation...")
    
    # Test 1: Basic rate limiting
    print("\n1. Testing basic rate limiting:")
    limiter = RateLimiter()
    test_ip = "192.168.1.100"
    
    # Should allow initial requests
    allowed_count = 0
    for _ in range(10):
        if limiter.is_allowed(test_ip, 'api_general'):
            allowed_count += 1
    
    print(f"   Allowed {allowed_count} requests out of 10")
    assert allowed_count == 10
    print("   ✓ Basic rate limiting works!")
    
    # Test 2: Rate limit exhaustion
    print("\n2. Testing rate limit exhaustion:")
    test_ip2 = "192.168.1.101"
    
    # Exhaust the limit (100 per minute + 50 burst = 150 capacity)
    allowed = 0
    for _ in range(200):
        if limiter.is_allowed(test_ip2, 'api_general'):
            allowed += 1
    
    print(f"   Allowed {allowed} requests before exhaustion")
    assert allowed < 200  # Should not allow all 200
    assert allowed >= 100  # Should allow at least rate_per_minute
    print("   ✓ Rate limit exhaustion works!")
    
    # Test 3: Different limit types
    print("\n3. Testing different limit types:")
    test_ip3 = "192.168.1.102"
    
    # key_exchange is limited to 5 per minute
    ke_allowed = 0
    for _ in range(20):
        if limiter.is_allowed(test_ip3, 'key_exchange'):
            ke_allowed += 1
    
    print(f"   Key exchange: {ke_allowed} requests allowed")
    assert ke_allowed < 20
    assert ke_allowed >= 5
    print("   ✓ Different limit types work!")
    
    # Test 4: Token refill
    print("\n4. Testing token refill:")
    test_ip4 = "192.168.1.103"
    
    # Exhaust some tokens
    for _ in range(50):
        limiter.is_allowed(test_ip4, 'api_general')
    
    remaining_before = limiter.get_remaining(test_ip4, 'api_general')
    
    # Wait a bit for refill
    time.sleep(1)
    
    remaining_after = limiter.get_remaining(test_ip4, 'api_general')
    
    print(f"   Before wait: {remaining_before:.2f} tokens")
    print(f"   After 1 second: {remaining_after:.2f} tokens")
    assert remaining_after > remaining_before
    print("   ✓ Token refill works!")
    
    # Test 5: Reset functionality
    print("\n5. Testing reset functionality:")
    test_ip5 = "192.168.1.104"
    
    # Use some tokens
    for _ in range(50):
        limiter.is_allowed(test_ip5, 'api_general')
    
    before_reset = limiter.get_remaining(test_ip5, 'api_general')
    
    # Reset
    limiter.reset(test_ip5, 'api_general')
    
    after_reset = limiter.get_remaining(test_ip5, 'api_general')
    
    print(f"   Before reset: {before_reset:.2f} tokens")
    print(f"   After reset: {after_reset:.2f} tokens")
    assert after_reset > before_reset
    print("   ✓ Reset works!")
    
    # Test 6: Multiple IPs
    print("\n6. Testing multiple IPs:")
    ips = [f"10.0.0.{i}" for i in range(10)]
    
    for ip in ips:
        # Each IP should have its own bucket
        assert limiter.is_allowed(ip, 'api_general')
    
    stats = limiter.get_stats()
    print(f"   Tracked IPs: {stats['api_general']['tracked_ips']}")
    assert stats['api_general']['tracked_ips'] >= 10
    print("   ✓ Multiple IPs work!")
    
    # Test 7: Statistics
    print("\n7. Testing statistics:")
    stats = limiter.get_stats()
    print(f"   Rate limit types: {list(stats.keys())}")
    for lt, info in stats.items():
        print(f"   - {lt}: {info['config']['rate_per_minute']}/min, "
              f"{info['tracked_ips']} IPs tracked")
    print("   ✓ Statistics work!")
    
    # Test 8: Reset time calculation
    print("\n8. Testing reset time calculation:")
    test_ip8 = "192.168.1.108"
    
    # Exhaust tokens
    while limiter.is_allowed(test_ip8, 'key_exchange'):
        pass
    
    reset_time = limiter.get_reset_time(test_ip8, 'key_exchange')
    print(f"   Reset time for key_exchange: {reset_time:.2f} seconds")
    assert reset_time > 0
    print("   ✓ Reset time calculation works!")
    
    # Test 9: Thread safety (basic test)
    print("\n9. Testing concurrent access:")
    import threading
    
    test_ip9 = "192.168.1.109"
    results = []
    
    def make_requests():
        for _ in range(100):
            results.append(limiter.is_allowed(test_ip9, 'api_general'))
    
    threads = [threading.Thread(target=make_requests) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    allowed = sum(1 for r in results if r)
    print(f"   Concurrent: {allowed} allowed out of {len(results)}")
    assert len(results) == 500  # All threads completed
    print("   ✓ Thread safety works!")
    
    # Test 10: Singleton
    print("\n10. Testing singleton:")
    limiter1 = get_rate_limiter()
    limiter2 = get_rate_limiter()
    assert limiter1 is limiter2
    print("   ✓ Singleton works!")
    
    print("\n" + "="*50)
    print("All Rate Limiter tests passed! ✓")
    print("="*50)