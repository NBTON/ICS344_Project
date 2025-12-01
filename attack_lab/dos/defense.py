"""
Denial of Service (DoS) Defense Implementation

This module implements defense against DoS attacks using
token bucket rate limiting. Each client (identified by IP)
has separate rate limits, preventing any single source from
overwhelming the server.

Defense Strategy:
1. Token bucket algorithm for rate limiting
2. Per-IP tracking to isolate attackers
3. Different limits for different operations
4. Graceful degradation under load
"""

import os
import sys
import time
from typing import Dict, Any, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass, field
from threading import Lock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.
    
    Tokens are added at a constant rate up to a maximum capacity.
    Each request consumes one token. If no tokens available,
    the request is rejected.
    """
    rate: float  # tokens per second
    capacity: float  # maximum tokens
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Initialize with full bucket."""
        self.tokens = self.capacity
    
    def consume(self, tokens: float = 1.0) -> Tuple[bool, float]:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume.
        
        Returns:
            tuple: (allowed, remaining_tokens)
        """
        now = time.time()
        
        # Add tokens based on time elapsed
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        # Try to consume tokens
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, self.tokens
        
        return False, self.tokens
    
    def get_tokens(self) -> float:
        """Get current token count after refill."""
        now = time.time()
        elapsed = now - self.last_update
        return min(self.capacity, self.tokens + elapsed * self.rate)
    
    def time_until_available(self) -> float:
        """Get time until at least one token is available."""
        if self.tokens >= 1:
            return 0
        needed = 1 - self.tokens
        return needed / self.rate


class DoSDefense:
    """
    Defense against DoS attacks using token bucket rate limiting.
    
    Each IP address has its own rate limit bucket, preventing
    any single attacker from consuming all server resources.
    """
    
    def __init__(self, rate: float = 10.0, burst: int = 20):
        """
        Initialize the DoS defense.
        
        Args:
            rate: Tokens per second (requests allowed per second).
            burst: Maximum bucket size (allows short bursts).
        """
        self.rate = rate
        self.burst = burst
        self.buckets: Dict[str, TokenBucket] = {}
        self._lock = Lock()
        self.request_log = []
        self.blocked_count = 0
        self.allowed_count = 0
    
    def _get_bucket(self, ip: str) -> TokenBucket:
        """Get or create a bucket for an IP."""
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket(
                rate=self.rate,
                capacity=self.burst
            )
        return self.buckets[ip]
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a request is allowed under rate limits.
        
        Args:
            ip: Client IP address.
        
        Returns:
            tuple: (allowed, info_dict)
        """
        with self._lock:
            bucket = self._get_bucket(ip)
            allowed, remaining = bucket.consume(1.0)
            
            info = {
                "allowed": allowed,
                "remaining_tokens": remaining,
                "rate_limit": self.rate,
                "burst_limit": self.burst,
                "retry_after": bucket.time_until_available() if not allowed else 0
            }
            
            self.request_log.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "allowed": allowed,
                "remaining": remaining
            })
            
            if allowed:
                self.allowed_count += 1
            else:
                self.blocked_count += 1
            
            return allowed, info
    
    def process_request(self, ip: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a request with rate limiting.
        
        Args:
            ip: Client IP address.
            request: The request data.
        
        Returns:
            dict: Response with success/failure status.
        """
        allowed, info = self.check_rate_limit(ip)
        
        if allowed:
            # Simulate processing
            time.sleep(0.005)
            return {
                "success": True,
                "status": 200,
                "message": "Request processed",
                "rate_limit_info": info
            }
        else:
            return {
                "success": False,
                "status": 429,
                "message": "Too Many Requests",
                "retry_after": info["retry_after"],
                "rate_limit_info": info
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get defense statistics."""
        return {
            "total_requests": self.allowed_count + self.blocked_count,
            "allowed": self.allowed_count,
            "blocked": self.blocked_count,
            "block_rate": self.blocked_count / (self.allowed_count + self.blocked_count) 
                         if (self.allowed_count + self.blocked_count) > 0 else 0,
            "tracked_ips": len(self.buckets),
            "rate_limit": self.rate,
            "burst_limit": self.burst
        }
    
    def get_ip_status(self, ip: str) -> Dict[str, Any]:
        """Get rate limit status for a specific IP."""
        with self._lock:
            if ip in self.buckets:
                bucket = self.buckets[ip]
                return {
                    "ip": ip,
                    "remaining_tokens": bucket.get_tokens(),
                    "rate": self.rate,
                    "capacity": self.burst
                }
            return {
                "ip": ip,
                "remaining_tokens": self.burst,  # Full bucket for new IPs
                "rate": self.rate,
                "capacity": self.burst
            }
    
    def reset_ip(self, ip: str):
        """Reset rate limit for an IP."""
        with self._lock:
            if ip in self.buckets:
                del self.buckets[ip]
    
    def reset_all(self):
        """Reset all rate limits and statistics."""
        with self._lock:
            self.buckets.clear()
            self.request_log.clear()
            self.blocked_count = 0
            self.allowed_count = 0
    
    def demonstrate_defense(self, attack_requests: list,
                           attacker_ip: str) -> Dict[str, Any]:
        """
        Demonstrate the defense blocking a DoS attack.
        
        Args:
            attack_requests: List of attack requests.
            attacker_ip: The attacker's IP address.
        
        Returns:
            dict: Results of the defense demonstration.
        """
        steps = []
        logs = []
        
        def log(level: str, message: str):
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message
            })
        
        self.reset_all()
        
        log("info", "DoS defense system activated...")
        log("info", f"Rate limit: {self.rate} req/s, Burst: {self.burst}")
        
        # Step 1: Process initial burst (should allow up to burst limit)
        log("info", "Processing initial request burst...")
        initial_allowed = 0
        initial_blocked = 0
        
        for i, request in enumerate(attack_requests[:30]):
            result = self.process_request(attacker_ip, request)
            if result["success"]:
                initial_allowed += 1
            else:
                initial_blocked += 1
        
        steps.append({
            "step": 1,
            "action": f"Process first 30 requests from {attacker_ip}",
            "result": f"Allowed: {initial_allowed}, Blocked: {initial_blocked}"
        })
        
        log("info", f"Initial burst: {initial_allowed} allowed, {initial_blocked} blocked")
        
        # Step 2: Continue attack (most should be blocked)
        log("warn", "Attacker continues flood...")
        continued_allowed = 0
        continued_blocked = 0
        
        for request in attack_requests[30:100]:
            result = self.process_request(attacker_ip, request)
            if result["success"]:
                continued_allowed += 1
            else:
                continued_blocked += 1
        
        steps.append({
            "step": 2,
            "action": "Process next 70 requests (continued attack)",
            "result": f"Allowed: {continued_allowed}, Blocked: {continued_blocked}"
        })
        
        log("warn", f"Continued attack: {continued_allowed} allowed, {continued_blocked} blocked")
        
        # Step 3: Test legitimate user from different IP
        log("info", "Testing legitimate user from different IP...")
        legitimate_ip = "192.168.1.100"
        legit_allowed = 0
        
        for i in range(5):
            result = self.process_request(legitimate_ip, {"id": i, "data": "legitimate"})
            if result["success"]:
                legit_allowed += 1
        
        steps.append({
            "step": 3,
            "action": "Process 5 requests from legitimate user",
            "result": f"All {legit_allowed}/5 requests allowed"
        })
        
        log("info", f"Legitimate user: {legit_allowed}/5 requests allowed")
        
        # Final statistics
        stats = self.get_stats()
        
        steps.append({
            "step": 4,
            "action": "Defense statistics",
            "result": f"Total blocked: {stats['blocked']}/{stats['total_requests']} "
                     f"({stats['block_rate']*100:.1f}%)"
        })
        
        return {
            "attack_type": "dos",
            "with_defense": True,
            "steps": steps,
            "logs": logs,
            "attack_success": False,  # Attack mitigated
            "blocked_by": "rate_limiter",
            "summary": (
                f"DoS ATTACK MITIGATED! Rate limiting blocked {stats['blocked']} of "
                f"{stats['total_requests']} requests ({stats['block_rate']*100:.1f}%). "
                f"Legitimate users from other IPs were not affected - the defense "
                f"isolates attackers without impacting good traffic."
            ),
            "stats": stats,
            "attacker_blocked": stats["blocked"],
            "legitimate_allowed": legit_allowed
        }


if __name__ == "__main__":
    print("=" * 60)
    print("DoS DEFENSE DEMONSTRATION")
    print("=" * 60)
    
    defense = DoSDefense(rate=10.0, burst=20)
    
    # Generate attack requests
    attack_requests = [{"id": i, "data": f"attack_{i}"} for i in range(100)]
    attacker_ip = "10.0.0.99"
    
    # Run demonstration
    result = defense.demonstrate_defense(attack_requests, attacker_ip)
    
    print("\n--- Defense Steps ---")
    for step in result["steps"]:
        print(f"\nStep {step['step']}: {step['action']}")
        print(f"  Result: {step['result']}")
    
    print("\n--- Defense Statistics ---")
    stats = result["stats"]
    print(f"  Total requests: {stats['total_requests']}")
    print(f"  Allowed: {stats['allowed']}")
    print(f"  Blocked: {stats['blocked']}")
    print(f"  Block rate: {stats['block_rate']*100:.1f}%")
    print(f"  Tracked IPs: {stats['tracked_ips']}")
    
    print("\n" + "=" * 60)
    print("SUMMARY:", result["summary"])
    print("=" * 60)