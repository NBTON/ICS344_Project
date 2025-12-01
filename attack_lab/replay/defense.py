"""
Replay Attack Defense Implementation

This module implements defenses against replay attacks using:
1. Timestamp validation - Messages must be within a time window
2. Nonce tracking - Each nonce can only be used once

Defense Strategy:
- Check timestamp is within acceptable window (default: 5 minutes)
- Check nonce has not been seen before
- Store used nonces with TTL for automatic cleanup
- Reject messages that fail either check
"""

import os
import time
from typing import Dict, Tuple, Set, Any, Optional
from datetime import datetime
from collections import OrderedDict
from threading import Lock

# Import crypto modules from backend (direct imports to avoid Flask dependency)
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key as generate_aes_key, encrypt, decrypt
from backend.crypto.rsa_keys import generate_key_pair
from backend.crypto.rsa_pss import sign, verify


class NonceCache:
    """
    A cache for tracking used nonces with TTL-based expiration.
    
    Uses an OrderedDict to maintain insertion order for efficient
    cleanup of expired entries.
    """
    
    def __init__(self, ttl_seconds: int = 600):
        """
        Initialize the nonce cache.
        
        Args:
            ttl_seconds: Time-to-live for nonces (default: 10 minutes).
        """
        self.ttl = ttl_seconds
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = Lock()
    
    def add(self, nonce: str) -> bool:
        """
        Add a nonce to the cache.
        
        Args:
            nonce: The nonce to add.
        
        Returns:
            bool: True if nonce was added (not seen before), False if already exists.
        """
        with self._lock:
            # Clean up expired entries first
            self._cleanup()
            
            # Check if nonce already exists
            if nonce in self._cache:
                return False
            
            # Add nonce with current timestamp
            self._cache[nonce] = time.time()
            return True
    
    def contains(self, nonce: str) -> bool:
        """Check if a nonce is in the cache."""
        with self._lock:
            self._cleanup()
            return nonce in self._cache
    
    def _cleanup(self):
        """Remove expired entries from the cache."""
        now = time.time()
        cutoff = now - self.ttl
        
        # Remove expired entries from the front
        while self._cache:
            oldest_nonce, oldest_time = next(iter(self._cache.items()))
            if oldest_time < cutoff:
                del self._cache[oldest_nonce]
            else:
                break
    
    def size(self) -> int:
        """Get the number of nonces in the cache."""
        with self._lock:
            self._cleanup()
            return len(self._cache)
    
    def clear(self):
        """Clear all nonces from the cache."""
        with self._lock:
            self._cache.clear()


class ReplayDefense:
    """
    Defense against replay attacks using timestamps and nonces.
    
    This class validates incoming messages to ensure they:
    1. Have a timestamp within the acceptable time window
    2. Have a nonce that hasn't been used before
    """
    
    def __init__(self, time_window_seconds: int = 300, nonce_ttl_seconds: int = 600):
        """
        Initialize replay defense.
        
        Args:
            time_window_seconds: Maximum age of valid messages (default: 5 minutes).
            nonce_ttl_seconds: How long to track nonces (default: 10 minutes).
        """
        self.time_window = time_window_seconds
        self.nonce_cache = NonceCache(ttl_seconds=nonce_ttl_seconds)
    
    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure 16-byte nonce.
        
        Returns:
            bytes: A 16-byte random nonce.
        """
        return os.urandom(16)
    
    def validate_timestamp(self, timestamp_ms: int) -> Tuple[bool, str]:
        """
        Validate that a message timestamp is within the acceptable window.
        
        Args:
            timestamp_ms: Message timestamp in milliseconds since epoch.
        
        Returns:
            tuple: (is_valid, reason)
        """
        now_ms = int(time.time() * 1000)
        age_ms = now_ms - timestamp_ms
        
        # Check if timestamp is in the future (with small tolerance for clock skew)
        if age_ms < -5000:  # 5 second tolerance for future timestamps
            return False, f"Timestamp is in the future by {-age_ms}ms"
        
        # Check if timestamp is too old
        max_age_ms = self.time_window * 1000
        if age_ms > max_age_ms:
            return False, f"Timestamp is too old: {age_ms}ms > {max_age_ms}ms"
        
        return True, "Timestamp is valid"
    
    def validate_nonce(self, nonce: str) -> Tuple[bool, str]:
        """
        Validate that a nonce has not been used before.
        
        Args:
            nonce: The nonce to validate (hex string).
        
        Returns:
            tuple: (is_valid, reason)
        """
        # Try to add the nonce to the cache
        if self.nonce_cache.add(nonce):
            return True, "Nonce is unique"
        else:
            return False, "Nonce has already been used (replay detected)"
    
    def validate_message(self, message: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate that a message is not a replay.
        
        Checks both timestamp and nonce validity.
        
        Args:
            message: The message dictionary containing 'timestamp' and 'nonce'.
        
        Returns:
            tuple: (is_valid, reason)
        """
        # Extract timestamp
        timestamp = message.get("timestamp")
        if timestamp is None:
            return False, "Message missing timestamp"
        
        # Extract nonce
        nonce = message.get("nonce")
        if nonce is None:
            return False, "Message missing nonce"
        
        # Validate timestamp first
        ts_valid, ts_reason = self.validate_timestamp(timestamp)
        if not ts_valid:
            return False, f"Timestamp validation failed: {ts_reason}"
        
        # Validate nonce
        nonce_valid, nonce_reason = self.validate_nonce(nonce)
        if not nonce_valid:
            return False, f"Nonce validation failed: {nonce_reason}"
        
        return True, "Message is valid (not a replay)"
    
    def demonstrate_defense(self, attack_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Demonstrate the defense blocking a replay attack.
        
        Args:
            attack_message: A message that might be a replay.
        
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
        
        log("info", "Defense system activated - validating incoming message...")
        
        # Step 1: Check timestamp
        timestamp = attack_message.get("timestamp", 0)
        ts_valid, ts_reason = self.validate_timestamp(timestamp)
        
        steps.append({
            "step": 1,
            "action": "Validate timestamp",
            "result": f"{'PASS' if ts_valid else 'FAIL'}: {ts_reason}"
        })
        
        if ts_valid:
            log("info", f"Timestamp check passed: {ts_reason}")
        else:
            log("warn", f"Timestamp check failed: {ts_reason}")
            return {
                "attack_type": "replay",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": "timestamp",
                "summary": f"Replay attack blocked by timestamp validation: {ts_reason}"
            }
        
        # Step 2: Check nonce
        nonce = attack_message.get("nonce", "")
        
        # For demonstration, we check if this nonce was already used
        nonce_valid, nonce_reason = self.validate_nonce(nonce)
        
        steps.append({
            "step": 2,
            "action": "Validate nonce",
            "result": f"{'PASS' if nonce_valid else 'FAIL'}: {nonce_reason}"
        })
        
        if nonce_valid:
            log("info", f"Nonce check passed: {nonce_reason}")
        else:
            log("warn", f"Nonce check failed: {nonce_reason}")
            return {
                "attack_type": "replay",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": "nonce",
                "summary": f"Replay attack blocked by nonce validation: {nonce_reason}"
            }
        
        # If both checks pass, message is accepted
        log("info", "All validation checks passed - message accepted")
        
        steps.append({
            "step": 3,
            "action": "Process message",
            "result": "Message accepted and processed"
        })
        
        return {
            "attack_type": "replay",
            "with_defense": True,
            "steps": steps,
            "logs": logs,
            "attack_success": False,
            "blocked_by": None,
            "summary": "Message validation passed - this is a legitimate message"
        }
    
    def reset(self):
        """Reset the defense state (clear nonce cache)."""
        self.nonce_cache.clear()


def create_protected_message(
    plaintext: bytes,
    session_key: bytes,
    private_key,
    defense: ReplayDefense
) -> Dict[str, Any]:
    """
    Create a message with replay protection.
    
    Args:
        plaintext: The message content.
        session_key: AES session key for encryption.
        private_key: RSA private key for signing.
        defense: ReplayDefense instance for nonce generation.
    
    Returns:
        dict: The protected encrypted message.
    """
    # Encrypt the message
    ciphertext, iv, tag = encrypt(plaintext, session_key)
    
    # Generate timestamp and nonce
    timestamp = int(time.time() * 1000)
    nonce = defense.generate_nonce()
    
    # Sign the message
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    data_to_sign = ciphertext + iv + timestamp_bytes + nonce
    signature = sign(data_to_sign, private_key)
    
    return {
        "timestamp": timestamp,
        "nonce": nonce.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "auth_tag": tag.hex(),
        "signature": signature.hex()
    }


if __name__ == "__main__":
    print("=" * 60)
    print("REPLAY DEFENSE DEMONSTRATION")
    print("=" * 60)
    
    # Create defense system
    defense = ReplayDefense(time_window_seconds=300)
    
    # Generate keys
    private_key, public_key = generate_key_pair()
    session_key = generate_aes_key()
    
    # Create a protected message
    print("\n1. Creating a protected message...")
    message = create_protected_message(
        b"Transfer $1000 to Bob",
        session_key,
        private_key,
        defense
    )
    print(f"   Timestamp: {message['timestamp']}")
    print(f"   Nonce: {message['nonce'][:16]}...")
    
    # First validation (should succeed)
    print("\n2. First message validation (should pass)...")
    result = defense.demonstrate_defense(message)
    print(f"   Result: {result['summary']}")
    
    # Replay attempt (should fail)
    print("\n3. Replay attempt with same message (should fail)...")
    result = defense.demonstrate_defense(message)
    print(f"   Result: {result['summary']}")
    print(f"   Blocked by: {result.get('blocked_by', 'N/A')}")
    
    # Old timestamp test
    print("\n4. Testing expired timestamp...")
    old_message = message.copy()
    old_message["timestamp"] = int((time.time() - 600) * 1000)  # 10 minutes ago
    old_message["nonce"] = os.urandom(16).hex()  # New nonce
    result = defense.demonstrate_defense(old_message)
    print(f"   Result: {result['summary']}")
    
    print("\n" + "=" * 60)
    print("DEFENSE SUMMARY: Replay attacks blocked by timestamp and nonce validation")
    print("=" * 60)