"""
Attack Lab Service

This module provides attack simulation functionality for SecureChat:
- Replay attacks (vulnerable/defended)
- Ciphertext tampering (vulnerable/defended)
- MITM attacks (vulnerable/defended)
- DoS attacks (vulnerable/defended)
"""

import time
import hashlib
from typing import Dict, Any

from backend.services.key_manager import get_key_manager
from backend.models.message import Message
from backend.crypto.aes_gcm import encrypt_message, decrypt_message
from backend.crypto.rsa_oaep import encrypt_key, decrypt_key
from backend.crypto.rsa_pss import sign, verify
from backend.middleware.rate_limiter import get_rate_limiter


def simulate_replay_attack(mode: str) -> Dict[str, Any]:
    """Simulate replay attack with optional defense."""
    km = get_key_manager()
    
    # Generate a test message
    session = km.create_session("alice", "bob")
    session_key = km.get_session_key(session['session_id'], "alice")
    
    # Create a valid message
    message = Message(
        version=1,
        flags=3,  # Encrypted + Signed
        timestamp=int(time.time() * 1000),
        nonce=os.urandom(16),
        sender_id=hashlib.sha256(km.get_public_key("alice")).hexdigest(),
        iv=os.urandom(12),
        ciphertext=os.urandom(32),  # Simulated ciphertext
        auth_tag=os.urandom(16),
        signature=sign(os.urandom(32), km.get_user_keys("alice").private_key)
    )
    
    if mode == 'vulnerable':
        # Vulnerable mode: Replay without validation
        return {
            'attack': 'replay',
            'mode': 'vulnerable',
            'result': 'Attack succeeded',
            'log': 'Captured valid message and replayed immediately.'
        }
    else:  # defended
        # Defended mode: Validate timestamp and nonce
        current_time = int(time.time() * 1000)
        if current_time - message.timestamp > 300000:  # 5 minutes
            return {
                'attack': 'replay',
                'mode': 'defended',
                'result': 'Attack blocked',
                'log': 'Timestamp expired - message rejected.'
            }
        
        # Check nonce (simulated nonce cache)
        nonce_cache = {}
        if message.nonce.hex() in nonce_cache:
            return {
                'attack': 'replay',
                'mode': 'defended',
                'result': 'Attack blocked',
                'log': 'Duplicate nonce detected - message rejected.'
            }
        
        nonce_cache[message.nonce.hex()] = current_time
        
        return {
            'attack': 'replay',
            'mode': 'defended',
            'result': 'Attack blocked',
            'log': 'Timestamp and nonce validation passed - message accepted.'
        }


def simulate_tampering_attack(mode: str) -> Dict[str, Any]:
    """Simulate ciphertext tampering attack with optional defense."""
    km = get_key_manager()
    
    # Generate a test message
    session = km.create_session("alice", "bob")
    session_key = km.get_session_key(session['session_id'], "alice")
    
    # Create a valid message
    message = Message(
        version=1,
        flags=3,  # Encrypted + Signed
        timestamp=int(time.time() * 1000),
        nonce=os.urandom(16),
        sender_id=hashlib.sha256(km.get_public_key("alice")).hexdigest(),
        iv=os.urandom(12),
        ciphertext=os.urandom(32),  # Simulated ciphertext
        auth_tag=os.urandom(16),
        signature=sign(os.urandom(32), km.get_user_keys("alice").private_key)
    )
    
    if mode == 'vulnerable':
        # Vulnerable mode: Modify ciphertext without auth tag validation
        tampered_ciphertext = bytearray(message.ciphertext)
        tampered_ciphertext[10] ^= 0xFF  # Flip bits
        
        try:
            # Attempt decryption (would fail in real scenario)
            decrypted = decrypt_message(
                message.iv,
                bytes(tampered_ciphertext),
                message.auth_tag,
                session_key
            )
            return {
                'attack': 'tampering',
                'mode': 'vulnerable',
                'result': 'Message corrupted',
                'log': 'Modified ciphertext decrypted but data integrity compromised.'
            }
        except Exception as e:
            return {
                'attack': 'tampering',
                'mode': 'vulnerable',
                'result': 'Decryption failed',
                'log': f'Error during decryption: {str(e)}'
            }
    else:  # defended
        # Defended mode: Validate auth tag
        tampered_ciphertext = bytearray(message.ciphertext)
        tampered_ciphertext[10] ^= 0xFF  # Flip bits
        
        try:
            decrypt_message(
                message.iv,
                bytes(tampered_ciphertext),
                message.auth_tag,
                session_key
            )
            # If no exception, tag validation passed (should not happen)
            return {
                'attack': 'tampering',
                'mode': 'defended',
                'result': 'Unexpected success',
                'log': 'Auth tag validation passed despite tampering - potential bug!'
            }
        except Exception as e:
            return {
                'attack': 'tampering',
                'mode': 'defended',
                'result': 'Tampering detected',
                'log': f'AES-GCM auth tag validation failed: {str(e)}'
            }


def simulate_mitm_attack(mode: str) -> Dict[str, Any]:
    """Simulate MITM attack with optional defense."""
    km = get_key_manager()
    
    # Create legitimate session
    session = km.create_session("alice", "bob")
    alice_keys = km.get_user_keys("alice")
    bob_keys = km.get_user_keys("bob")
    
    # Generate valid encrypted session key for bob
    session_key = km.get_session_key(session['session_id'], "alice")
    encrypted_key = encrypt_key(session_key, bob_keys.public_key)
    signature = sign(encrypted_key, alice_keys.private_key)
    
    if mode == 'vulnerable':
        # Vulnerable mode: Attacker substitutes their own public key
        attacker_pub_key = km.get_public_key("eve")
        if not attacker_pub_key:
            # Create attacker keys if not exists
            km.register_user("eve")
            attacker_pub_key = km.get_public_key("eve")
        
        # Attacker encrypts with their own key
        attacker_encrypted_key = encrypt_key(session_key, attacker_pub_key)
        attacker_signature = sign(attacker_encrypted_key, alice_keys.private_key)
        
        return {
            'attack': 'mitm',
            'mode': 'vulnerable',
            'result': 'Key substitution successful',
            'log': 'Attacker replaced bob\'s public key with their own during exchange.'
        }
    else:  # defended
        # Defended mode: Validate signature against legitimate bob's key
        try:
            verify(signature, encrypted_key, bob_keys.public_key)
            return {
                'attack': 'mitm',
                'mode': 'defended',
                'result': 'Signature validation passed',
                'log': 'RSA-PSS signature matched legitimate bob\'s public key.'
            }
        except Exception as e:
            return {
                'attack': 'mitm',
                'mode': 'defended',
                'result': 'Signature validation failed',
                'log': f'MITM detected: {str(e)}'
            }


def simulate_dos_attack(mode: str) -> Dict[str, Any]:
    """Simulate DoS attack with optional defense."""
    km = get_key_manager()
    limiter = get_rate_limiter()
    
    if mode == 'vulnerable':
        # Vulnerable mode: Simulate unlimited requests with resource consumption
        sessions_created = 0
        log_messages = []
        
        try:
            for _ in range(100):  # Simulate 100 concurrent requests
                session = km.create_session("alice", "bob")
                log_messages.append(f"Session created: {session['session_id']}")
                sessions_created += 1
                
            return {
                'attack': 'dos',
                'mode': 'vulnerable',
                'result': 'Service overwhelmed',
                'log': f"Created {sessions_created} sessions. System resources exhausted."
            }
        except Exception as e:
            return {
                'attack': 'dos',
                'mode': 'vulnerable',
                'result': 'Service overwhelmed',
                'log': f"Resource exhaustion error: {str(e)}"
            }
            
    else:  # defended
        # Defended mode: Validate rate limits and demonstrate protection
        client_ip = "127.0.0.1"  # Simulate attacker IP
        
        # Test rate limiting on different endpoints
        endpoints = ['messages', 'key_exchange', 'login_attempts']
        blocked_count = 0
        allowed_count = 0
        log_messages = []
        
        for endpoint in endpoints:
            if not limiter.is_allowed(client_ip, endpoint):
                blocked_count += 1
                log_messages.append(f"Blocked {endpoint} request from {client_ip}")
            else:
                allowed_count += 1
                log_messages.append(f"Allowed {endpoint} request from {client_ip}")
        
        # Add system status information
        system_status = {
            'blocked_requests': blocked_count,
            'allowed_requests': allowed_count,
            'total_requests': blocked_count + allowed_count,
            'rate_limit_config': limiter.get_config()
        }
        
        return {
            'attack': 'dos',
            'mode': 'defended',
            'result': 'Requests blocked' if blocked_count > 0 else 'Some requests allowed',
            'log': ", ".join(log_messages),
            'system_status': system_status
        }


# Example usage (for testing)
if __name__ == "__main__":
    print("Testing Attack Lab simulations...")
    print(simulate_replay_attack('vulnerable'))
    print(simulate_replay_attack('defended'))
    print(simulate_tampering_attack('vulnerable'))
    print(simulate_tampering_attack('defended'))
    print(simulate_mitm_attack('vulnerable'))
    print(simulate_mitm_attack('defended'))
    print(simulate_dos_attack('vulnerable'))
    print(simulate_dos_attack('defended'))