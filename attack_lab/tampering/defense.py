"""
Ciphertext Tampering Defense Implementation

This module implements defense against tampering attacks using
AES-GCM's built-in authentication tag verification.

AES-GCM provides Authenticated Encryption with Associated Data (AEAD):
- The authentication tag is computed over the ciphertext, IV, and optional AAD
- Any modification to any component causes tag verification to fail
- This provides both confidentiality AND integrity

Defense mechanism:
1. Always use authenticated encryption (AES-GCM, ChaCha20-Poly1305, etc.)
2. Verify the authentication tag before decryption
3. Reject any message where verification fails
"""

import os
import sys
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key, encrypt, decrypt
from cryptography.exceptions import InvalidTag


class TamperingDefense:
    """
    Defense against ciphertext tampering using AES-GCM authentication.
    
    AES-GCM provides authenticated encryption, meaning any tampering
    with the ciphertext, IV, or tag will be detected during decryption.
    """
    
    def __init__(self):
        """Initialize the tampering defense."""
        self.verification_log = []
    
    def verify_and_decrypt(self, ciphertext: bytes, key: bytes,
                           iv: bytes, tag: bytes) -> Tuple[bool, Optional[bytes], str]:
        """
        Verify the authentication tag and decrypt the message.
        
        This is the core defense mechanism. If any tampering has occurred,
        the tag verification will fail and an InvalidTag exception is raised.
        
        Args:
            ciphertext: The encrypted data.
            key: The AES-256 key.
            iv: The initialization vector.
            tag: The authentication tag.
        
        Returns:
            tuple: (is_valid, plaintext or None, message)
                - is_valid: True if verification succeeded
                - plaintext: The decrypted data (or None if verification failed)
                - message: Description of the result
        """
        try:
            # AES-GCM decrypt verifies the tag automatically
            plaintext = decrypt(ciphertext, key, iv, tag)
            
            self.verification_log.append({
                "timestamp": datetime.now().isoformat(),
                "result": "success",
                "ciphertext_len": len(ciphertext),
                "plaintext_len": len(plaintext)
            })
            
            return True, plaintext, "Authentication tag verified - message is authentic"
            
        except InvalidTag:
            self.verification_log.append({
                "timestamp": datetime.now().isoformat(),
                "result": "failed",
                "reason": "InvalidTag",
                "ciphertext_len": len(ciphertext)
            })
            
            return False, None, "TAMPERING DETECTED: Authentication tag verification failed"
            
        except ValueError as e:
            self.verification_log.append({
                "timestamp": datetime.now().isoformat(),
                "result": "error",
                "reason": str(e)
            })
            
            return False, None, f"Validation error: {str(e)}"
    
    def verify_message_integrity(self, message: Dict[str, Any], 
                                  key: bytes) -> Tuple[bool, str]:
        """
        Verify the integrity of a complete encrypted message.
        
        Args:
            message: Dictionary with 'ciphertext', 'iv', and 'auth_tag' (hex encoded).
            key: The AES-256 key.
        
        Returns:
            tuple: (is_valid, reason)
        """
        try:
            ciphertext = bytes.fromhex(message.get('ciphertext', ''))
            iv = bytes.fromhex(message.get('iv', ''))
            tag = bytes.fromhex(message.get('auth_tag', ''))
            
            is_valid, plaintext, reason = self.verify_and_decrypt(
                ciphertext, key, iv, tag
            )
            
            return is_valid, reason
            
        except (ValueError, KeyError) as e:
            return False, f"Invalid message format: {e}"
    
    def get_verification_log(self) -> list:
        """Get the log of all verification attempts."""
        return self.verification_log.copy()
    
    def clear_log(self):
        """Clear the verification log."""
        self.verification_log.clear()
    
    def demonstrate_defense(self, tampered_ciphertext: bytes,
                           tampered_iv: bytes,
                           tampered_tag: bytes,
                           original_key: bytes) -> Dict[str, Any]:
        """
        Demonstrate the defense blocking a tampering attack.
        
        Args:
            tampered_ciphertext: Potentially tampered ciphertext.
            tampered_iv: Potentially tampered IV.
            tampered_tag: Potentially tampered authentication tag.
            original_key: The original encryption key.
        
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
        
        log("info", "Defense system activated - verifying message integrity...")
        
        # Step 1: Attempt to verify and decrypt
        log("info", "Attempting to verify authentication tag...")
        
        is_valid, plaintext, reason = self.verify_and_decrypt(
            tampered_ciphertext, original_key, tampered_iv, tampered_tag
        )
        
        steps.append({
            "step": 1,
            "action": "Verify authentication tag",
            "result": f"{'PASS' if is_valid else 'FAIL'}: {reason}"
        })
        
        if is_valid:
            log("info", f"Tag verification passed - decrypted: {plaintext}")
            return {
                "attack_type": "tampering",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": None,
                "summary": "Message integrity verified - no tampering detected",
                "plaintext": plaintext.decode() if plaintext else None
            }
        else:
            log("warn", f"Tag verification FAILED: {reason}")
            
            steps.append({
                "step": 2,
                "action": "Reject tampered message",
                "result": "Message rejected - integrity check failed"
            })
            
            log("info", "Tampered message rejected by AES-GCM authentication")
            
            return {
                "attack_type": "tampering",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": "gcm_authentication",
                "summary": (
                    "TAMPERING ATTACK BLOCKED! AES-GCM authentication tag "
                    "verification detected the modified data. The tampered "
                    "message was rejected and no corrupted data was processed."
                )
            }


def encrypt_with_integrity(plaintext: bytes, key: bytes = None) -> Dict[str, Any]:
    """
    Encrypt a message with full integrity protection.
    
    Args:
        plaintext: The data to encrypt.
        key: Optional AES key (generated if not provided).
    
    Returns:
        dict: The encrypted message with all components.
    """
    if key is None:
        key = generate_key()
    
    ciphertext, iv, tag = encrypt(plaintext, key)
    
    return {
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
        "auth_tag": tag.hex(),
        "key": key.hex()  # In production, key would be exchanged separately
    }


if __name__ == "__main__":
    print("=" * 60)
    print("TAMPERING DEFENSE DEMONSTRATION")
    print("=" * 60)
    
    defense = TamperingDefense()
    
    # Create an encrypted message
    print("\n1. Creating encrypted message with AES-GCM...")
    key = generate_key()
    plaintext = b"Transfer $1000 to Bob"
    ciphertext, iv, tag = encrypt(plaintext, key)
    print(f"   Plaintext: {plaintext.decode()}")
    print(f"   Ciphertext: {ciphertext.hex()[:32]}...")
    print(f"   IV: {iv.hex()}")
    print(f"   Tag: {tag.hex()}")
    
    # Test 1: Verify original (unmodified) message
    print("\n2. Verifying original message...")
    is_valid, decrypted, reason = defense.verify_and_decrypt(ciphertext, key, iv, tag)
    print(f"   Result: {reason}")
    if decrypted:
        print(f"   Decrypted: {decrypted.decode()}")
    
    # Test 2: Tamper with ciphertext
    print("\n3. Testing tampered ciphertext...")
    tampered_ct = bytearray(ciphertext)
    tampered_ct[5] ^= 0xFF  # Flip bits
    is_valid, decrypted, reason = defense.verify_and_decrypt(bytes(tampered_ct), key, iv, tag)
    print(f"   Result: {reason}")
    
    # Test 3: Tamper with IV
    print("\n4. Testing tampered IV...")
    tampered_iv = bytearray(iv)
    tampered_iv[0] ^= 0xFF
    is_valid, decrypted, reason = defense.verify_and_decrypt(ciphertext, key, bytes(tampered_iv), tag)
    print(f"   Result: {reason}")
    
    # Test 4: Tamper with tag
    print("\n5. Testing tampered authentication tag...")
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0xFF
    is_valid, decrypted, reason = defense.verify_and_decrypt(ciphertext, key, iv, bytes(tampered_tag))
    print(f"   Result: {reason}")
    
    # Show verification log
    print("\n6. Verification log:")
    for entry in defense.get_verification_log():
        print(f"   - {entry['result']}: {entry.get('reason', 'OK')}")
    
    print("\n" + "=" * 60)
    print("DEFENSE SUMMARY: AES-GCM authentication detects ALL tampering")
    print("=" * 60)