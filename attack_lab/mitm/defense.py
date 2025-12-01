"""
Man-in-the-Middle (MITM) Defense Implementation

This module implements defense against MITM attacks using
RSA-PSS digital signatures for public key authentication.

Defense Strategy:
1. Sign public keys with a trusted identity key
2. Verify signatures before accepting public keys
3. Use certificate chains or pre-exchanged trust anchors
4. Reject any key that doesn't verify

Without a signature from a trusted source, an attacker can't
forge a valid signed public key, making MITM attacks detectable.
"""

import os
import sys
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.rsa_keys import generate_key_pair, serialize_public_key, load_public_key
from backend.crypto.rsa_pss import sign, verify
from backend.crypto.aes_gcm import encrypt as aes_encrypt, decrypt as aes_decrypt


class MITMDefense:
    """
    Defense against MITM attacks using RSA-PSS signatures.
    
    Public keys are signed by the owner's identity key, allowing
    recipients to verify the authenticity of received keys.
    """
    
    def __init__(self):
        """Initialize the MITM defense."""
        self.trusted_keys = {}  # user_id -> public_key
        self.verification_log = []
    
    def register_trusted_key(self, user_id: str, public_key) -> bool:
        """
        Register a trusted public key for a user.
        
        In production, this would involve certificate verification
        or out-of-band key verification.
        
        Args:
            user_id: Identifier for the user.
            public_key: The user's verified public key.
        
        Returns:
            bool: True if registration succeeded.
        """
        self.trusted_keys[user_id] = public_key
        self.verification_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": "register_key",
            "user_id": user_id,
            "result": "success"
        })
        return True
    
    def create_signed_key_exchange(self, public_key: bytes,
                                   private_key,
                                   sender_id: str = None) -> Dict[str, Any]:
        """
        Create a key exchange message with digital signature.
        
        The public key is signed with the sender's private key,
        allowing the recipient to verify it's authentic.
        
        Args:
            public_key: The public key to send (serialized).
            private_key: The sender's private key for signing.
            sender_id: Optional sender identifier.
        
        Returns:
            dict: The signed key exchange message.
        """
        # Sign the public key
        signature = sign(public_key, private_key)
        
        return {
            "public_key": public_key.hex() if isinstance(public_key, bytes) else public_key,
            "signature": signature.hex(),
            "sender_id": sender_id,
            "timestamp": int(datetime.now().timestamp() * 1000)
        }
    
    def verify_key_exchange(self, key_exchange: Dict[str, Any],
                           expected_sender_public_key) -> Tuple[bool, str]:
        """
        Verify a signed key exchange message.
        
        Args:
            key_exchange: The key exchange message with signature.
            expected_sender_public_key: The sender's known public key.
        
        Returns:
            tuple: (is_valid, reason)
        """
        try:
            # Extract components
            public_key_bytes = bytes.fromhex(key_exchange['public_key'])
            signature = bytes.fromhex(key_exchange['signature'])
            
            # Verify the signature
            is_valid = verify(
                public_key_bytes,
                signature,
                expected_sender_public_key
            )
            
            self.verification_log.append({
                "timestamp": datetime.now().isoformat(),
                "action": "verify_key_exchange",
                "result": "valid" if is_valid else "invalid"
            })
            
            if is_valid:
                return True, "Signature verified - key exchange is authentic"
            else:
                return False, "SIGNATURE INVALID - possible MITM attack!"
                
        except Exception as e:
            self.verification_log.append({
                "timestamp": datetime.now().isoformat(),
                "action": "verify_key_exchange",
                "result": "error",
                "error": str(e)
            })
            return False, f"Verification error: {str(e)}"
    
    def verify_key_from_trusted(self, key_exchange: Dict[str, Any],
                                sender_id: str) -> Tuple[bool, str]:
        """
        Verify a key exchange against trusted key registry.
        
        Args:
            key_exchange: The key exchange message.
            sender_id: The claimed sender's ID.
        
        Returns:
            tuple: (is_valid, reason)
        """
        if sender_id not in self.trusted_keys:
            return False, f"Unknown sender '{sender_id}' - not in trusted keys"
        
        trusted_key = self.trusted_keys[sender_id]
        return self.verify_key_exchange(key_exchange, trusted_key)
    
    def create_signed_message(self, plaintext: bytes,
                              session_key: bytes,
                              private_key) -> Dict[str, Any]:
        """
        Create an encrypted and signed message.
        
        Args:
            plaintext: The message content.
            session_key: AES key for encryption.
            private_key: RSA key for signing.
        
        Returns:
            dict: The encrypted and signed message.
        """
        # Encrypt the message
        ciphertext, iv, tag = aes_encrypt(plaintext, session_key)
        
        # Sign the ciphertext (includes IV and tag in signature)
        data_to_sign = ciphertext + iv + tag
        signature = sign(data_to_sign, private_key)
        
        return {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex(),
            "auth_tag": tag.hex(),
            "signature": signature.hex(),
            "timestamp": int(datetime.now().timestamp() * 1000)
        }
    
    def verify_message_signature(self, message: Dict[str, Any],
                                 sender_public_key) -> Tuple[bool, str]:
        """
        Verify the signature on an encrypted message.
        
        Args:
            message: The encrypted message with signature.
            sender_public_key: The sender's public key.
        
        Returns:
            tuple: (is_valid, reason)
        """
        try:
            ciphertext = bytes.fromhex(message['ciphertext'])
            iv = bytes.fromhex(message['iv'])
            tag = bytes.fromhex(message['auth_tag'])
            signature = bytes.fromhex(message['signature'])
            
            # Verify signature over all encrypted data
            data_to_verify = ciphertext + iv + tag
            is_valid = verify(data_to_verify, signature, sender_public_key)
            
            if is_valid:
                return True, "Message signature verified - authentic sender"
            else:
                return False, "INVALID SIGNATURE - message may be forged or modified!"
                
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def get_verification_log(self) -> list:
        """Get the verification log."""
        return self.verification_log.copy()
    
    def clear_log(self):
        """Clear the verification log."""
        self.verification_log.clear()
    
    def demonstrate_defense(self, mitm_key_exchange: Dict[str, Any],
                           legitimate_sender_key) -> Dict[str, Any]:
        """
        Demonstrate the defense blocking a MITM attack.
        
        Args:
            mitm_key_exchange: A key exchange that may be from an attacker.
            legitimate_sender_key: The known legitimate sender's public key.
        
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
        
        log("info", "Defense system activated - verifying key exchange...")
        
        # Step 1: Check signature on key exchange
        is_valid, reason = self.verify_key_exchange(
            mitm_key_exchange,
            legitimate_sender_key
        )
        
        steps.append({
            "step": 1,
            "action": "Verify key exchange signature",
            "result": f"{'PASS' if is_valid else 'FAIL'}: {reason}"
        })
        
        if is_valid:
            log("info", "Key exchange signature verified")
            return {
                "attack_type": "mitm",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": None,
                "summary": "Key exchange verified - this is from the legitimate sender"
            }
        else:
            log("warn", f"MITM DETECTED: {reason}")
            
            steps.append({
                "step": 2,
                "action": "Reject suspicious key exchange",
                "result": "Key exchange rejected - potential MITM attack"
            })
            
            log("info", "MITM attack blocked by signature verification")
            
            return {
                "attack_type": "mitm",
                "with_defense": True,
                "steps": steps,
                "logs": logs,
                "attack_success": False,
                "blocked_by": "signature_verification",
                "summary": (
                    "MITM ATTACK BLOCKED! The attacker's forged key exchange "
                    "was rejected because the signature didn't match the expected "
                    "sender's public key. Without the legitimate sender's private "
                    "key, the attacker cannot forge a valid signature."
                )
            }


if __name__ == "__main__":
    print("=" * 60)
    print("MITM DEFENSE DEMONSTRATION")
    print("=" * 60)
    
    defense = MITMDefense()
    
    # Setup: Create legitimate key pairs
    print("\n1. Setting up Alice's key pair...")
    alice_private, alice_public = generate_key_pair()
    
    # Register Alice's public key as trusted
    defense.register_trusted_key("alice", alice_public)
    print("   Alice's public key registered as trusted")
    
    # Create legitimate signed key exchange
    print("\n2. Alice creates signed key exchange...")
    alice_session_pub = serialize_public_key(alice_public)
    legitimate_exchange = defense.create_signed_key_exchange(
        alice_session_pub,
        alice_private,
        "alice"
    )
    print(f"   Signature: {legitimate_exchange['signature'][:32]}...")
    
    # Verify legitimate exchange
    print("\n3. Bob verifies Alice's key exchange...")
    is_valid, reason = defense.verify_key_exchange(legitimate_exchange, alice_public)
    print(f"   Result: {reason}")
    
    # Create attacker's key exchange (without Alice's private key)
    print("\n4. Eve (attacker) creates fake key exchange...")
    eve_private, eve_public = generate_key_pair()
    eve_pub_bytes = serialize_public_key(eve_public)
    
    # Eve signs with her own key (not Alice's)
    fake_exchange = defense.create_signed_key_exchange(
        eve_pub_bytes,
        eve_private,  # Eve's key, not Alice's!
        "alice"  # Eve claims to be Alice
    )
    print(f"   Eve's signature: {fake_exchange['signature'][:32]}...")
    
    # Verify fake exchange against Alice's key
    print("\n5. Bob verifies 'Alice's' key exchange (actually Eve's)...")
    is_valid, reason = defense.verify_key_exchange(fake_exchange, alice_public)
    print(f"   Result: {reason}")
    
    # Demonstrate defense
    print("\n6. Full defense demonstration...")
    result = defense.demonstrate_defense(fake_exchange, alice_public)
    for step in result["steps"]:
        print(f"   Step {step['step']}: {step['result']}")
    
    print("\n" + "=" * 60)
    print("DEFENSE SUMMARY: Digital signatures prevent MITM key substitution")
    print("=" * 60)