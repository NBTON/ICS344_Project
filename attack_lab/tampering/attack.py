"""
Ciphertext Tampering Attack Implementation

This module demonstrates how an attacker can attempt to modify
encrypted data in transit. The attack shows:

1. Modifying ciphertext bytes (bit-flipping attacks)
2. Modifying the IV (affects first block decryption in some modes)
3. Attempting to modify the authentication tag

Without authenticated encryption (like AES-GCM), some of these
attacks could succeed in corrupting the decrypted plaintext in
predictable ways (e.g., bit-flipping attacks on CBC mode).

With AES-GCM, any tampering is detected via the authentication tag.
"""

import os
import sys
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key, encrypt, decrypt


class TamperingAttacker:
    """
    Demonstrates ciphertext tampering attacks.
    
    The attacker intercepts encrypted messages and modifies them
    in various ways to see how the system responds.
    """
    
    def __init__(self):
        """Initialize the tampering attacker."""
        self.tampering_log = []
    
    def tamper_ciphertext(self, ciphertext: bytes, position: int = 0, 
                          xor_value: int = 0xFF) -> bytes:
        """
        Modify ciphertext bytes using XOR (bit-flipping attack).
        
        In stream ciphers or CTR mode, XORing a byte at position P
        with value V will cause the decrypted byte at position P
        to be XORed with V as well. This allows targeted corruption.
        
        Args:
            ciphertext: The original encrypted data.
            position: Byte position to modify.
            xor_value: Value to XOR with (default: 0xFF flips all bits).
        
        Returns:
            bytes: The tampered ciphertext.
        """
        if not ciphertext:
            return ciphertext
        
        # Ensure position is valid
        position = position % len(ciphertext)
        
        # Convert to mutable bytearray
        tampered = bytearray(ciphertext)
        
        # Log the original value
        original_byte = tampered[position]
        
        # Apply XOR to flip bits
        tampered[position] ^= xor_value
        
        self.tampering_log.append({
            "type": "ciphertext",
            "position": position,
            "original": original_byte,
            "modified": tampered[position],
            "xor_value": xor_value
        })
        
        return bytes(tampered)
    
    def tamper_multiple_bytes(self, ciphertext: bytes, 
                               positions: list = None,
                               xor_values: list = None) -> bytes:
        """
        Modify multiple bytes in the ciphertext.
        
        Args:
            ciphertext: The original encrypted data.
            positions: List of byte positions to modify.
            xor_values: List of XOR values (parallel to positions).
        
        Returns:
            bytes: The tampered ciphertext.
        """
        if not ciphertext:
            return ciphertext
        
        if positions is None:
            positions = [0, len(ciphertext) // 2, -1]
        
        if xor_values is None:
            xor_values = [0xFF] * len(positions)
        
        tampered = bytearray(ciphertext)
        
        for pos, xor_val in zip(positions, xor_values):
            actual_pos = pos % len(tampered)
            original = tampered[actual_pos]
            tampered[actual_pos] ^= xor_val
            
            self.tampering_log.append({
                "type": "ciphertext_multi",
                "position": actual_pos,
                "original": original,
                "modified": tampered[actual_pos]
            })
        
        return bytes(tampered)
    
    def tamper_iv(self, iv: bytes, position: int = 0,
                  xor_value: int = 0xFF) -> bytes:
        """
        Modify IV bits.
        
        In CBC mode, modifying the IV affects the first block of
        decrypted plaintext. In GCM mode, modifying the IV will
        cause authentication to fail.
        
        Args:
            iv: The initialization vector.
            position: Byte position to modify.
            xor_value: Value to XOR with.
        
        Returns:
            bytes: The tampered IV.
        """
        if not iv:
            return iv
        
        position = position % len(iv)
        tampered = bytearray(iv)
        original = tampered[position]
        tampered[position] ^= xor_value
        
        self.tampering_log.append({
            "type": "iv",
            "position": position,
            "original": original,
            "modified": tampered[position]
        })
        
        return bytes(tampered)
    
    def tamper_auth_tag(self, tag: bytes, position: int = 0,
                        xor_value: int = 0xFF) -> bytes:
        """
        Attempt to modify the authentication tag.
        
        This will always cause decryption to fail in AES-GCM mode,
        as the tag is a cryptographic MAC over all data.
        
        Args:
            tag: The authentication tag.
            position: Byte position to modify.
            xor_value: Value to XOR with.
        
        Returns:
            bytes: The tampered tag.
        """
        if not tag:
            return tag
        
        position = position % len(tag)
        tampered = bytearray(tag)
        original = tampered[position]
        tampered[position] ^= xor_value
        
        self.tampering_log.append({
            "type": "auth_tag",
            "position": position,
            "original": original,
            "modified": tampered[position]
        })
        
        return bytes(tampered)
    
    def get_tampering_log(self) -> list:
        """Get the log of all tampering operations."""
        return self.tampering_log.copy()
    
    def clear_log(self):
        """Clear the tampering log."""
        self.tampering_log.clear()
    
    def demonstrate_attack(self, original_message: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run a full tampering attack demonstration.
        
        Shows various tampering techniques and their effects.
        
        Args:
            original_message: Optional pre-encrypted message to tamper with.
        
        Returns:
            dict: Results of the attack demonstration.
        """
        steps = []
        logs = []
        
        def log(level: str, message: str):
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message
            })
        
        self.clear_log()
        
        # Step 1: Create original encrypted message
        log("info", "Creating original encrypted message...")
        key = generate_key()
        plaintext = b"Transfer $100 to Alice"
        ciphertext, iv, tag = encrypt(plaintext, key)
        
        steps.append({
            "step": 1,
            "action": "Create encrypted message",
            "result": f"Encrypted '{plaintext.decode()}' with AES-256-GCM"
        })
        log("info", f"Original plaintext: {plaintext.decode()}")
        log("info", f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Step 2: Verify original message decrypts correctly
        log("info", "Verifying original message decrypts correctly...")
        try:
            decrypted = decrypt(ciphertext, key, iv, tag)
            steps.append({
                "step": 2,
                "action": "Verify original decryption",
                "result": f"Success: '{decrypted.decode()}'"
            })
            log("info", "Original message decrypts successfully")
        except Exception as e:
            log("error", f"Original decryption failed: {e}")
        
        # Step 3: Tamper with ciphertext
        log("warn", "Eve (attacker) intercepts and tampers with ciphertext...")
        tampered_ct = self.tamper_ciphertext(ciphertext, position=10, xor_value=0xFF)
        
        steps.append({
            "step": 3,
            "action": "Tamper with ciphertext (flip bits)",
            "result": f"Modified byte at position 10 (XOR with 0xFF)"
        })
        log("warn", "Ciphertext modified - bit-flipping attack")
        
        # Step 4: Attempt to decrypt tampered message (simulating vulnerable system)
        log("error", "Attempting to decrypt tampered message...")
        
        # In a vulnerable system without authentication, this might produce garbage
        # But with AES-GCM, authentication should fail
        
        steps.append({
            "step": 4,
            "action": "Send tampered message to vulnerable system",
            "result": "Without AEAD: Decryption produces corrupted plaintext"
        })
        log("error", "Vulnerable system might accept corrupted data!")
        
        # Step 5: Try different tampering techniques
        log("warn", "Trying additional tampering techniques...")
        
        # Tamper with IV
        tampered_iv = self.tamper_iv(iv, position=0)
        steps.append({
            "step": 5,
            "action": "Tamper with IV",
            "result": "Modified first byte of IV"
        })
        
        # Tamper with auth tag
        tampered_tag = self.tamper_auth_tag(tag, position=0)
        steps.append({
            "step": 6,
            "action": "Tamper with authentication tag",
            "result": "Modified first byte of auth tag"
        })
        
        log("warn", "Multiple components tampered - full attack attempted")
        
        return {
            "attack_type": "tampering",
            "with_defense": False,
            "steps": steps,
            "logs": logs,
            "attack_success": True,  # Attack succeeds against vulnerable system
            "summary": (
                "Ciphertext tampering attack demonstrated. Without authenticated "
                "encryption, an attacker can modify encrypted data in transit. "
                "The modifications may cause predictable changes in the decrypted "
                "plaintext (e.g., changing '$100' to '$900' via bit-flipping)."
            ),
            "tampering_log": self.get_tampering_log(),
            "original_plaintext": plaintext.decode(),
            "modifications_made": len(self.tampering_log)
        }


if __name__ == "__main__":
    print("=" * 60)
    print("CIPHERTEXT TAMPERING ATTACK DEMONSTRATION")
    print("=" * 60)
    
    attacker = TamperingAttacker()
    result = attacker.demonstrate_attack()
    
    print("\n--- Attack Steps ---")
    for step in result["steps"]:
        print(f"\nStep {step['step']}: {step['action']}")
        print(f"  Result: {step['result']}")
    
    print("\n--- Tampering Log ---")
    for entry in result["tampering_log"]:
        print(f"  {entry['type']}: position {entry['position']}, "
              f"0x{entry['original']:02x} -> 0x{entry['modified']:02x}")
    
    print("\n" + "=" * 60)
    print("SUMMARY:", result["summary"])
    print("=" * 60)