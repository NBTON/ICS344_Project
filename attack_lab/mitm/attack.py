"""
Man-in-the-Middle (MITM) Attack Implementation

This module demonstrates how an attacker can intercept and manipulate
communications between two parties by positioning themselves in the middle.

MITM Attack on Key Exchange:
1. Alice tries to send her public key to Bob
2. Eve intercepts and replaces Alice's key with Eve's key
3. Bob receives Eve's key thinking it's Alice's
4. Bob encrypts messages with Eve's key
5. Eve decrypts messages, reads/modifies them, re-encrypts for Alice

This attack works when there's no authentication of public keys.
"""

import os
import sys
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.rsa_keys import generate_key_pair, serialize_public_key, load_public_key
from backend.crypto.rsa_oaep import encrypt_key, decrypt_key
from backend.crypto.aes_gcm import generate_key as aes_generate_key, encrypt as aes_encrypt, decrypt as aes_decrypt


class MITMAttacker:
    """
    Demonstrates MITM attack by intercepting key exchange.
    
    Eve (the attacker) generates her own key pair and substitutes
    her public key for the legitimate parties' keys.
    """
    
    def __init__(self):
        """Initialize the MITM attacker with their own key pair."""
        self.attacker_private_key, self.attacker_public_key = generate_key_pair()
        self.intercepted_session_key = None
        self.intercepted_messages = []
        self.action_log = []
    
    def _log_action(self, action: str, details: str = ""):
        """Log an attacker action."""
        self.action_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        })
    
    def intercept_public_key(self, victim_public_key: bytes) -> bytes:
        """
        Intercept and replace a victim's public key with attacker's.
        
        In a real attack, Eve would intercept the network packet
        containing Alice's public key and replace it.
        
        Args:
            victim_public_key: The legitimate public key being sent.
        
        Returns:
            bytes: The attacker's public key (to be sent instead).
        """
        # Store the victim's real public key (for demonstration)
        self._victim_public_key = victim_public_key
        
        # Return attacker's public key instead
        attacker_pub_bytes = serialize_public_key(self.attacker_public_key)
        
        self._log_action(
            "intercept_public_key",
            f"Replaced victim's public key with attacker's key"
        )
        
        return attacker_pub_bytes
    
    def intercept_encrypted_key(self, encrypted_session_key: bytes,
                                sender_private_key,
                                recipient_public_key) -> Tuple[bytes, bytes]:
        """
        Intercept encrypted session key, decrypt it, and re-encrypt for recipient.
        
        This is the core of the MITM attack:
        1. Decrypt the session key using attacker's private key
        2. Store the session key for later message interception
        3. Re-encrypt the session key using the actual recipient's public key
        
        Args:
            encrypted_session_key: Session key encrypted with attacker's public key.
            sender_private_key: Not used - attacker uses their own key.
            recipient_public_key: The real recipient's public key.
        
        Returns:
            tuple: (re_encrypted_key, session_key)
        """
        # Decrypt the session key using attacker's private key
        try:
            self.intercepted_session_key = decrypt_key(
                encrypted_session_key,
                self.attacker_private_key
            )
            
            self._log_action(
                "decrypt_session_key",
                f"Successfully decrypted session key: {self.intercepted_session_key.hex()[:16]}..."
            )
        except Exception as e:
            self._log_action("decrypt_session_key", f"Failed: {e}")
            return encrypted_session_key, None
        
        # Re-encrypt for the actual recipient
        re_encrypted = encrypt_key(
            self.intercepted_session_key,
            recipient_public_key
        )
        
        self._log_action(
            "re_encrypt_session_key",
            "Re-encrypted session key for actual recipient"
        )
        
        return re_encrypted, self.intercepted_session_key
    
    def intercept_message(self, encrypted_message: Dict[str, Any],
                         session_key: bytes = None) -> Tuple[str, Dict[str, Any]]:
        """
        Intercept and decrypt an encrypted message.
        
        If the attacker has the session key, they can decrypt the
        message, read or modify it, and re-encrypt.
        
        Args:
            encrypted_message: The encrypted message dictionary.
            session_key: Optional session key (uses intercepted if not provided).
        
        Returns:
            tuple: (plaintext, potentially_modified_message)
        """
        key = session_key or self.intercepted_session_key
        
        if key is None:
            self._log_action("intercept_message", "Failed - no session key available")
            return None, encrypted_message
        
        try:
            # Extract message components
            ciphertext = bytes.fromhex(encrypted_message['ciphertext'])
            iv = bytes.fromhex(encrypted_message['iv'])
            tag = bytes.fromhex(encrypted_message['auth_tag'])
            
            # Decrypt the message
            plaintext = aes_decrypt(ciphertext, key, iv, tag)
            plaintext_str = plaintext.decode()
            
            self._log_action(
                "intercept_message",
                f"Decrypted message: '{plaintext_str}'"
            )
            
            # Store the intercepted message
            self.intercepted_messages.append({
                "plaintext": plaintext_str,
                "timestamp": datetime.now().isoformat()
            })
            
            return plaintext_str, encrypted_message
            
        except Exception as e:
            self._log_action("intercept_message", f"Decryption failed: {e}")
            return None, encrypted_message
    
    def modify_and_forward_message(self, encrypted_message: Dict[str, Any],
                                   modification_func,
                                   session_key: bytes = None) -> Dict[str, Any]:
        """
        Intercept a message, modify it, and re-encrypt.
        
        Args:
            encrypted_message: The original encrypted message.
            modification_func: Function to modify plaintext.
            session_key: Optional session key.
        
        Returns:
            dict: The modified encrypted message.
        """
        key = session_key or self.intercepted_session_key
        
        if key is None:
            return encrypted_message
        
        try:
            # Decrypt
            ciphertext = bytes.fromhex(encrypted_message['ciphertext'])
            iv = bytes.fromhex(encrypted_message['iv'])
            tag = bytes.fromhex(encrypted_message['auth_tag'])
            
            plaintext = aes_decrypt(ciphertext, key, iv, tag)
            original_text = plaintext.decode()
            
            # Modify
            modified_text = modification_func(original_text)
            
            self._log_action(
                "modify_message",
                f"Modified: '{original_text}' -> '{modified_text}'"
            )
            
            # Re-encrypt with new IV
            new_ciphertext, new_iv, new_tag = aes_encrypt(
                modified_text.encode(), key
            )
            
            # Return modified message
            modified_message = encrypted_message.copy()
            modified_message['ciphertext'] = new_ciphertext.hex()
            modified_message['iv'] = new_iv.hex()
            modified_message['auth_tag'] = new_tag.hex()
            
            return modified_message
            
        except Exception as e:
            self._log_action("modify_message", f"Failed: {e}")
            return encrypted_message
    
    def get_action_log(self) -> list:
        """Get the log of all attacker actions."""
        return self.action_log.copy()
    
    def get_intercepted_messages(self) -> list:
        """Get all intercepted messages."""
        return self.intercepted_messages.copy()
    
    def clear_logs(self):
        """Clear all logs and intercepted data."""
        self.action_log.clear()
        self.intercepted_messages.clear()
        self.intercepted_session_key = None
    
    def demonstrate_attack(self) -> Dict[str, Any]:
        """
        Run a full MITM attack demonstration.
        
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
        
        self.clear_logs()
        
        # Step 1: Setup - Alice and Bob generate their key pairs
        log("info", "Setting up Alice and Bob's key pairs...")
        alice_private, alice_public = generate_key_pair()
        bob_private, bob_public = generate_key_pair()
        
        steps.append({
            "step": 1,
            "action": "Setup - Generate key pairs",
            "result": "Alice and Bob each have RSA-2048 key pairs"
        })
        
        # Step 2: Alice tries to send her public key to Bob
        log("info", "Alice sends her public key to Bob...")
        alice_pub_bytes = serialize_public_key(alice_public)
        
        # Eve intercepts!
        log("error", "Eve intercepts Alice's public key transmission!")
        intercepted_pub = self.intercept_public_key(alice_pub_bytes)
        
        steps.append({
            "step": 2,
            "action": "Key exchange - Alice to Bob (INTERCEPTED)",
            "result": "Eve replaces Alice's public key with her own"
        })
        log("error", "Bob now has Eve's public key, thinking it's Alice's!")
        
        # Step 3: Bob encrypts session key with "Alice's" key (actually Eve's)
        log("info", "Bob generates and encrypts session key for 'Alice'...")
        session_key = aes_generate_key()
        
        # Bob encrypts with Eve's key (thinking it's Alice's)
        eve_pub_key = load_public_key(intercepted_pub)
        encrypted_session_key = encrypt_key(session_key, eve_pub_key)
        
        steps.append({
            "step": 3,
            "action": "Bob encrypts session key",
            "result": "Encrypted with Eve's key (Bob thinks it's Alice's)"
        })
        
        # Step 4: Eve intercepts the encrypted session key
        log("error", "Eve intercepts the encrypted session key!")
        re_encrypted, stolen_key = self.intercept_encrypted_key(
            encrypted_session_key,
            None,  # Not used
            alice_public
        )
        
        steps.append({
            "step": 4,
            "action": "Eve intercepts session key",
            "result": f"Eve now has session key: {stolen_key.hex()[:16]}..."
        })
        log("error", f"Eve decrypted the session key!")
        
        # Step 5: Bob sends encrypted message
        log("info", "Bob sends encrypted message to 'Alice'...")
        plaintext = b"Hi Alice! The secret code is: ALPHA-BRAVO-7749"
        ciphertext, iv, tag = aes_encrypt(plaintext, session_key)
        
        encrypted_msg = {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex(),
            "auth_tag": tag.hex()
        }
        
        steps.append({
            "step": 5,
            "action": "Bob sends encrypted message",
            "result": f"Message: '{plaintext.decode()}'"
        })
        
        # Step 6: Eve intercepts and reads the message
        log("error", "Eve intercepts and decrypts Bob's message!")
        intercepted_text, _ = self.intercept_message(encrypted_msg, stolen_key)
        
        steps.append({
            "step": 6,
            "action": "Eve reads the message",
            "result": f"Eve sees: '{intercepted_text}'"
        })
        log("error", f"CONFIDENTIALITY BREACH: Eve read the secret message!")
        
        # Step 7: Eve modifies the message
        log("error", "Eve modifies the message before forwarding...")
        modified_msg = self.modify_and_forward_message(
            encrypted_msg,
            lambda text: text.replace("ALPHA-BRAVO-7749", "COMPROMISED"),
            stolen_key
        )
        
        steps.append({
            "step": 7,
            "action": "Eve modifies and forwards",
            "result": "Changed 'ALPHA-BRAVO-7749' to 'COMPROMISED'"
        })
        
        return {
            "attack_type": "mitm",
            "with_defense": False,
            "steps": steps,
            "logs": logs,
            "attack_success": True,
            "summary": (
                "MITM attack successful! Eve intercepted the key exchange, "
                "obtained the session key, read all encrypted messages, and "
                "even modified a message in transit. Without authentication "
                "of public keys, the attack is undetectable."
            ),
            "attacker_actions": self.get_action_log(),
            "intercepted_messages": self.get_intercepted_messages(),
            "session_key_stolen": stolen_key.hex() if stolen_key else None
        }


if __name__ == "__main__":
    print("=" * 60)
    print("MAN-IN-THE-MIDDLE ATTACK DEMONSTRATION")
    print("=" * 60)
    
    attacker = MITMAttacker()
    result = attacker.demonstrate_attack()
    
    print("\n--- Attack Steps ---")
    for step in result["steps"]:
        print(f"\nStep {step['step']}: {step['action']}")
        print(f"  Result: {step['result']}")
    
    print("\n--- Attacker Actions ---")
    for action in result["attacker_actions"]:
        print(f"  • {action['action']}: {action['details']}")
    
    print("\n--- Intercepted Messages ---")
    for msg in result["intercepted_messages"]:
        print(f"  • '{msg['plaintext']}'")
    
    print("\n" + "=" * 60)
    print("SUMMARY:", result["summary"])
    print("=" * 60)