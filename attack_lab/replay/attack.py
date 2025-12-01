"""
Replay Attack Implementation

This module demonstrates how an attacker can capture valid encrypted
messages and replay them later to cause duplicate actions.

In a replay attack:
1. Attacker eavesdrops on network communication
2. Attacker captures a valid encrypted message
3. Attacker resends the exact same message later
4. Without proper defenses, the server accepts the replayed message

The attack succeeds because the encrypted message is still valid -
the encryption hasn't been broken, just reused.
"""

import os
import time
import copy
from typing import Dict, List, Any, Optional
from datetime import datetime

# Import crypto modules from backend (direct imports to avoid Flask dependency)
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key, encrypt, decrypt
from backend.crypto.rsa_keys import generate_key_pair, serialize_public_key
from backend.crypto.rsa_pss import sign, verify


class ReplayAttacker:
    """
    Demonstrates replay attack by capturing and resending messages.
    
    The attacker intercepts valid encrypted messages and stores them
    for later replay. Since the messages are properly encrypted and
    signed, they will be accepted by a vulnerable system.
    """
    
    def __init__(self):
        """Initialize the replay attacker."""
        self.captured_messages: List[Dict[str, Any]] = []
        self.capture_times: List[float] = []
    
    def capture_message(self, encrypted_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Capture a message for later replay.
        
        In a real attack, this would happen by intercepting network
        traffic (e.g., via ARP spoofing, rogue WiFi, etc.)
        
        Args:
            encrypted_message: The complete encrypted message to capture.
        
        Returns:
            dict: The captured message (same as input).
        """
        # Deep copy to simulate network capture
        captured = copy.deepcopy(encrypted_message)
        
        # Store the captured message
        self.captured_messages.append(captured)
        self.capture_times.append(time.time())
        
        return captured
    
    def replay_message(self, message_index: int = -1) -> Optional[Dict[str, Any]]:
        """
        Replay a previously captured message.
        
        Args:
            message_index: Index of message to replay (-1 for most recent).
        
        Returns:
            dict: The replayed message, or None if no messages captured.
        """
        if not self.captured_messages:
            return None
        
        # Get the message to replay
        message = copy.deepcopy(self.captured_messages[message_index])
        
        return message
    
    def get_captured_count(self) -> int:
        """Get the number of captured messages."""
        return len(self.captured_messages)
    
    def get_capture_info(self, index: int = -1) -> Dict[str, Any]:
        """
        Get information about a captured message.
        
        Args:
            index: Index of the message.
        
        Returns:
            dict: Information about the captured message.
        """
        if not self.captured_messages:
            return {}
        
        msg = self.captured_messages[index]
        capture_time = self.capture_times[index]
        
        return {
            "index": index if index >= 0 else len(self.captured_messages) + index,
            "capture_time": datetime.fromtimestamp(capture_time).isoformat(),
            "message_timestamp": msg.get("timestamp"),
            "nonce": msg.get("nonce", "")[:16] + "..." if msg.get("nonce") else None,
            "ciphertext_length": len(msg.get("ciphertext", "")),
            "has_signature": "signature" in msg
        }
    
    def clear_captured(self):
        """Clear all captured messages."""
        self.captured_messages.clear()
        self.capture_times.clear()
    
    def demonstrate_attack(self) -> Dict[str, Any]:
        """
        Run a full replay attack demonstration.
        
        This creates a legitimate message, captures it, and then
        replays it multiple times to show the attack.
        
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
        
        # Step 1: Generate keys for demo
        log("info", "Generating RSA key pair for Alice...")
        private_key, public_key = generate_key_pair()
        session_key = generate_key()
        
        steps.append({
            "step": 1,
            "action": "Setup - Generate cryptographic keys",
            "result": "Created RSA-2048 key pair and AES-256 session key"
        })
        
        # Step 2: Create legitimate message
        log("info", "Alice creates a legitimate encrypted message...")
        plaintext = b"Transfer $1000 to Bob's account"
        ciphertext, iv, tag = encrypt(plaintext, session_key)
        
        timestamp = int(time.time() * 1000)
        nonce = os.urandom(16)
        
        # Sign the message
        timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
        data_to_sign = ciphertext + iv + timestamp_bytes + nonce
        signature = sign(data_to_sign, private_key)
        
        original_message = {
            "timestamp": timestamp,
            "nonce": nonce.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "auth_tag": tag.hex(),
            "signature": signature.hex()
        }
        
        steps.append({
            "step": 2,
            "action": "Alice sends encrypted message",
            "result": f"Message encrypted and signed (plaintext: '{plaintext.decode()}')"
        })
        log("info", f"Original message created with timestamp {timestamp}")
        
        # Step 3: Attacker captures the message
        log("warn", "Eve (attacker) intercepts the network traffic...")
        captured = self.capture_message(original_message)
        
        steps.append({
            "step": 3,
            "action": "Eve captures the encrypted message",
            "result": "Message stored for replay attack"
        })
        log("warn", "Message captured and stored by attacker")
        
        # Step 4: Original message is delivered (simulated)
        log("info", "Server receives and processes original message...")
        steps.append({
            "step": 4,
            "action": "Server processes original message",
            "result": "Transaction executed: $1000 transferred to Bob"
        })
        log("info", "Original transaction completed successfully")
        
        # Step 5: Wait a bit (simulating time passing)
        time.sleep(0.1)  # Small delay for demo
        
        # Step 6: Replay the message
        log("error", "Eve replays the captured message...")
        replayed = self.replay_message()
        
        steps.append({
            "step": 5,
            "action": "Eve replays the captured message",
            "result": "Exact same encrypted message sent again"
        })
        
        # Step 7: Vulnerable server accepts replay
        log("error", "Vulnerable server accepts replayed message!")
        steps.append({
            "step": 6,
            "action": "Vulnerable server processes replay",
            "result": "ATTACK SUCCESS: Another $1000 transferred to Bob!"
        })
        log("error", "Duplicate transaction executed - Attack succeeded!")
        
        # Multiple replays
        log("error", "Eve continues replaying...")
        for i in range(2):
            replayed = self.replay_message()
            log("error", f"Replay #{i+2} accepted by vulnerable server")
        
        steps.append({
            "step": 7,
            "action": "Multiple replays executed",
            "result": "Total of $4000 transferred instead of $1000!"
        })
        
        return {
            "attack_type": "replay",
            "with_defense": False,
            "steps": steps,
            "logs": logs,
            "attack_success": True,
            "summary": (
                "Replay attack successful! The attacker captured a valid "
                "encrypted message and replayed it multiple times. Without "
                "timestamp and nonce validation, the server accepted each "
                "replay as a new valid transaction."
            ),
            "original_message": {
                "timestamp": original_message["timestamp"],
                "nonce_preview": original_message["nonce"][:16] + "...",
                "ciphertext_length": len(original_message["ciphertext"])
            },
            "replays_executed": 3,
            "total_damage": "$4000 transferred instead of $1000"
        }


if __name__ == "__main__":
    print("=" * 60)
    print("REPLAY ATTACK DEMONSTRATION")
    print("=" * 60)
    
    attacker = ReplayAttacker()
    result = attacker.demonstrate_attack()
    
    print("\n--- Attack Steps ---")
    for step in result["steps"]:
        print(f"\nStep {step['step']}: {step['action']}")
        print(f"  Result: {step['result']}")
    
    print("\n--- Attack Logs ---")
    for log in result["logs"]:
        level = log["level"].upper()
        print(f"[{level}] {log['message']}")
    
    print("\n" + "=" * 60)
    print("SUMMARY:", result["summary"])
    print("=" * 60)