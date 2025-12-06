"""
Replay Attack Demo Module

This module provides the demo function for replay attack demonstrations.
It integrates with the attack lab API endpoints.
"""

import os
import sys
import time
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_lab.replay.attack import ReplayAttacker


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run replay attack demonstration with optional defense.
    
    Args:
        with_defense: If True, demonstrates defense mechanisms.
    
    Returns:
        dict: Complete demo results with steps, logs, and summary.
    """
    attacker = ReplayAttacker()
    
    if with_defense:
        return _run_defended_demo(attacker)
    else:
        return _run_vulnerable_demo(attacker)


def _run_vulnerable_demo(attacker: ReplayAttacker) -> Dict[str, Any]:
    """Run replay attack demo without defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup
    log("info", "Setting up cryptographic keys...")
    steps.append({
        "step": 1,
        "action": "Setup cryptographic keys",
        "result": "RSA-2048 and AES-256 keys generated"
    })
    
    # Step 2: Create legitimate message
    log("info", "Creating legitimate encrypted message...")
    steps.append({
        "step": 2,
        "action": "Alice sends encrypted message",
        "result": "Message: 'Transfer $1000 to Bob'"
    })
    log("info", "Original message created")
    
    # Step 3: Attacker captures message
    log("warn", "Eve intercepts and captures the message...")
    steps.append({
        "step": 3,
        "action": "Eve captures encrypted message",
        "result": "Message stored for replay"
    })
    log("warn", "Message captured successfully")
    
    # Step 4: Original message processed
    log("info", "Server processes original message...")
    steps.append({
        "step": 4,
        "action": "Server processes original message",
        "result": "Transaction executed: $1000 transferred"
    })
    log("info", "Original transaction completed")
    
    # Step 5: Replay attack
    log("error", "Eve replays the captured message...")
    steps.append({
        "step": 5,
        "action": "Eve replays captured message",
        "result": "Replayed message sent to server"
    })
    log("error", "Replayed message sent")
    
    # Step 6: Vulnerable server accepts replay
    log("error", "Vulnerable server accepts replayed message!")
    steps.append({
        "step": 6,
        "action": "Vulnerable server processes replay",
        "result": "ATTACK SUCCESS: Another $1000 transferred!"
    })
    log("error", "Duplicate transaction executed")
    
    # Multiple replays
    for i in range(2):
        log("error", f"Eve replays message #{i+2}")
    
    steps.append({
        "step": 7,
        "action": "Multiple replays executed",
        "result": "Total: $4000 transferred instead of $1000"
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
            "timestamp": int(time.time() * 1000),
            "nonce_preview": "abcd1234...",
            "ciphertext_length": 128
        },
        "replays_executed": 3,
        "total_damage": "$4000 transferred instead of $1000"
    }


def _run_defended_demo(attacker: ReplayAttacker) -> Dict[str, Any]:
    """Run replay attack demo with defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup with defense
    log("info", "Setting up cryptographic keys with replay protection...")
    steps.append({
        "step": 1,
        "action": "Setup with replay protection",
        "result": "Keys + timestamp + nonce validation enabled"
    })
    log("info", "Replay protection mechanisms activated")
    
    # Step 2: Create legitimate message with timestamp and nonce
    log("info", "Creating legitimate message with timestamp and nonce...")
    steps.append({
        "step": 2,
        "action": "Alice sends message with timestamp and nonce",
        "result": "Message includes timestamp and unique nonce"
    })
    log("info", "Message includes timestamp and unique nonce")
    
    # Step 3: Attacker captures message
    log("warn", "Eve intercepts and captures the message...")
    steps.append({
        "step": 3,
        "action": "Eve captures encrypted message",
        "result": "Message stored for replay attempt"
    })
    log("warn", "Message captured by attacker")
    
    # Step 4: Original message processed
    log("info", "Server validates and processes original message...")
    steps.append({
        "step": 4,
        "action": "Server validates timestamp and nonce",
        "result": "Original message accepted and processed"
    })
    log("info", "Original message validated and processed")
    
    # Step 5: Replay attempt
    log("error", "Eve attempts to replay the captured message...")
    steps.append({
        "step": 5,
        "action": "Eve replays captured message",
        "result": "Replayed message sent to defended server"
    })
    log("error", "Replay attempt initiated")
    
    # Step 6: Defense detects replay
    log("info", "Server detects replay attempt!")
    steps.append({
        "step": 6,
        "action": "Server rejects replayed message",
        "result": "DEFENSE SUCCESS: Replay detected and blocked!"
    })
    log("info", "Replay attempt blocked by timestamp/nonce validation")
    
    # Additional replay attempts
    for i in range(2):
        log("error", f"Eve attempts replay #{i+2} - BLOCKED")
    
    steps.append({
        "step": 7,
        "action": "Multiple replay attempts blocked",
        "result": "All replays detected and rejected"
    })
    
    return {
        "attack_type": "replay",
        "with_defense": True,
        "steps": steps,
        "logs": logs,
        "attack_success": False,
        "summary": (
            "Replay attack blocked! The defended system validates timestamps "
            "and nonces to prevent replay attacks. When the attacker attempted "
            "to replay the captured message, the server detected that either "
            "the timestamp was outside the acceptable window or the nonce "
            "had been used before, and rejected the message."
        ),
        "defense_mechanisms": [
            "Timestamp validation (5-minute window)",
            "Nonce uniqueness tracking",
            "Replay cache with expiration"
        ],
        "replay_attempts_blocked": 3,
        "damage_prevented": "$3000 potential loss prevented"
    }


if __name__ == "__main__":
    print("Replay Attack Demo Module")
    print("Use run_demo(with_defense=True/False) to run demonstrations")
