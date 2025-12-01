"""
Replay Attack Interactive Demo

This module provides a complete interactive demonstration of:
1. How replay attacks work against unprotected systems
2. How timestamp + nonce validation defends against replay attacks

Run this demo directly:
    python -m attack_lab.replay.demo
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key as generate_aes_key, encrypt, decrypt
from backend.crypto.rsa_keys import generate_key_pair
from backend.crypto.rsa_pss import sign, verify
from attack_lab.replay.attack import ReplayAttacker
from attack_lab.replay.defense import ReplayDefense, create_protected_message


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run the replay attack demonstration.
    
    Args:
        with_defense: If True, enable replay protection defenses.
    
    Returns:
        dict: Demo results with steps, logs, and outcome.
    """
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def add_step(step_num: int, action: str, result: str):
        steps.append({
            "step": step_num,
            "action": action,
            "result": result
        })
    
    # Initialize components
    attacker = ReplayAttacker()
    defense = ReplayDefense(time_window_seconds=300) if with_defense else None
    
    log("info", f"Starting replay attack demo (defense: {'enabled' if with_defense else 'disabled'})")
    
    # Step 1: Setup - Generate keys
    log("info", "Setting up cryptographic keys...")
    private_key, public_key = generate_key_pair()
    session_key = generate_aes_key()
    
    add_step(1, "Setup - Generate cryptographic keys",
             "RSA-2048 key pair and AES-256 session key created")
    
    # Step 2: Alice creates and sends a legitimate message
    log("info", "Alice creates a legitimate encrypted message...")
    plaintext = b"Transfer $1000 to Bob's account #12345"
    
    if with_defense:
        # Create message with replay protection
        original_message = create_protected_message(
            plaintext, session_key, private_key, defense
        )
        log("info", f"Message includes timestamp {original_message['timestamp']} and unique nonce")
    else:
        # Create message without replay protection
        ciphertext, iv, tag = encrypt(plaintext, session_key)
        timestamp = int(time.time() * 1000)
        nonce = os.urandom(16)
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
    
    add_step(2, "Alice sends encrypted message",
             f"Message encrypted (content: '{plaintext.decode()[:30]}...')")
    
    # Step 3: Attacker captures the message
    log("warn", "Eve (attacker) intercepts the network traffic...")
    captured = attacker.capture_message(original_message)
    
    add_step(3, "Eve intercepts the message",
             f"Captured message with nonce {captured['nonce'][:16]}...")
    log("warn", "Message captured for replay attack")
    
    # Step 4: Original message is processed
    log("info", "Server receives original message...")
    
    if with_defense:
        # Validate the original message
        is_valid, reason = defense.validate_message(original_message)
        if is_valid:
            log("info", "Original message validated and processed")
            add_step(4, "Server processes original message",
                     "Validation passed - Transaction: $1000 to Bob")
        else:
            log("error", f"Unexpected: Original message rejected - {reason}")
    else:
        log("info", "Message accepted (no validation)")
        add_step(4, "Server processes original message",
                 "Transaction executed: $1000 transferred to Bob")
    
    # Step 5: Time passes, attacker prepares replay
    time.sleep(0.1)  # Small delay for demo
    log("warn", "Some time passes...")
    log("error", "Eve prepares to replay the captured message...")
    
    add_step(5, "Eve prepares replay attack",
             "Using previously captured message...")
    
    # Step 6: Replay attempt
    replayed_message = attacker.replay_message()
    log("error", "Eve sends replayed message to server...")
    
    attack_success = False
    
    if with_defense:
        # Try to validate the replayed message
        is_valid, reason = defense.validate_message(replayed_message)
        
        if is_valid:
            log("error", "Replay accepted - DEFENSE FAILED!")
            add_step(6, "Replay attempt",
                     "UNEXPECTED: Replay accepted!")
            attack_success = True
        else:
            log("info", f"Replay blocked: {reason}")
            add_step(6, "Replay attempt",
                     f"BLOCKED: {reason}")
            attack_success = False
    else:
        log("error", "Replayed message accepted - no validation!")
        add_step(6, "Replay attempt",
                 "ATTACK SUCCESS: Duplicate transaction executed!")
        attack_success = True
    
    # Step 7: Multiple replay attempts (if defense enabled)
    if with_defense:
        log("warn", "Eve attempts multiple replays...")
        blocked_count = 0
        for i in range(3):
            replayed = attacker.replay_message()
            is_valid, reason = defense.validate_message(replayed)
            if not is_valid:
                blocked_count += 1
                log("info", f"Replay #{i+1} blocked: {reason}")
        
        add_step(7, f"Multiple replay attempts ({3} total)",
                 f"All {blocked_count} replays blocked by defense")
    else:
        log("error", "Eve continues replaying the message...")
        add_step(7, "Multiple replays",
                 "ATTACK SUCCESS: 3 more duplicate transactions!")
    
    # Summary
    if with_defense:
        if attack_success:
            summary = (
                "DEFENSE FAILED: Despite having replay protection enabled, "
                "the attack succeeded. This indicates a bug in the defense."
            )
        else:
            summary = (
                "DEFENSE SUCCESSFUL: The replay attack was blocked! "
                "Timestamp and nonce validation prevented duplicate transactions. "
                "The original message was processed once, and all replay attempts were rejected."
            )
    else:
        summary = (
            "ATTACK SUCCESSFUL: Without replay protection, the attacker was able "
            "to capture a valid encrypted message and replay it multiple times. "
            "This resulted in duplicate transactions being processed, causing "
            "financial damage to the victim."
        )
    
    return {
        "attack_type": "replay",
        "with_defense": with_defense,
        "steps": steps,
        "logs": logs,
        "attack_success": attack_success,
        "summary": summary,
        "captured_messages": attacker.get_captured_count(),
        "defense_status": "enabled" if with_defense else "disabled"
    }


def main():
    """Run the demo with both modes and display results."""
    print("=" * 70)
    print("                    REPLAY ATTACK DEMONSTRATION")
    print("=" * 70)
    
    # Run without defense
    print("\n" + "-" * 70)
    print("SCENARIO 1: Vulnerable System (No Defense)")
    print("-" * 70)
    
    result = run_demo(with_defense=False)
    
    print("\n--- Steps ---")
    for step in result["steps"]:
        print(f"\n  Step {step['step']}: {step['action']}")
        print(f"    → {step['result']}")
    
    print("\n--- Event Log ---")
    for log in result["logs"]:
        level_icon = {"info": "ℹ", "warn": "⚠", "error": "✖"}.get(log["level"], "•")
        print(f"  {level_icon} [{log['level'].upper()}] {log['message']}")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'FAILED'}")
    print(f"\n{result['summary']}")
    
    # Run with defense
    print("\n" + "-" * 70)
    print("SCENARIO 2: Protected System (Defense Enabled)")
    print("-" * 70)
    
    result = run_demo(with_defense=True)
    
    print("\n--- Steps ---")
    for step in result["steps"]:
        print(f"\n  Step {step['step']}: {step['action']}")
        print(f"    → {step['result']}")
    
    print("\n--- Event Log ---")
    for log in result["logs"]:
        level_icon = {"info": "ℹ", "warn": "⚠", "error": "✖"}.get(log["level"], "•")
        print(f"  {level_icon} [{log['level'].upper()}] {log['message']}")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'BLOCKED'}")
    print(f"\n{result['summary']}")
    
    # Final comparison
    print("\n" + "=" * 70)
    print("                         COMPARISON")
    print("=" * 70)
    print("""
    ┌─────────────────────────────────────────────────────────────────┐
    │                    WITHOUT DEFENSE                              │
    ├─────────────────────────────────────────────────────────────────┤
    │  • Attacker captures valid encrypted message                    │
    │  • Replays are accepted as valid (encryption is intact)         │
    │  • Multiple duplicate transactions executed                     │
    │  • Result: ATTACK SUCCEEDS                                      │
    └─────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────┐
    │                     WITH DEFENSE                                │
    ├─────────────────────────────────────────────────────────────────┤
    │  • Timestamp validation: Reject old messages                    │
    │  • Nonce tracking: Each nonce used only once                    │
    │  • Replays detected and blocked                                 │
    │  • Result: ATTACK BLOCKED                                       │
    └─────────────────────────────────────────────────────────────────┘
    """)
    print("=" * 70)


if __name__ == "__main__":
    main()