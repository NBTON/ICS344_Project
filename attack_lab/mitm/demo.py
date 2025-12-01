"""
Man-in-the-Middle Attack Interactive Demo

This module provides a complete interactive demonstration of:
1. How MITM attacks work against unauthenticated key exchanges
2. How digital signatures defend against MITM attacks

Run this demo directly:
    python -m attack_lab.mitm.demo
"""

import os
import sys
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.rsa_keys import generate_key_pair, serialize_public_key, load_public_key
from backend.crypto.rsa_oaep import encrypt_key, decrypt_key
from backend.crypto.aes_gcm import generate_key as aes_generate_key, encrypt as aes_encrypt, decrypt as aes_decrypt
from attack_lab.mitm.attack import MITMAttacker
from attack_lab.mitm.defense import MITMDefense


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run the MITM attack demonstration.
    
    Args:
        with_defense: If True, enable signature verification.
    
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
    attacker = MITMAttacker()
    defense = MITMDefense() if with_defense else None
    
    log("info", f"Starting MITM attack demo (defense: {'enabled' if with_defense else 'disabled'})")
    
    # Step 1: Setup - Generate key pairs for Alice and Bob
    log("info", "Setting up Alice and Bob's key pairs...")
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    
    add_step(1, "Setup - Generate key pairs",
             "Alice and Bob each generate RSA-2048 key pairs")
    
    if with_defense:
        # Register trusted keys
        defense.register_trusted_key("alice", alice_public)
        defense.register_trusted_key("bob", bob_public)
        log("info", "Public keys registered in trusted key store")
    
    # Step 2: Alice initiates key exchange with Bob
    alice_pub_bytes = serialize_public_key(alice_public)
    
    if with_defense:
        # Create signed key exchange
        log("info", "Alice creates SIGNED key exchange message...")
        key_exchange = defense.create_signed_key_exchange(
            alice_pub_bytes,
            alice_private,
            "alice"
        )
        add_step(2, "Alice creates signed key exchange",
                 f"Public key + RSA-PSS signature")
    else:
        # Unsigned key exchange (vulnerable)
        log("info", "Alice sends UNSIGNED public key...")
        key_exchange = {
            "public_key": alice_pub_bytes.hex(),
            "sender_id": "alice"
        }
        add_step(2, "Alice sends unsigned public key",
                 "No signature - VULNERABLE to interception!")
    
    # Step 3: Eve attempts MITM attack
    log("warn", "Eve (attacker) positions herself between Alice and Bob...")
    
    attack_success = False
    intercepted_key = None
    
    if with_defense:
        # Eve tries to create a fake signed key exchange
        log("error", "Eve creates fake key exchange with her own keys...")
        eve_pub_bytes = serialize_public_key(attacker.attacker_public_key)
        
        # Eve signs with her own private key (not Alice's)
        fake_key_exchange = defense.create_signed_key_exchange(
            eve_pub_bytes,
            attacker.attacker_private_key,
            "alice"  # Eve claims to be Alice
        )
        
        add_step(3, "Eve creates fake signed key exchange",
                 "Signed with Eve's key, claiming to be Alice")
        
        # Bob verifies the signature
        log("info", "Bob verifies the key exchange signature...")
        is_valid, reason = defense.verify_key_exchange(
            fake_key_exchange,
            alice_public  # Bob uses Alice's trusted public key
        )
        
        if is_valid:
            # This shouldn't happen
            add_step(4, "Bob verifies signature",
                     f"UNEXPECTED: Verification passed - {reason}")
            attack_success = True
            log("error", "DEFENSE FAILED!")
        else:
            add_step(4, "Bob verifies signature",
                     f"VERIFICATION FAILED: {reason}")
            attack_success = False
            log("info", "MITM attack detected and blocked!")
        
        # For comparison, show legitimate exchange works
        log("info", "Testing legitimate key exchange for comparison...")
        is_valid_legit, reason_legit = defense.verify_key_exchange(
            key_exchange,  # Alice's legitimate exchange
            alice_public
        )
        
        add_step(5, "Verify legitimate key exchange",
                 f"{'PASS' if is_valid_legit else 'FAIL'}: {reason_legit}")
        
    else:
        # Vulnerable scenario - no signature verification
        log("error", "Eve intercepts Alice's public key transmission!")
        intercepted_key = attacker.intercept_public_key(alice_pub_bytes)
        
        add_step(3, "Eve intercepts key exchange",
                 "Replaces Alice's public key with Eve's key")
        
        # Bob receives Eve's key thinking it's Alice's
        log("error", "Bob receives Eve's public key, thinking it's Alice's!")
        eve_pub_key = load_public_key(intercepted_key)
        
        add_step(4, "Bob receives fake public key",
                 "Bob now has Eve's key, labeled as 'Alice'")
        
        # Bob generates and encrypts session key
        log("info", "Bob generates session key and encrypts for 'Alice'...")
        session_key = aes_generate_key()
        encrypted_session_key = encrypt_key(session_key, eve_pub_key)
        
        add_step(5, "Bob encrypts session key",
                 "Encrypted with Eve's public key (thinking it's Alice's)")
        
        # Eve intercepts the encrypted session key
        log("error", "Eve intercepts and decrypts the session key!")
        re_encrypted, stolen_key = attacker.intercept_encrypted_key(
            encrypted_session_key,
            None,
            alice_public
        )
        
        add_step(6, "Eve steals session key",
                 f"Session key: {stolen_key.hex()[:16]}... (STOLEN!)")
        
        attack_success = True
        
        # Demonstrate message interception
        log("error", "Eve can now read all encrypted messages!")
        plaintext = b"Secret: The launch code is DELTA-4477"
        ciphertext, iv, tag = aes_encrypt(plaintext, session_key)
        
        test_message = {
            "ciphertext": ciphertext.hex(),
            "iv": iv.hex(),
            "auth_tag": tag.hex()
        }
        
        intercepted_plaintext, _ = attacker.intercept_message(test_message, stolen_key)
        
        add_step(7, "Eve intercepts encrypted message",
                 f"Eve reads: '{intercepted_plaintext}'")
        
        log("error", f"CONFIDENTIALITY BREACH: '{intercepted_plaintext}'")
    
    # Summary
    if with_defense:
        if attack_success:
            summary = (
                "DEFENSE FAILED: Despite signature verification, the MITM attack "
                "succeeded. This indicates a bug in the implementation."
            )
        else:
            summary = (
                "DEFENSE SUCCESSFUL: The MITM attack was blocked! Eve tried to "
                "substitute her own public key for Alice's, but the signature "
                "verification failed because Eve doesn't have Alice's private key. "
                "Bob was able to detect the forgery and reject the fake key exchange."
            )
    else:
        summary = (
            "ATTACK SUCCESSFUL: Without signature verification, Eve was able to:\n"
            "• Intercept Alice's public key and replace it with her own\n"
            "• Receive the session key encrypted with her public key\n"
            "• Decrypt and read all messages between Alice and Bob\n"
            "This is a complete compromise of confidentiality!"
        )
    
    return {
        "attack_type": "mitm",
        "with_defense": with_defense,
        "steps": steps,
        "logs": logs,
        "attack_success": attack_success,
        "summary": summary,
        "attacker_actions": attacker.get_action_log() if not with_defense else [],
        "intercepted_messages": attacker.get_intercepted_messages() if not with_defense else [],
        "defense_status": "enabled" if with_defense else "disabled"
    }


def main():
    """Run the demo with both modes and display results."""
    print("=" * 70)
    print("               MAN-IN-THE-MIDDLE ATTACK DEMONSTRATION")
    print("=" * 70)
    
    # Run without defense
    print("\n" + "-" * 70)
    print("SCENARIO 1: Vulnerable System (No Signature Verification)")
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
    
    if result["attacker_actions"]:
        print("\n--- Attacker Actions ---")
        for action in result["attacker_actions"]:
            print(f"  • {action['action']}: {action['details'][:50]}...")
    
    if result["intercepted_messages"]:
        print("\n--- Intercepted Messages ---")
        for msg in result["intercepted_messages"]:
            print(f"  • '{msg['plaintext']}'")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'FAILED'}")
    print(f"\n{result['summary']}")
    
    # Run with defense
    print("\n" + "-" * 70)
    print("SCENARIO 2: Protected System (Digital Signature Verification)")
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
    │              WITHOUT SIGNATURE VERIFICATION                     │
    ├─────────────────────────────────────────────────────────────────┤
    │  • Attacker can intercept and replace public keys               │
    │  • No way to verify key authenticity                            │
    │  • Attacker obtains session keys                                │
    │  • All encrypted communications compromised                     │
    │  • Result: COMPLETE CONFIDENTIALITY BREACH                      │
    └─────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────┐
    │               WITH SIGNATURE VERIFICATION                       │
    ├─────────────────────────────────────────────────────────────────┤
    │  • All key exchanges signed with sender's private key           │
    │  • Recipient verifies signature with trusted public key         │
    │  • Attacker can't forge valid signatures                        │
    │  • Fake key exchanges are detected and rejected                 │
    │  • Result: MITM ATTACK BLOCKED                                  │
    └─────────────────────────────────────────────────────────────────┘
    
    Key Insight: Always authenticate public keys using digital signatures
    or a trusted certificate authority. Never accept raw public keys
    without verification of their authenticity.
    """)
    print("=" * 70)


if __name__ == "__main__":
    main()