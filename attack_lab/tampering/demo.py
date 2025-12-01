"""
Ciphertext Tampering Attack Interactive Demo

This module provides a complete interactive demonstration of:
1. How ciphertext tampering attacks work against unauthenticated encryption
2. How AES-GCM's authentication tag defends against tampering

Run this demo directly:
    python -m attack_lab.tampering.demo
"""

import os
import sys
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.crypto.aes_gcm import generate_key, encrypt, decrypt
from attack_lab.tampering.attack import TamperingAttacker
from attack_lab.tampering.defense import TamperingDefense


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run the ciphertext tampering attack demonstration.
    
    Args:
        with_defense: If True, use AES-GCM with tag verification.
    
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
    attacker = TamperingAttacker()
    defense = TamperingDefense() if with_defense else None
    
    log("info", f"Starting tampering attack demo (defense: {'enabled' if with_defense else 'disabled'})")
    
    # Step 1: Create encrypted message
    log("info", "Creating encrypted message with AES-256-GCM...")
    key = generate_key()
    original_plaintext = b"Transfer $100 to Account #12345"
    ciphertext, iv, tag = encrypt(original_plaintext, key)
    
    add_step(1, "Create encrypted message",
             f"Encrypted: '{original_plaintext.decode()}'")
    log("info", f"Original plaintext: {original_plaintext.decode()}")
    log("info", f"Ciphertext length: {len(ciphertext)} bytes")
    log("info", f"Authentication tag: {tag.hex()[:16]}...")
    
    # Step 2: Attacker intercepts the message
    log("warn", "Eve (attacker) intercepts the encrypted message...")
    add_step(2, "Eve intercepts message",
             "Captured ciphertext, IV, and authentication tag")
    
    # Step 3: Attacker tampers with ciphertext
    log("error", "Eve modifies the ciphertext (bit-flipping attack)...")
    
    # Tamper with specific bytes to try to change "$100" to "$900"
    # In practice, this requires knowing the plaintext position
    tampered_ciphertext = attacker.tamper_ciphertext(
        ciphertext, position=9, xor_value=0x08  # Try to change 1 to 9
    )
    
    add_step(3, "Eve tampers with ciphertext",
             "Modified byte at position 9 (attempting to change '$100' to '$900')")
    log("error", f"Original byte: 0x{ciphertext[9]:02x} -> Tampered: 0x{tampered_ciphertext[9]:02x}")
    
    attack_success = False
    decrypted_result = None
    
    if with_defense:
        # Step 4: Server verifies with AES-GCM
        log("info", "Server attempts to verify and decrypt message...")
        
        is_valid, plaintext, reason = defense.verify_and_decrypt(
            tampered_ciphertext, key, iv, tag
        )
        
        if is_valid:
            add_step(4, "Server verifies message",
                     f"UNEXPECTED: Verification passed - {reason}")
            attack_success = True
            decrypted_result = plaintext.decode() if plaintext else None
            log("error", "DEFENSE FAILED - this should not happen!")
        else:
            add_step(4, "Server verifies message",
                     f"VERIFICATION FAILED: {reason}")
            attack_success = False
            log("info", "Tampering detected - message rejected")
        
        # Step 5: Try additional tampering techniques
        log("warn", "Eve tries additional tampering techniques...")
        
        # Try tampering with IV
        tampered_iv = attacker.tamper_iv(iv, position=0)
        is_valid_iv, _, reason_iv = defense.verify_and_decrypt(
            ciphertext, key, tampered_iv, tag
        )
        
        add_step(5, "Try tampered IV",
                 f"{'PASS' if is_valid_iv else 'BLOCKED'}: {reason_iv}")
        
        # Try tampering with tag
        tampered_tag = attacker.tamper_auth_tag(tag, position=0)
        is_valid_tag, _, reason_tag = defense.verify_and_decrypt(
            ciphertext, key, iv, tampered_tag
        )
        
        add_step(6, "Try tampered authentication tag",
                 f"{'PASS' if is_valid_tag else 'BLOCKED'}: {reason_tag}")
        
        log("info", "All tampering attempts blocked by AES-GCM authentication")
        
    else:
        # Simulate vulnerable system (no authentication check)
        log("error", "Vulnerable server receives tampered message...")
        
        # In a truly vulnerable system using something like AES-CBC without MAC,
        # the decryption would "succeed" but produce corrupted plaintext
        
        add_step(4, "Vulnerable server decrypts message",
                 "No integrity check - decryption proceeds with corrupted data")
        
        # Simulate what the corrupted plaintext might look like
        # (In reality, this depends on the cipher mode)
        corrupted_plaintext = bytearray(original_plaintext)
        corrupted_plaintext[9] ^= 0x08  # Same modification
        decrypted_result = bytes(corrupted_plaintext).decode(errors='replace')
        
        add_step(5, "Decrypted (corrupted) result",
                 f"'{decrypted_result}' - potentially exploitable!")
        
        attack_success = True
        log("error", f"ATTACK SUCCESS: Server processed corrupted data!")
        log("error", f"Original: '{original_plaintext.decode()}'")
        log("error", f"Corrupted: '{decrypted_result}'")
    
    # Summary
    if with_defense:
        if attack_success:
            summary = (
                "DEFENSE FAILED: Despite using AES-GCM, the tampering attack "
                "succeeded. This indicates a critical bug in the implementation."
            )
        else:
            summary = (
                "DEFENSE SUCCESSFUL: AES-GCM authentication detected all tampering "
                "attempts! The ciphertext, IV, and authentication tag are all "
                "protected by the GCM authentication mechanism. Any modification "
                "causes tag verification to fail, preventing the attack."
            )
    else:
        summary = (
            "ATTACK SUCCESSFUL: Without authenticated encryption, the attacker "
            "was able to modify the ciphertext, potentially changing the "
            "transaction amount from $100 to $900 or causing other harmful "
            "modifications. This demonstrates why unauthenticated encryption "
            "(like raw AES-CBC) is dangerous."
        )
    
    return {
        "attack_type": "tampering",
        "with_defense": with_defense,
        "steps": steps,
        "logs": logs,
        "attack_success": attack_success,
        "summary": summary,
        "original_plaintext": original_plaintext.decode(),
        "decrypted_result": decrypted_result,
        "tampering_log": attacker.get_tampering_log(),
        "defense_status": "enabled" if with_defense else "disabled"
    }


def main():
    """Run the demo with both modes and display results."""
    print("=" * 70)
    print("               CIPHERTEXT TAMPERING ATTACK DEMONSTRATION")
    print("=" * 70)
    
    # Run without defense
    print("\n" + "-" * 70)
    print("SCENARIO 1: Vulnerable System (No Authentication)")
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
    
    print("\n--- Tampering Operations ---")
    for entry in result["tampering_log"]:
        print(f"  • {entry['type']}: pos {entry['position']}, "
              f"0x{entry['original']:02x} → 0x{entry['modified']:02x}")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'FAILED'}")
    print(f"\n{result['summary']}")
    
    # Run with defense
    print("\n" + "-" * 70)
    print("SCENARIO 2: Protected System (AES-GCM Authentication)")
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
    │           WITHOUT AUTHENTICATED ENCRYPTION (e.g., AES-CBC)      │
    ├─────────────────────────────────────────────────────────────────┤
    │  • Attacker can modify ciphertext bytes                         │
    │  • Bit-flipping attacks may change plaintext predictably        │
    │  • No integrity verification before decryption                  │
    │  • Server processes corrupted/malicious data                    │
    │  • Result: ATTACK SUCCEEDS                                      │
    └─────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────┐
    │            WITH AES-GCM (Authenticated Encryption)              │
    ├─────────────────────────────────────────────────────────────────┤
    │  • 128-bit authentication tag covers all data                   │
    │  • Tag verification before decryption                           │
    │  • ANY modification causes verification failure                 │
    │  • Tampered messages are rejected                               │
    │  • Result: ATTACK BLOCKED                                       │
    └─────────────────────────────────────────────────────────────────┘
    
    Key Insight: Always use Authenticated Encryption (AEAD) modes like
    AES-GCM, ChaCha20-Poly1305, or AES-CCM. Never use unauthenticated
    modes like raw AES-CBC or AES-CTR without a separate MAC.
    """)
    print("=" * 70)


if __name__ == "__main__":
    main()