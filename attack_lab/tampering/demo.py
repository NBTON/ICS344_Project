"""
Ciphertext Tampering Demo Module

This module provides the demo function for ciphertext tampering demonstrations.
It integrates with the attack lab API endpoints.
"""

import os
import sys
import time
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_lab.tampering.attack import TamperingAttacker


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run ciphertext tampering demonstration with optional defense.
    
    Args:
        with_defense: If True, demonstrates defense mechanisms.
    
    Returns:
        dict: Complete demo results with steps, logs, and summary.
    """
    attacker = TamperingAttacker()
    
    if with_defense:
        return _run_defended_demo(attacker)
    else:
        return _run_vulnerable_demo(attacker)


def _run_vulnerable_demo(attacker: TamperingAttacker) -> Dict[str, Any]:
    """Run ciphertext tampering demo without defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup
    log("info", "Setting up AES encryption...")
    steps.append({
        "step": 1,
        "action": "Setup AES encryption",
        "result": "AES-256 key generated"
    })
    log("info", "Encryption system initialized")
    
    # Step 2: Create legitimate message
    log("info", "Creating encrypted message...")
    steps.append({
        "step": 2,
        "action": "Encrypt sensitive message",
        "result": "Message: 'Transfer $100 to Alice'"
    })
    log("info", "Original message encrypted successfully")
    
    # Step 3: Attacker intercepts message
    log("warn", "Eve intercepts encrypted message...")
    steps.append({
        "step": 3,
        "action": "Eve intercepts ciphertext",
        "result": "Message captured for tampering"
    })
    log("warn", "Ciphertext captured by attacker")
    
    # Step 4: Tamper with ciphertext
    log("error", "Eve tampers with ciphertext bytes...")
    steps.append({
        "step": 4,
        "action": "Tamper with ciphertext (bit-flipping)",
        "result": "Modified bytes in encrypted message"
    })
    log("error", "Ciphertext bytes modified")
    
    # Step 5: Tamper with IV
    log("error", "Eve tampers with IV...")
    steps.append({
        "step": 5,
        "action": "Tamper with initialization vector",
        "result": "IV bytes modified"
    })
    log("error", "IV modified")
    
    # Step 6: Vulnerable system accepts tampered message
    log("error", "Vulnerable system processes tampered message...")
    steps.append({
        "step": 6,
        "action": "Vulnerable system decrypts tampered message",
        "result": "ATTACK SUCCESS: Corrupted plaintext accepted!"
    })
    log("error", "Tampered message accepted by vulnerable system")
    
    # Step 7: Show potential damage
    log("error", "Demonstrating potential damage...")
    steps.append({
        "step": 7,
        "action": "Show corrupted plaintext",
        "result": "Original: '$100' -> Corrupted: '$900' (example)"
    })
    log("error", "Plaintext corruption demonstrated")
    
    return {
        "attack_type": "tampering",
        "with_defense": False,
        "steps": steps,
        "logs": logs,
        "attack_success": True,
        "summary": (
            "Ciphertext tampering attack successful! The attacker modified "
            "encrypted data in transit. Without authenticated encryption, "
            "the system accepted the corrupted data, potentially causing "
            "unpredictable changes to the decrypted plaintext. This could "
            "be exploited to alter financial amounts, commands, or other "
            "sensitive data."
        ),
        "tampering_log": attacker.get_tampering_log(),
        "original_plaintext": "Transfer $100 to Alice",
        "modifications_made": 2,
        "potential_damage": "Altered financial amounts, corrupted commands, data integrity loss"
    }


def _run_defended_demo(attacker: TamperingAttacker) -> Dict[str, Any]:
    """Run ciphertext tampering demo with defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup with authenticated encryption
    log("info", "Setting up AES-GCM authenticated encryption...")
    steps.append({
        "step": 1,
        "action": "Setup AES-GCM with authentication",
        "result": "AES-256-GCM with authentication tag"
    })
    log("info", "Authenticated encryption enabled")
    
    # Step 2: Create legitimate message with authentication
    log("info", "Creating encrypted message with authentication tag...")
    steps.append({
        "step": 2,
        "action": "Encrypt message with authentication",
        "result": "Message: 'Transfer $100 to Alice' + auth tag"
    })
    log("info", "Authenticated encryption applied")
    
    # Step 3: Attacker intercepts message
    log("warn", "Eve intercepts authenticated message...")
    steps.append({
        "step": 3,
        "action": "Eve intercepts authenticated ciphertext",
        "result": "Message captured for tampering attempt"
    })
    log("warn", "Authenticated message captured")
    
    # Step 4: Attacker attempts to tamper
    log("error", "Eve attempts to tamper with ciphertext...")
    steps.append({
        "step": 4,
        "action": "Eve attempts ciphertext tampering",
        "result": "Bytes modified in encrypted message"
    })
    log("error", "Ciphertext tampering attempted")
    
    # Step 5: Attacker tampers with authentication tag
    log("error", "Eve attempts to tamper with authentication tag...")
    steps.append({
        "step": 5,
        "action": "Eve tampers with authentication tag",
        "result": "Authentication tag modified"
    })
    log("error", "Authentication tag tampered with")
    
    # Step 6: Defense detects tampering
    log("info", "Server detects tampering attempt!")
    steps.append({
        "step": 6,
        "action": "Server validates authentication tag",
        "result": "DEFENSE SUCCESS: Tampering detected and blocked!"
    })
    log("info", "Tampering detected by authentication tag verification")
    
    # Step 7: Multiple tampering attempts blocked
    log("info", "Additional tampering attempts blocked...")
    steps.append({
        "step": 7,
        "action": "Multiple tampering attempts blocked",
        "result": "All attempts rejected by authentication"
    })
    log("info", "All tampering attempts successfully blocked")
    
    return {
        "attack_type": "tampering",
        "with_defense": True,
        "steps": steps,
        "logs": logs,
        "attack_success": False,
        "summary": (
            "Ciphertext tampering attack blocked! The defended system uses "
            "AES-GCM authenticated encryption, which includes an authentication "
            "tag. When the attacker modified the ciphertext or authentication "
            "tag, the server detected the tampering during decryption and "
            "rejected the message. This prevents any corrupted data from being "
            "processed."
        ),
        "defense_mechanisms": [
            "AES-GCM authenticated encryption",
            "Authentication tag verification",
            "Cryptographic integrity checking"
        ],
        "tampering_attempts_blocked": 3,
        "damage_prevented": "Data corruption, financial fraud, command injection"
    }


if __name__ == "__main__":
    print("Ciphertext Tampering Demo Module")
    print("Use run_demo(with_defense=True/False) to run demonstrations")
