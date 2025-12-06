"""
MITM Attack Demo Module

This module provides the demo function for MITM attack demonstrations.
It integrates with the attack lab API endpoints.
"""

import os
import sys
import time
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_lab.mitm.attack import MITMAttacker


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run MITM attack demonstration with optional defense.
    
    Args:
        with_defense: If True, demonstrates defense mechanisms.
    
    Returns:
        dict: Complete demo results with steps, logs, and summary.
    """
    attacker = MITMAttacker()
    
    if with_defense:
        return _run_defended_demo(attacker)
    else:
        return _run_vulnerable_demo(attacker)


def _run_vulnerable_demo(attacker: MITMAttacker) -> Dict[str, Any]:
    """Run MITM attack demo without defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup
    log("info", "Setting up key exchange between Alice and Bob...")
    steps.append({
        "step": 1,
        "action": "Setup key exchange",
        "result": "Alice and Bob prepare to exchange keys"
    })
    log("info", "Key exchange protocol initialized")
    
    # Step 2: Alice sends public key to Bob
    log("info", "Alice sends her public key to Bob...")
    steps.append({
        "step": 2,
        "action": "Alice sends public key",
        "result": "Alice's public key in transit"
    })
    log("info", "Alice's public key being transmitted")
    
    # Step 3: Attacker intercepts Alice's key
    log("warn", "Eve intercepts Alice's public key...")
    steps.append({
        "step": 3,
        "action": "Eve intercepts Alice's key",
        "result": "Alice's key captured by Eve"
    })
    log("warn", "Alice's public key intercepted")
    
    # Step 4: Attacker replaces Alice's key with fake key
    log("error", "Eve replaces Alice's key with her own fake key...")
    steps.append({
        "step": 4,
        "action": "Eve sends fake key to Bob",
        "result": "Bob receives Eve's fake key"
    })
    log("error", "Bob receives Eve's fake public key")
    
    # Step 5: Bob sends public key to Alice
    log("info", "Bob sends his public key to Alice...")
    steps.append({
        "step": 5,
        "action": "Bob sends public key",
        "result": "Bob's public key in transit"
    })
    log("info", "Bob's public key being transmitted")
    
    # Step 6: Attacker intercepts Bob's key
    log("warn", "Eve intercepts Bob's public key...")
    steps.append({
        "step": 6,
        "action": "Eve intercepts Bob's key",
        "result": "Bob's key captured by Eve"
    })
    log("warn", "Bob's public key intercepted")
    
    # Step 7: Attacker replaces Bob's key with fake key
    log("error", "Eve replaces Bob's key with her own fake key...")
    steps.append({
        "step": 7,
        "action": "Eve sends fake key to Alice",
        "result": "Alice receives Eve's fake key"
    })
    log("error", "Alice receives Eve's fake public key")
    
    # Step 8: Both parties think they have each other's keys
    log("error", "Alice and Bob unknowingly use Eve's fake keys...")
    steps.append({
        "step": 8,
        "action": "Alice and Bob use fake keys",
        "result": "Eve can decrypt all communications"
    })
    log("error", "Eve now controls the communication channel")
    
    # Step 9: Attacker can read and modify all messages
    log("error", "Eve can now read and modify all messages...")
    steps.append({
        "step": 9,
        "action": "Eve intercepts all messages",
        "result": "ATTACK SUCCESS: Eve reads and modifies all traffic!"
    })
    log("error", "Complete MITM attack successful")
    
    return {
        "attack_type": "mitm",
        "with_defense": False,
        "steps": steps,
        "logs": logs,
        "attack_success": True,
        "summary": (
            "MITM attack successful! The attacker intercepted the key exchange "
            "between Alice and Bob, replacing their public keys with fake keys. "
            "Now both parties unknowingly encrypt messages with Eve's keys, "
            "allowing her to decrypt, read, and modify all communications. "
            "This is a classic 'evil twin' or 'man-in-the-middle' attack."
        ),
        "attack_details": {
            "alice_key_compromised": True,
            "bob_key_compromised": True,
            "eve_controls_communication": True
        },
        "damage": "Complete loss of confidentiality and integrity"
    }


def _run_defended_demo(attacker: MITMAttacker) -> Dict[str, Any]:
    """Run MITM attack demo with defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup with digital signatures
    log("info", "Setting up key exchange with digital signatures...")
    steps.append({
        "step": 1,
        "action": "Setup key exchange with signatures",
        "result": "RSA-PSS digital signatures enabled"
    })
    log("info", "Digital signature verification enabled")
    
    # Step 2: Alice sends signed public key to Bob
    log("info", "Alice sends her signed public key to Bob...")
    steps.append({
        "step": 2,
        "action": "Alice sends signed public key",
        "result": "Alice's key + signature in transit"
    })
    log("info", "Alice's signed public key being transmitted")
    
    # Step 3: Attacker intercepts Alice's key
    log("warn", "Eve intercepts Alice's signed public key...")
    steps.append({
        "step": 3,
        "action": "Eve intercepts Alice's signed key",
        "result": "Alice's key and signature captured"
    })
    log("warn", "Alice's signed public key intercepted")
    
    # Step 4: Attacker attempts to replace key
    log("error", "Eve attempts to replace Alice's key with fake key...")
    steps.append({
        "step": 4,
        "action": "Eve tries to substitute fake key",
        "result": "Eve cannot forge Alice's signature"
    })
    log("error", "Eve cannot create valid signature for fake key")
    
    # Step 5: Attacker forwards original key (no modification possible)
    log("info", "Eve forwards original key (cannot modify)...")
    steps.append({
        "step": 5,
        "action": "Eve forwards original signed key",
        "result": "Bob receives Alice's real key and signature"
    })
    log("info", "Original key forwarded without modification")
    
    # Step 6: Bob verifies Alice's signature
    log("info", "Bob verifies Alice's digital signature...")
    steps.append({
        "step": 6,
        "action": "Bob verifies signature",
        "result": "Signature valid - key is authentic"
    })
    log("info", "Alice's signature verified successfully")
    
    # Step 7: Bob sends signed public key to Alice
    log("info", "Bob sends his signed public key to Alice...")
    steps.append({
        "step": 7,
        "action": "Bob sends signed public key",
        "result": "Bob's key + signature in transit"
    })
    log("info", "Bob's signed public key being transmitted")
    
    # Step 8: Attacker intercepts Bob's key
    log("warn", "Eve intercepts Bob's signed public key...")
    steps.append({
        "step": 8,
        "action": "Eve intercepts Bob's signed key",
        "result": "Bob's key and signature captured"
    })
    log("warn", "Bob's signed public key intercepted")
    
    # Step 9: Attacker cannot modify without valid signature
    log("info", "Eve cannot modify Bob's key without valid signature...")
    steps.append({
        "step": 9,
        "action": "Eve cannot forge Bob's signature",
        "result": "Eve forwards original key unchanged"
    })
    log("info", "Eve cannot create valid signature for modified key")
    
    # Step 10: Alice verifies Bob's signature
    log("info", "Alice verifies Bob's digital signature...")
    steps.append({
        "step": 10,
        "action": "Alice verifies signature",
        "result": "DEFENSE SUCCESS: Signature valid - key is authentic"
    })
    log("info", "Bob's signature verified successfully")
    
    # Step 11: Secure communication established
    log("info", "Alice and Bob establish secure communication...")
    steps.append({
        "step": 11,
        "action": "Secure key exchange completed",
        "result": "Eve cannot intercept or modify communications"
    })
    log("info", "Secure communication channel established")
    
    return {
        "attack_type": "mitm",
        "with_defense": True,
        "steps": steps,
        "logs": logs,
        "attack_success": False,
        "summary": (
            "MITM attack blocked! The defended system uses RSA-PSS digital "
            "signatures to authenticate public keys during the key exchange. "
            "When the attacker attempted to substitute fake keys, she could "
            "not create valid signatures for them. The signature verification "
            "detected the tampering and rejected the fake keys, ensuring that "
            "Alice and Bob only accept authentic public keys."
        ),
        "defense_mechanisms": [
            "RSA-PSS digital signatures",
            "Public key authentication",
            "Signature verification during key exchange"
        ],
        "attack_attempts_blocked": 2,
        "damage_prevented": "Identity theft, communication interception, data theft"
    }


if __name__ == "__main__":
    print("MITM Attack Demo Module")
    print("Use run_demo(with_defense=True/False) to run demonstrations")
