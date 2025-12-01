"""
SecureChat Attack Lab

This package provides interactive demonstrations of security attacks
and their corresponding defenses:

1. Replay Attack - Capturing and resending valid messages
2. Ciphertext Tampering - Modifying encrypted data
3. Man-in-the-Middle (MITM) - Intercepting key exchanges
4. Denial of Service (DoS) - Flooding with requests

Each attack module includes:
- attack.py: Attack implementation
- defense.py: Defense implementation  
- demo.py: Interactive demonstration

Usage:
    # Run individual demos
    python -m attack_lab.replay.demo
    python -m attack_lab.tampering.demo
    python -m attack_lab.mitm.demo
    python -m attack_lab.dos.demo
    
    # Or via API endpoints
    POST /api/attack-lab/replay
    POST /api/attack-lab/tampering
    POST /api/attack-lab/mitm
    POST /api/attack-lab/dos
"""

__version__ = "1.0.0"

# Attack types
ATTACK_TYPES = [
    "replay",
    "tampering", 
    "mitm",
    "dos"
]

__all__ = [
    "ATTACK_TYPES",
    "__version__"
]