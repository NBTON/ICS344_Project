"""
Ciphertext Tampering Attack Module

Demonstrates how attackers can attempt to modify encrypted data,
and how AES-GCM's authentication tag detects any tampering.
"""

# Lazy imports to avoid triggering Flask import chain

__all__ = [
    "TamperingAttacker",
    "TamperingDefense",
    "run_demo"
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "TamperingAttacker":
        from attack_lab.tampering.attack import TamperingAttacker
        return TamperingAttacker
    elif name == "TamperingDefense":
        from attack_lab.tampering.defense import TamperingDefense
        return TamperingDefense
    elif name == "run_demo":
        from attack_lab.tampering.demo import run_demo
        return run_demo
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")