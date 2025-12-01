"""
Man-in-the-Middle (MITM) Attack Module

Demonstrates how attackers can intercept key exchanges by substituting
their own keys, and how digital signatures defend against this attack.
"""

# Lazy imports to avoid triggering Flask import chain

__all__ = [
    "MITMAttacker",
    "MITMDefense",
    "run_demo"
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "MITMAttacker":
        from attack_lab.mitm.attack import MITMAttacker
        return MITMAttacker
    elif name == "MITMDefense":
        from attack_lab.mitm.defense import MITMDefense
        return MITMDefense
    elif name == "run_demo":
        from attack_lab.mitm.demo import run_demo
        return run_demo
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")