"""
Denial of Service (DoS) Attack Module

Demonstrates how attackers can flood a server with requests to
exhaust resources, and how token bucket rate limiting defends
against this attack.
"""

# Lazy imports to avoid triggering Flask import chain

__all__ = [
    "DoSAttacker",
    "DoSDefense",
    "run_demo"
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "DoSAttacker":
        from attack_lab.dos.attack import DoSAttacker
        return DoSAttacker
    elif name == "DoSDefense":
        from attack_lab.dos.defense import DoSDefense
        return DoSDefense
    elif name == "run_demo":
        from attack_lab.dos.demo import run_demo
        return run_demo
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")