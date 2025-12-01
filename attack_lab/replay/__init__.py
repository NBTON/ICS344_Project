"""
Replay Attack Module

Demonstrates how attackers can capture and resend valid encrypted messages,
and how timestamp + nonce validation defends against this attack.
"""

# Lazy imports to avoid triggering Flask import chain
# Import these from the submodules directly when needed:
#   from attack_lab.replay.attack import ReplayAttacker
#   from attack_lab.replay.defense import ReplayDefense
#   from attack_lab.replay.demo import run_demo

__all__ = [
    "ReplayAttacker",
    "ReplayDefense",
    "run_demo"
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "ReplayAttacker":
        from attack_lab.replay.attack import ReplayAttacker
        return ReplayAttacker
    elif name == "ReplayDefense":
        from attack_lab.replay.defense import ReplayDefense
        return ReplayDefense
    elif name == "run_demo":
        from attack_lab.replay.demo import run_demo
        return run_demo
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")