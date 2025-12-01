"""
SecureChat Backend Package

This package contains the Flask backend application for SecureChat,
including API routes, cryptographic modules, and security middleware.
"""

__version__ = '1.0.0'
__all__ = ['create_app', 'socketio']


def __getattr__(name):
    """Lazy import to avoid circular dependencies and allow submodule imports without Flask."""
    if name == "create_app":
        from backend.app import create_app
        return create_app
    elif name == "socketio":
        from backend.app import socketio
        return socketio
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")