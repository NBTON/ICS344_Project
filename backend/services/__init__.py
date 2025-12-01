"""
SecureChat Services Package

This package contains business logic services for SecureChat:
- Key management service for handling user keys and sessions
"""

from backend.services.key_manager import KeyManager

__all__ = ['KeyManager']