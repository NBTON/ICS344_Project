"""
SecureChat Models Package

This package contains data models for SecureChat:
- Message: Encrypted message format
"""

from backend.models.message import Message, MessageFlags

__all__ = ['Message', 'MessageFlags']