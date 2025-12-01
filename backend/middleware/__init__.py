"""
SecureChat Middleware Package

This package contains middleware components for SecureChat:
- Rate limiter for DoS protection
"""

from backend.middleware.rate_limiter import RateLimiter, get_rate_limiter

__all__ = ['RateLimiter', 'get_rate_limiter']