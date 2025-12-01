"""
Backend-Specific Configuration

This module contains configuration settings specific to the backend application.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class BackendConfig:
    """Backend configuration class."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')
    TESTING = os.environ.get('TESTING', 'False').lower() in ('true', '1', 'yes')
    
    # Server settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Cryptographic settings
    RSA_KEY_SIZE = int(os.environ.get('RSA_KEY_SIZE', 2048))
    AES_KEY_SIZE = int(os.environ.get('AES_KEY_SIZE', 256))  # bits
    AES_KEY_SIZE_BYTES = AES_KEY_SIZE // 8  # 32 bytes for AES-256
    IV_SIZE = 12  # bytes (96 bits for AES-GCM)
    AUTH_TAG_SIZE = 16  # bytes (128 bits)
    NONCE_SIZE = 16  # bytes (128 bits for replay protection)
    
    # Message protocol settings
    PROTOCOL_VERSION = 0x01
    
    # Session settings
    SESSION_KEY_TIMEOUT = int(os.environ.get('SESSION_KEY_TIMEOUT', 3600))  # 1 hour default
    
    # Rate limiting settings (requests per minute)
    RATE_LIMIT_MESSAGES = int(os.environ.get('RATE_LIMIT_MESSAGES', 30))
    RATE_LIMIT_KEY_EXCHANGE = int(os.environ.get('RATE_LIMIT_KEY_EXCHANGE', 5))
    RATE_LIMIT_API_GENERAL = int(os.environ.get('RATE_LIMIT_API_GENERAL', 100))
    
    # Token bucket settings
    RATE_LIMIT_BURST_MULTIPLIER = float(os.environ.get('RATE_LIMIT_BURST_MULTIPLIER', 1.5))
    
    # Replay protection settings
    TIMESTAMP_WINDOW = int(os.environ.get('TIMESTAMP_WINDOW', 300))  # 5 minutes in seconds
    NONCE_CACHE_SIZE = int(os.environ.get('NONCE_CACHE_SIZE', 10000))
    NONCE_CACHE_TTL = int(os.environ.get('NONCE_CACHE_TTL', 600))  # 10 minutes
    
    # WebSocket settings
    SOCKETIO_MESSAGE_QUEUE = os.environ.get('SOCKETIO_MESSAGE_QUEUE', None)
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'eventlet')
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DevelopmentConfig(BackendConfig):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(BackendConfig):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = 'WARNING'


class TestingConfig(BackendConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    LOG_LEVEL = 'DEBUG'


# Configuration mapping
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(env_name: str = None) -> type:
    """
    Get configuration class by environment name.
    
    Args:
        env_name: Environment name ('development', 'production', 'testing').
                  If None, reads from FLASK_ENV environment variable.
    
    Returns:
        Configuration class for the specified environment.
    """
    if env_name is None:
        env_name = os.environ.get('FLASK_ENV', 'development')
    return config_by_name.get(env_name, config_by_name['default'])