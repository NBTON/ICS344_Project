"""
SecureChat Application Configuration

This module contains the main application configuration settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')
    
    # Server settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Cryptographic settings
    RSA_KEY_SIZE = int(os.environ.get('RSA_KEY_SIZE', 2048))
    AES_KEY_SIZE = int(os.environ.get('AES_KEY_SIZE', 256))  # bits
    IV_SIZE = 12  # bytes (96 bits for AES-GCM)
    AUTH_TAG_SIZE = 16  # bytes (128 bits)
    NONCE_SIZE = 16  # bytes (128 bits)
    
    # Session settings
    SESSION_KEY_TIMEOUT = int(os.environ.get('SESSION_KEY_TIMEOUT', 3600))  # 1 hour default
    
    # Rate limiting settings
    RATE_LIMIT_MESSAGES = int(os.environ.get('RATE_LIMIT_MESSAGES', 30))  # per minute
    RATE_LIMIT_KEY_EXCHANGE = int(os.environ.get('RATE_LIMIT_KEY_EXCHANGE', 5))  # per minute
    RATE_LIMIT_API_GENERAL = int(os.environ.get('RATE_LIMIT_API_GENERAL', 100))  # per minute
    
    # Replay protection settings
    TIMESTAMP_WINDOW = int(os.environ.get('TIMESTAMP_WINDOW', 300))  # 5 minutes in seconds
    NONCE_CACHE_SIZE = int(os.environ.get('NONCE_CACHE_SIZE', 10000))
    
    # WebSocket settings
    SOCKETIO_MESSAGE_QUEUE = os.environ.get('SOCKETIO_MESSAGE_QUEUE', None)


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get the current configuration based on environment."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])