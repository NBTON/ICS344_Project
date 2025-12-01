"""
Pytest Configuration and Fixtures

This module provides shared fixtures for all SecureChat tests.
"""

import os
import sys
import pytest

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.crypto import rsa_keys, aes_gcm
from backend.services.key_manager import KeyManager


@pytest.fixture
def app():
    """Create test application."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def sample_keys():
    """Generate sample RSA key pair."""
    return rsa_keys.generate_key_pair()


@pytest.fixture
def sample_private_key(sample_keys):
    """Get sample private key."""
    return sample_keys[0]


@pytest.fixture
def sample_public_key(sample_keys):
    """Get sample public key."""
    return sample_keys[1]


@pytest.fixture
def sample_aes_key():
    """Generate sample AES-256 key."""
    return aes_gcm.generate_key()


@pytest.fixture
def key_manager():
    """Create a fresh KeyManager instance for testing."""
    return KeyManager()


@pytest.fixture
def registered_users(key_manager):
    """Register test users and return their info."""
    alice = key_manager.register_user("alice")
    bob = key_manager.register_user("bob")
    return {
        "alice": alice,
        "bob": bob,
        "key_manager": key_manager
    }


@pytest.fixture
def sample_plaintext():
    """Sample plaintext message for testing."""
    return b"Hello, SecureChat! This is a test message."


@pytest.fixture
def sample_nonce():
    """Generate sample 16-byte nonce."""
    return os.urandom(16)


@pytest.fixture
def sample_sender_id():
    """Generate sample 32-byte sender ID."""
    return os.urandom(32)


@pytest.fixture
def sample_iv():
    """Generate sample 12-byte IV for AES-GCM."""
    return os.urandom(12)


@pytest.fixture
def sample_auth_tag():
    """Generate sample 16-byte auth tag."""
    return os.urandom(16)


@pytest.fixture
def sample_signature():
    """Generate sample 256-byte signature."""
    return os.urandom(256)


@pytest.fixture
def encrypted_message(sample_aes_key, sample_plaintext):
    """Create encrypted message data."""
    ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "tag": tag,
        "key": sample_aes_key,
        "plaintext": sample_plaintext
    }