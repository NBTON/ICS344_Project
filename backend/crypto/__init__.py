"""
SecureChat Cryptographic Modules

This package provides cryptographic primitives for SecureChat:
- AES-256-GCM for symmetric encryption
- RSA-OAEP for key wrapping
- RSA-PSS for digital signatures
- Key management utilities
"""

from backend.crypto.aes_gcm import (
    generate_key,
    encrypt,
    decrypt
)

from backend.crypto.rsa_keys import (
    generate_key_pair,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key
)

from backend.crypto.rsa_oaep import (
    encrypt_key,
    decrypt_key
)

from backend.crypto.rsa_pss import (
    sign,
    verify
)

__all__ = [
    # AES-GCM
    'generate_key',
    'encrypt',
    'decrypt',
    # RSA Keys
    'generate_key_pair',
    'serialize_public_key',
    'serialize_private_key',
    'load_public_key',
    'load_private_key',
    # RSA-OAEP
    'encrypt_key',
    'decrypt_key',
    # RSA-PSS
    'sign',
    'verify'
]