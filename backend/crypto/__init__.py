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
    decrypt,
    encrypt_with_nonce,
    decrypt_with_nonce
)

from backend.crypto.rsa_keys import (
    generate_key_pair,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key,
    get_public_key_fingerprint
)

from backend.crypto.rsa_oaep import (
    encrypt_key,
    decrypt_key,
    get_max_session_key_size,
    encrypt_key_with_fingerprint,
    decrypt_key_with_fingerprint
)

from backend.crypto.rsa_pss import (
    sign,
    verify,
    sign_data_for_message,
    verify_message_signature,
    create_message_digest,
    sign_prehashed,
    verify_prehashed
)

__all__ = [
    # AES-GCM
    'generate_key',
    'encrypt',
    'decrypt',
    'encrypt_with_nonce',
    'decrypt_with_nonce',
    # RSA Keys
    'generate_key_pair',
    'serialize_public_key',
    'serialize_private_key',
    'load_public_key',
    'load_private_key',
    'get_public_key_fingerprint',
    # RSA-OAEP
    'encrypt_key',
    'decrypt_key',
    'get_max_session_key_size',
    'encrypt_key_with_fingerprint',
    'decrypt_key_with_fingerprint',
    # RSA-PSS
    'sign',
    'verify',
    'sign_data_for_message',
    'verify_message_signature',
    'create_message_digest',
    'sign_prehashed',
    'verify_prehashed'
]