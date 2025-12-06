"""AES-GCM helpers for SecureChat.

Provides AES-256-GCM session key generation, encrypt/decrypt primitives
that operate on bytes and return/consume separate iv, ciphertext and tag.
Also includes small helpers to base64-encode/decode binary payloads for JSON transport.
"""
import os
import base64
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Constants
KEY_SIZE = 32  # AES-256
IV_SIZE = 12   # Recommended 96-bit IV for GCM
TAG_SIZE = 16  # 128-bit auth tag


def generate_session_key() -> bytes:
    """
    Generate a 32-byte (256-bit) AES session key.

    Returns:
        bytes: Random 32 bytes suitable for AES-256.
    """
    return os.urandom(KEY_SIZE)


# Backwards-compatible alias expected by tests
def generate_key() -> bytes:
    """
    Backward-compatible alias for generate_session_key.
    """
    return generate_session_key()


def encrypt(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None):
    """
    Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: The data to encrypt.
        key: A 256-bit (32-byte) AES key.
        associated_data: Optional associated data for authentication (not encrypted).

    Returns:
        tuple: (ciphertext, iv, tag) where tag is 16 bytes.

    Raises:
        ValueError: If the key is not 32 bytes.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")

    iv = os.urandom(IV_SIZE)
    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(iv, plaintext, associated_data)
    ciphertext = combined[:-TAG_SIZE]
    tag = combined[-TAG_SIZE:]
    return ciphertext, iv, tag


def decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.

    Args:
        ciphertext: The encrypted data.
        key: A 256-bit (32-byte) AES key.
        iv: The 12-byte initialization vector used during encryption.
        tag: The 16-byte authentication tag from encryption.
        associated_data: Optional associated data that was authenticated.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        ValueError: If key, IV, or tag have incorrect sizes.
        InvalidTag: If authentication fails (ciphertext was tampered with).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes")
    if len(tag) != TAG_SIZE:
        raise ValueError(f"Tag must be {TAG_SIZE} bytes")

    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)
    return plaintext


def encrypt_with_nonce(plaintext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None):
    """
    Encrypt plaintext using AES-256-GCM with a provided nonce.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES key.
        nonce: 12-byte nonce/IV.
        associated_data: Optional AAD.

    Returns:
        tuple: (ciphertext, tag)
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")
    if len(nonce) != IV_SIZE:
        raise ValueError(f"Nonce must be {IV_SIZE} bytes")

    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = combined[:-TAG_SIZE]
    tag = combined[-TAG_SIZE:]
    return ciphertext, tag


def decrypt_with_nonce(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM with a provided nonce.

    Args:
        ciphertext: Encrypted payload (without tag).
        key: 32-byte AES key.
        nonce: 12-byte nonce/IV.
        tag: 16-byte authentication tag.
        associated_data: Optional AAD.

    Returns:
        bytes: Decrypted plaintext.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")
    if len(nonce) != IV_SIZE:
        raise ValueError(f"Nonce must be {IV_SIZE} bytes")
    if len(tag) != TAG_SIZE:
        raise ValueError(f"Tag must be {TAG_SIZE} bytes")

    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(nonce, combined, associated_data)


# Small helpers for JSON transport
def b64_encode(b: bytes) -> str:
    """
    Base64-encode bytes to a UTF-8 string.

    Args:
        b: Bytes to encode.

    Returns:
        str: Base64 (URL-safe) encoded string.
    """
    return base64.b64encode(b).decode("utf-8")


def b64_decode(s: str) -> bytes:
    """
    Decode a base64 UTF-8 string to bytes.

    Args:
        s: Base64 encoded string.

    Returns:
        bytes: Decoded bytes.
    """
    return base64.b64decode(s.encode("utf-8"))