"""
AES-256-GCM Encryption Module

This module provides AES-256-GCM encryption and decryption functions
for securing message content with authenticated encryption.

AES-GCM provides both confidentiality and integrity, using a 256-bit key,
12-byte (96-bit) IV, and produces a 16-byte (128-bit) authentication tag.
"""

import os
import struct
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Constants
KEY_SIZE = 32  # 256 bits
IV_SIZE = 12   # 96 bits (recommended for AES-GCM)
TAG_SIZE = 16  # 128 bits


def generate_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit AES key.
    
    Returns:
        bytes: A 32-byte (256-bit) random key.
    
    Example:
        >>> key = generate_key()
        >>> len(key)
        32
    """
    return os.urandom(KEY_SIZE)


def encrypt(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.
    
    Args:
        plaintext: The data to encrypt.
        key: A 256-bit (32-byte) AES key.
        associated_data: Optional associated data for authentication (not encrypted).
    
    Returns:
        tuple: A tuple containing (ciphertext, iv, tag):
            - ciphertext (bytes): The encrypted data.
            - iv (bytes): The 12-byte initialization vector used.
            - tag (bytes): The 16-byte authentication tag.
    
    Raises:
        ValueError: If the key is not 32 bytes.
    
    Example:
        >>> key = generate_key()
        >>> ciphertext, iv, tag = encrypt(b"Hello, World!", key)
        >>> len(iv)
        12
        >>> len(tag)
        16
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes (256 bits)")
    
    # Generate a random 12-byte IV
    iv = os.urandom(IV_SIZE)
    
    # Create AESGCM cipher and encrypt
    aesgcm = AESGCM(key)
    
    # encrypt() returns ciphertext with tag appended
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)
    
    # Separate ciphertext and tag
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]
    
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
    
    Example:
        >>> key = generate_key()
        >>> ciphertext, iv, tag = encrypt(b"Hello, World!", key)
        >>> plaintext = decrypt(ciphertext, key, iv, tag)
        >>> plaintext
        b'Hello, World!'
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes (256 bits)")
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes (96 bits)")
    if len(tag) != TAG_SIZE:
        raise ValueError(f"Tag must be {TAG_SIZE} bytes (128 bits)")
    
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Combine ciphertext and tag for decryption
    ciphertext_with_tag = ciphertext + tag
    
    # Decrypt and verify (raises InvalidTag if verification fails)
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)
    
    return plaintext


def encrypt_with_nonce(plaintext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM with a specific nonce.
    
    This is useful for deterministic encryption or when nonces are managed externally.
    
    Args:
        plaintext: The data to encrypt.
        key: A 256-bit (32-byte) AES key.
        nonce: A 12-byte nonce (must be unique per key).
        associated_data: Optional associated data for authentication.
    
    Returns:
        tuple: A tuple containing (ciphertext, tag).
    
    Raises:
        ValueError: If key or nonce have incorrect sizes.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes (256 bits)")
    if len(nonce) != IV_SIZE:
        raise ValueError(f"Nonce must be {IV_SIZE} bytes (96 bits)")
    
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]
    
    return ciphertext, tag


def decrypt_with_nonce(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM with a specific nonce.
    
    Args:
        ciphertext: The encrypted data.
        key: A 256-bit (32-byte) AES key.
        nonce: The 12-byte nonce used during encryption.
        tag: The 16-byte authentication tag.
        associated_data: Optional associated data that was authenticated.
    
    Returns:
        bytes: The decrypted plaintext.
    
    Raises:
        ValueError: If key, nonce, or tag have incorrect sizes.
        InvalidTag: If authentication fails.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes (256 bits)")
    if len(nonce) != IV_SIZE:
        raise ValueError(f"Nonce must be {IV_SIZE} bytes (96 bits)")
    if len(tag) != TAG_SIZE:
        raise ValueError(f"Tag must be {TAG_SIZE} bytes (128 bits)")
    
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    
    return plaintext


# Simple test when run directly
if __name__ == "__main__":
    print("Testing AES-256-GCM implementation...")
    
    # Test 1: Basic encryption/decryption
    print("\n1. Testing basic encryption/decryption:")
    test_key = generate_key()
    test_plaintext = b"Hello, SecureChat! This is a test message."
    
    ct, test_iv, test_tag = encrypt(test_plaintext, test_key)
    decrypted = decrypt(ct, test_key, test_iv, test_tag)
    
    assert decrypted == test_plaintext, "Decryption failed!"
    print(f"   Original:  {test_plaintext}")
    print(f"   Decrypted: {decrypted}")
    print("   ✓ Basic encryption/decryption works!")
    
    # Test 2: Key size validation
    print("\n2. Testing key size validation:")
    try:
        encrypt(b"test", b"short_key")
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected short key: {e}")
    
    # Test 3: Tampering detection
    print("\n3. Testing tampering detection:")
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF  # Flip bits in first byte
    
    try:
        decrypt(bytes(tampered_ct), test_key, test_iv, test_tag)
        print("   ✗ Should have raised InvalidTag")
    except InvalidTag:
        print("   ✓ Correctly detected tampered ciphertext!")
    
    # Test 4: IV uniqueness
    print("\n4. Testing IV uniqueness:")
    _, iv1, _ = encrypt(test_plaintext, test_key)
    _, iv2, _ = encrypt(test_plaintext, test_key)
    
    assert iv1 != iv2, "IVs should be unique!"
    print(f"   IV1: {iv1.hex()}")
    print(f"   IV2: {iv2.hex()}")
    print("   ✓ IVs are unique for each encryption!")
    
    # Test 5: Empty plaintext
    print("\n5. Testing empty plaintext:")
    ct_empty, iv_empty, tag_empty = encrypt(b"", test_key)
    decrypted_empty = decrypt(ct_empty, test_key, iv_empty, tag_empty)
    assert decrypted_empty == b"", "Empty plaintext handling failed!"
    print("   ✓ Empty plaintext handled correctly!")
    
    # Test 6: Associated data
    print("\n6. Testing associated data:")
    associated = b"authenticated but not encrypted"
    ct_assoc, iv_assoc, tag_assoc = encrypt(test_plaintext, test_key, associated)
    decrypted_assoc = decrypt(ct_assoc, test_key, iv_assoc, tag_assoc, associated)
    assert decrypted_assoc == test_plaintext, "Decryption with associated data failed!"
    
    # Test tampering of associated data
    try:
        wrong_associated = b"wrong associated data"
        decrypt(ct_assoc, test_key, iv_assoc, tag_assoc, wrong_associated)
        print("   ✗ Should have detected wrong associated data")
    except InvalidTag:
        print("   ✓ Correctly detected tampered associated data!")
    
    # Test 7: Nonce-based encryption
    print("\n7. Testing nonce-based encryption:")
    test_nonce = os.urandom(IV_SIZE)
    ct_nonce, tag_nonce = encrypt_with_nonce(test_plaintext, test_key, test_nonce)
    decrypted_nonce = decrypt_with_nonce(ct_nonce, test_key, test_nonce, tag_nonce)
    assert decrypted_nonce == test_plaintext, "Nonce-based decryption failed!"
    print("   ✓ Nonce-based encryption works!")
    
    print("\n" + "="*50)
    print("All AES-256-GCM tests passed! ✓")
    print("="*50)