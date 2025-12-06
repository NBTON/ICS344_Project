"""
RSA-OAEP Key Encryption Module

This module provides RSA-OAEP encryption and decryption functions
for wrapping and unwrapping session keys during key exchange.

RSA-OAEP (Optimal Asymmetric Encryption Padding) uses:
- SHA-256 for the hash function
- MGF1 with SHA-256 for the mask generation function
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm


def encrypt_key(session_key: bytes, public_key: rsa.RSAPublicKey, label: bytes = None) -> bytes:
    """
    Encrypt a session key using RSA-OAEP.
    
    This is used to securely transmit an AES session key to a recipient
    by encrypting it with their RSA public key.
    
    Args:
        session_key: The symmetric key to encrypt (typically 32 bytes for AES-256).
        public_key: The recipient's RSA public key.
        label: Optional label for OAEP padding (default: None).
    
    Returns:
        bytes: The encrypted session key.
    
    Raises:
        ValueError: If the session key is too large for the RSA key size.
    
    Example:
        >>> from backend.crypto.rsa_keys import generate_key_pair
        >>> from backend.crypto.aes_gcm import generate_key as generate_aes_key
        >>> private_key, public_key = generate_key_pair()
        >>> session_key = generate_aes_key()
        >>> encrypted_key = encrypt_key(session_key, public_key)
        >>> len(encrypted_key)
        256  # RSA-2048 produces 256-byte ciphertext
    """
    # Calculate maximum plaintext size for RSA-OAEP with SHA-256
    key_size_bytes = public_key.key_size // 8
    hash_size = 32  # SHA-256
    max_plaintext_size = key_size_bytes - 2 * hash_size - 2
    
    if len(session_key) > max_plaintext_size:
        raise ValueError(
            f"Session key too large ({len(session_key)} bytes). "
            f"Maximum size for {public_key.key_size}-bit RSA is {max_plaintext_size} bytes."
        )
    
    try:
        encrypted = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )
        return encrypted
    except Exception as e:
        raise ValueError(f"Failed to encrypt session key: {e}")


def decrypt_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey, label: bytes = None) -> bytes:
    """
    Decrypt a session key using RSA-OAEP.
    
    This is used to recover an AES session key that was encrypted
    with this user's RSA public key.
    
    Args:
        encrypted_key: The encrypted session key.
        private_key: The recipient's RSA private key.
        label: Optional label for OAEP padding (must match encryption).
    
    Returns:
        bytes: The decrypted session key.
    
    Raises:
        ValueError: If decryption fails (invalid ciphertext or wrong key).
    
    Example:
        >>> from backend.crypto.rsa_keys import generate_key_pair
        >>> from backend.crypto.aes_gcm import generate_key as generate_aes_key
        >>> private_key, public_key = generate_key_pair()
        >>> session_key = generate_aes_key()
        >>> encrypted_key = encrypt_key(session_key, public_key)
        >>> decrypted_key = decrypt_key(encrypted_key, private_key)
        >>> decrypted_key == session_key
        True
    """
    try:
        decrypted = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )
        return decrypted
    except InvalidKey as e:
        raise ValueError(f"Invalid key for decryption: {e}")
    except UnsupportedAlgorithm as e:
        raise ValueError(f"Unsupported algorithm: {e}")
    except Exception as e:
        raise ValueError(f"Failed to decrypt session key: {e}")


def get_max_session_key_size(public_key: rsa.RSAPublicKey) -> int:
    """
    Get the maximum size for a session key that can be encrypted with this public key.
    
    Args:
        public_key: The RSA public key.
    
    Returns:
        int: Maximum session key size in bytes.
    """
    key_size_bytes = public_key.key_size // 8
    hash_size = 32  # SHA-256
    return key_size_bytes - 2 * hash_size - 2


def encrypt_key_with_fingerprint(session_key: bytes, public_key: rsa.RSAPublicKey,
                                fingerprint: bytes = None) -> bytes:
    """
    Encrypt a session key using RSA-OAEP with optional fingerprint as label.
    
    This provides additional security by binding the encryption to a specific key.
    
    Args:
        session_key: The symmetric key to encrypt.
        public_key: The recipient's RSA public key.
        fingerprint: Optional fingerprint to use as OAEP label.
    
    Returns:
        bytes: The encrypted session key.
    """
    return encrypt_key(session_key, public_key, label=fingerprint)


def decrypt_key_with_fingerprint(encrypted_key: bytes, private_key: rsa.RSAPrivateKey,
                                fingerprint: bytes = None) -> bytes:
    """
    Decrypt a session key using RSA-OAEP with optional fingerprint as label.
    
    Args:
        encrypted_key: The encrypted session key.
        private_key: The recipient's RSA private key.
        fingerprint: Optional fingerprint that was used as OAEP label.
    
    Returns:
        bytes: The decrypted session key.
    """
    return decrypt_key(encrypted_key, private_key, label=fingerprint)


# Simple test when run directly
if __name__ == "__main__":
    import os
    from backend.crypto.rsa_keys import generate_key_pair
    
    print("Testing RSA-OAEP implementation...")
    
    # Test 1: Basic encryption/decryption
    print("\n1. Testing basic key encryption/decryption:")
    private_key, public_key = generate_key_pair()
    session_key = os.urandom(32)  # 256-bit AES key
    
    encrypted = encrypt_key(session_key, public_key)
    decrypted = decrypt_key(encrypted, private_key)
    
    assert decrypted == session_key, "Decryption failed!"
    print(f"   Original key:  {session_key.hex()[:32]}...")
    print(f"   Encrypted len: {len(encrypted)} bytes")
    print(f"   Decrypted key: {decrypted.hex()[:32]}...")
    print("   ✓ Basic encryption/decryption works!")
    
    # Test 2: Different session key sizes
    print("\n2. Testing different key sizes:")
    for key_size in [16, 24, 32]:  # 128, 192, 256 bit keys
        test_key = os.urandom(key_size)
        enc = encrypt_key(test_key, public_key)
        dec = decrypt_key(enc, private_key)
        assert dec == test_key
        print(f"   ✓ {key_size * 8}-bit key works!")
    
    # Test 3: Ciphertext size consistency
    print("\n3. Testing ciphertext size consistency:")
    sizes = []
    for _ in range(5):
        test_key = os.urandom(32)
        enc = encrypt_key(test_key, public_key)
        sizes.append(len(enc))
    assert all(s == sizes[0] for s in sizes), "Ciphertext sizes should be consistent"
    print(f"   All ciphertexts are {sizes[0]} bytes")
    print("   ✓ Ciphertext size is consistent!")
    
    # Test 4: Wrong key decryption
    print("\n4. Testing wrong key decryption:")
    wrong_private_key, _ = generate_key_pair()
    try:
        decrypt_key(encrypted, wrong_private_key)
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected wrong key: {str(e)[:40]}...")
    
    # Test 5: Corrupted ciphertext
    print("\n5. Testing corrupted ciphertext handling:")
    corrupted = bytearray(encrypted)
    corrupted[50] ^= 0xFF  # Flip some bits
    try:
        decrypt_key(bytes(corrupted), private_key)
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected corrupted ciphertext!")
    
    # Test 6: Randomized encryption (same plaintext, different ciphertext)
    print("\n6. Testing randomized encryption:")
    enc1 = encrypt_key(session_key, public_key)
    enc2 = encrypt_key(session_key, public_key)
    assert enc1 != enc2, "OAEP should produce different ciphertexts"
    print("   Ciphertext 1: " + enc1.hex()[:32] + "...")
    print("   Ciphertext 2: " + enc2.hex()[:32] + "...")
    print("   ✓ Encryption is randomized (IND-CPA secure)!")
    
    # Test 7: Maximum plaintext size
    print("\n7. Testing maximum plaintext size:")
    max_size = get_max_session_key_size(public_key)
    large_data = os.urandom(max_size)
    enc = encrypt_key(large_data, public_key)
    dec = decrypt_key(enc, private_key)
    assert dec == large_data
    print(f"   ✓ Maximum size ({max_size} bytes) works!")
    
    # Test too large
    try:
        too_large = os.urandom(max_size + 10)
        encrypt_key(too_large, public_key)
        print("   ✗ Should have raised ValueError for too large data")
    except ValueError:
        print(f"   ✓ Correctly rejected data larger than {max_size} bytes!")
    
    # Test 8: Label functionality
    print("\n8. Testing OAEP label functionality:")
    label = b"SecureChat Session Key"
    encrypted_with_label = encrypt_key(session_key, public_key, label)
    decrypted_with_label = decrypt_key(encrypted_with_label, private_key, label)
    assert decrypted_with_label == session_key
    
    # Wrong label should fail
    try:
        decrypt_key(encrypted_with_label, private_key, b"Wrong Label")
        print("   ✗ Should have failed with wrong label")
    except ValueError:
        print("   ✓ Correctly rejected wrong label!")
    
    print("\n" + "="*50)
    print("All RSA-OAEP tests passed! ✓")
    print("="*50)