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
from cryptography.exceptions import InvalidKey


def encrypt_key(session_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a session key using RSA-OAEP.
    
    This is used to securely transmit an AES session key to a recipient
    by encrypting it with their RSA public key.
    
    Args:
        session_key: The symmetric key to encrypt (typically 32 bytes for AES-256).
        public_key: The recipient's RSA public key.
    
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
    # Maximum plaintext size for RSA-OAEP with SHA-256:
    # key_size_bytes - 2 * hash_size - 2 = 256 - 2*32 - 2 = 190 bytes
    # This is plenty for a 32-byte AES key
    
    try:
        encrypted = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    except Exception as e:
        raise ValueError(f"Failed to encrypt session key: {e}")


def decrypt_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt a session key using RSA-OAEP.
    
    This is used to recover an AES session key that was encrypted
    with this user's RSA public key.
    
    Args:
        encrypted_key: The encrypted session key.
        private_key: The recipient's RSA private key.
    
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
                label=None
            )
        )
        return decrypted
    except InvalidKey as e:
        raise ValueError(f"Invalid key for decryption: {e}")
    except Exception as e:
        raise ValueError(f"Failed to decrypt session key: {e}")


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
    
    # Test 7: Large data rejection
    print("\n7. Testing maximum plaintext size:")
    max_size = (2048 // 8) - 2 * 32 - 2  # 190 bytes for RSA-2048 with SHA-256
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
    
    print("\n" + "="*50)
    print("All RSA-OAEP tests passed! ✓")
    print("="*50)