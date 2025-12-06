"""
RSA Key Management Module

This module provides functions for generating, serializing, and loading
RSA key pairs used for asymmetric encryption (RSA-OAEP) and digital
signatures (RSA-PSS).

Key size: 2048 bits (configurable)
Format: PEM
"""

from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


# Default key size
DEFAULT_KEY_SIZE = 2048

# Public exponent (standard value)
PUBLIC_EXPONENT = 65537


def generate_key_pair(key_size: int = DEFAULT_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA key pair.

    Args:
        key_size: The size of the key in bits. Defaults to 2048.
                  Must be at least 2048 for security.

    Returns:
        tuple: A tuple containing (private_key, public_key).

    Raises:
        ValueError: If key_size is less than 2048.
    """
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits for security")

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key


# Backwards-compatible alias
def generate_rsa_keypair(bits: int = DEFAULT_KEY_SIZE):
    """
    Backwards-compatible alias for generate_key_pair.
    """
    return generate_key_pair(bits)


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serialize an RSA public key to PEM format.
    
    Args:
        public_key: The RSA public key to serialize.
    
    Returns:
        bytes: The PEM-encoded public key.
    
    Example:
        >>> private_key, public_key = generate_key_pair()
        >>> pem = serialize_public_key(public_key)
        >>> pem.startswith(b'-----BEGIN PUBLIC KEY-----')
        True
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(private_key, password: Optional[bytes] = None) -> bytes:
    """
    Serialize a private key to PKCS#8 PEM. If password is provided the key is encrypted.

    Args:
        private_key: RSAPrivateKey object.
        password: Optional password bytes to encrypt PEM.

    Returns:
        bytes: PEM-encoded private key.
    """
    if password is not None:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from PEM data.
    
    Args:
        pem_data: The PEM-encoded public key.
    
    Returns:
        RSAPublicKey: The loaded public key.
    
    Raises:
        ValueError: If the PEM data is invalid.
    
    Example:
        >>> private_key, public_key = generate_key_pair()
        >>> pem = serialize_public_key(public_key)
        >>> loaded_key = load_public_key(pem)
        >>> loaded_key.key_size == public_key.key_size
        True
    """
    try:
        key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Loaded key is not an RSA public key")
        return key
    except Exception as e:
        raise ValueError(f"Failed to load public key: {e}")


def load_private_key(
    pem_data: bytes,
    password: Optional[bytes] = None
) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key from PEM data.
    
    Args:
        pem_data: The PEM-encoded private key.
        password: The password used to encrypt the key, or None if unencrypted.
    
    Returns:
        RSAPrivateKey: The loaded private key.
    
    Raises:
        ValueError: If the PEM data is invalid or password is incorrect.
    
    Example:
        >>> private_key, _ = generate_key_pair()
        >>> pem = serialize_private_key(private_key)
        >>> loaded_key = load_private_key(pem)
        >>> loaded_key.key_size == private_key.key_size
        True
    """
    try:
        key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Loaded key is not an RSA private key")
        return key
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")


def get_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Get the SHA-256 fingerprint of a public key.
    
    This can be used as a unique identifier for the key.
    
    Args:
        public_key: The RSA public key.
    
    Returns:
        bytes: The 32-byte SHA-256 hash of the public key.
    """
    import hashlib
    
    pem_data = serialize_public_key(public_key)
    return hashlib.sha256(pem_data).digest()


# Simple test when run directly
if __name__ == "__main__":
    print("Testing RSA Key Management implementation...")
    
    # Test 1: Key pair generation
    print("\n1. Testing key pair generation:")
    priv_key, pub_key = generate_key_pair()
    print(f"   Key size: {priv_key.key_size} bits")
    print("   ✓ Key pair generated successfully!")
    
    # Test 2: Public key serialization
    print("\n2. Testing public key serialization:")
    pub_pem = serialize_public_key(pub_key)
    print(f"   PEM length: {len(pub_pem)} bytes")
    newline = b'\n'
    print(f"   First line: {pub_pem.split(newline)[0].decode()}")
    print("   ✓ Public key serialized!")
    
    # Test 3: Private key serialization (unencrypted)
    print("\n3. Testing private key serialization (unencrypted):")
    priv_pem = serialize_private_key(priv_key)
    print(f"   PEM length: {len(priv_pem)} bytes")
    print(f"   First line: {priv_pem.split(newline)[0].decode()}")
    print("   ✓ Private key serialized!")
    
    # Test 4: Private key serialization (encrypted)
    print("\n4. Testing private key serialization (encrypted):")
    password = b"test_password_123"
    priv_pem_enc = serialize_private_key(priv_key, password)
    print(f"   PEM length: {len(priv_pem_enc)} bytes")
    print(f"   First line: {priv_pem_enc.split(newline)[0].decode()}")
    print("   ✓ Private key serialized with password!")
    
    # Test 5: Load public key
    print("\n5. Testing public key loading:")
    loaded_pub = load_public_key(pub_pem)
    assert loaded_pub.key_size == pub_key.key_size
    print(f"   Loaded key size: {loaded_pub.key_size} bits")
    print("   ✓ Public key loaded successfully!")
    
    # Test 6: Load private key (unencrypted)
    print("\n6. Testing private key loading (unencrypted):")
    loaded_priv = load_private_key(priv_pem)
    assert loaded_priv.key_size == priv_key.key_size
    print(f"   Loaded key size: {loaded_priv.key_size} bits")
    print("   ✓ Private key loaded successfully!")
    
    # Test 7: Load private key (encrypted)
    print("\n7. Testing private key loading (encrypted):")
    loaded_priv_enc = load_private_key(priv_pem_enc, password)
    assert loaded_priv_enc.key_size == priv_key.key_size
    print(f"   Loaded key size: {loaded_priv_enc.key_size} bits")
    print("   ✓ Encrypted private key loaded successfully!")
    
    # Test 8: Wrong password handling
    print("\n8. Testing wrong password handling:")
    try:
        load_private_key(priv_pem_enc, b"wrong_password")
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected wrong password: {str(e)[:50]}...")
    
    # Test 9: Key fingerprint
    print("\n9. Testing key fingerprint:")
    fingerprint = get_public_key_fingerprint(pub_key)
    print(f"   Fingerprint: {fingerprint.hex()}")
    print(f"   Fingerprint length: {len(fingerprint)} bytes")
    print("   ✓ Fingerprint generated!")
    
    # Test 10: Key size validation
    print("\n10. Testing key size validation:")
    try:
        generate_key_pair(1024)
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected small key size: {e}")
    
    print("\n" + "="*50)
    print("All RSA Key Management tests passed! ✓")
    print("="*50)