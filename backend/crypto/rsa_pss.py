"""
RSA-PSS Digital Signature Module

This module provides RSA-PSS signing and verification functions
for message authentication and integrity verification.

RSA-PSS (Probabilistic Signature Scheme) uses:
- SHA-256 for the hash function
- MGF1 with SHA-256 for the mask generation function
- Maximum salt length for security
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.
    
    This creates a digital signature that proves the message was created
    by the holder of the private key and has not been modified.
    
    Args:
        message: The message to sign.
        private_key: The signer's RSA private key.
    
    Returns:
        bytes: The digital signature (256 bytes for RSA-2048).
    
    Example:
        >>> from backend.crypto.rsa_keys import generate_key_pair
        >>> private_key, public_key = generate_key_pair()
        >>> message = b"Hello, World!"
        >>> signature = sign(message, private_key)
        >>> len(signature)
        256  # RSA-2048 produces 256-byte signatures
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify an RSA-PSS signature.
    
    This verifies that the signature was created by the holder of the
    corresponding private key and that the message has not been modified.
    
    Args:
        message: The original message that was signed.
        signature: The signature to verify.
        public_key: The signer's RSA public key.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    
    Example:
        >>> from backend.crypto.rsa_keys import generate_key_pair
        >>> private_key, public_key = generate_key_pair()
        >>> message = b"Hello, World!"
        >>> signature = sign(message, private_key)
        >>> verify(message, signature, public_key)
        True
        >>> verify(b"Modified message", signature, public_key)
        False
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_data_for_message(
    ciphertext: bytes,
    iv: bytes,
    timestamp: int,
    nonce: bytes,
    private_key: rsa.RSAPrivateKey
) -> bytes:
    """
    Create a signature for a SecureChat message.
    
    This combines all message components into a single blob and signs it,
    ensuring complete message integrity.
    
    Args:
        ciphertext: The encrypted message content.
        iv: The initialization vector used for encryption.
        timestamp: The message timestamp (milliseconds since epoch).
        nonce: The random nonce for replay protection.
        private_key: The sender's RSA private key.
    
    Returns:
        bytes: The digital signature.
    """
    # Combine all message components
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    data_to_sign = ciphertext + iv + timestamp_bytes + nonce
    
    return sign(data_to_sign, private_key)


def verify_message_signature(
    ciphertext: bytes,
    iv: bytes,
    timestamp: int,
    nonce: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify a signature for a SecureChat message.
    
    Args:
        ciphertext: The encrypted message content.
        iv: The initialization vector used for encryption.
        timestamp: The message timestamp (milliseconds since epoch).
        nonce: The random nonce for replay protection.
        signature: The signature to verify.
        public_key: The sender's RSA public key.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Combine all message components
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    data_to_verify = ciphertext + iv + timestamp_bytes + nonce
    
    return verify(data_to_verify, signature, public_key)


# Simple test when run directly
if __name__ == "__main__":
    import os
    import time
    from backend.crypto.rsa_keys import generate_key_pair
    
    print("Testing RSA-PSS implementation...")
    
    # Test 1: Basic signing/verification
    print("\n1. Testing basic signing/verification:")
    private_key, public_key = generate_key_pair()
    message = b"Hello, SecureChat! This is a test message."
    
    signature = sign(message, private_key)
    is_valid = verify(message, signature, public_key)
    
    assert is_valid, "Signature verification failed!"
    print(f"   Message: {message.decode()}")
    print(f"   Signature length: {len(signature)} bytes")
    print("   ✓ Signature verified successfully!")
    
    # Test 2: Modified message detection
    print("\n2. Testing modified message detection:")
    modified_message = b"Hello, SecureChat! This is a modified message."
    is_valid_modified = verify(modified_message, signature, public_key)
    
    assert not is_valid_modified, "Should have rejected modified message!"
    print("   ✓ Modified message correctly rejected!")
    
    # Test 3: Wrong key detection
    print("\n3. Testing wrong key detection:")
    wrong_private, wrong_public = generate_key_pair()
    is_valid_wrong_key = verify(message, signature, wrong_public)
    
    assert not is_valid_wrong_key, "Should have rejected wrong key!"
    print("   ✓ Wrong public key correctly rejected!")
    
    # Test 4: Corrupted signature detection
    print("\n4. Testing corrupted signature detection:")
    corrupted_sig = bytearray(signature)
    corrupted_sig[100] ^= 0xFF
    is_valid_corrupted = verify(message, bytes(corrupted_sig), public_key)
    
    assert not is_valid_corrupted, "Should have rejected corrupted signature!"
    print("   ✓ Corrupted signature correctly rejected!")
    
    # Test 5: Randomized signatures
    print("\n5. Testing randomized signatures (PSS property):")
    sig1 = sign(message, private_key)
    sig2 = sign(message, private_key)
    
    assert sig1 != sig2, "PSS signatures should be randomized!"
    assert verify(message, sig1, public_key)
    assert verify(message, sig2, public_key)
    print("   Signature 1: " + sig1.hex()[:32] + "...")
    print("   Signature 2: " + sig2.hex()[:32] + "...")
    print("   ✓ Both signatures valid but different (randomized)!")
    
    # Test 6: Empty message
    print("\n6. Testing empty message:")
    empty_sig = sign(b"", private_key)
    assert verify(b"", empty_sig, public_key)
    print("   ✓ Empty message signing works!")
    
    # Test 7: Large message
    print("\n7. Testing large message:")
    large_message = os.urandom(1024 * 1024)  # 1 MB
    large_sig = sign(large_message, private_key)
    assert verify(large_message, large_sig, public_key)
    print("   ✓ Large message (1 MB) signing works!")
    
    # Test 8: Message-specific signing
    print("\n8. Testing SecureChat message signing:")
    test_ciphertext = os.urandom(100)
    test_iv = os.urandom(12)
    test_timestamp = int(time.time() * 1000)
    test_nonce = os.urandom(16)
    
    msg_sig = sign_data_for_message(
        test_ciphertext, test_iv, test_timestamp, test_nonce, private_key
    )
    is_msg_valid = verify_message_signature(
        test_ciphertext, test_iv, test_timestamp, test_nonce, msg_sig, public_key
    )
    
    assert is_msg_valid, "Message signature verification failed!"
    print("   ✓ SecureChat message signing works!")
    
    # Test 9: Message tampering detection
    print("\n9. Testing message tampering detection:")
    # Tamper with ciphertext
    tampered_ct = bytearray(test_ciphertext)
    tampered_ct[0] ^= 0xFF
    is_tampered_valid = verify_message_signature(
        bytes(tampered_ct), test_iv, test_timestamp, test_nonce, msg_sig, public_key
    )
    assert not is_tampered_valid, "Should detect ciphertext tampering!"
    
    # Tamper with timestamp
    is_ts_tampered = verify_message_signature(
        test_ciphertext, test_iv, test_timestamp + 1, test_nonce, msg_sig, public_key
    )
    assert not is_ts_tampered, "Should detect timestamp tampering!"
    
    # Tamper with nonce
    tampered_nonce = bytearray(test_nonce)
    tampered_nonce[0] ^= 0xFF
    is_nonce_tampered = verify_message_signature(
        test_ciphertext, test_iv, test_timestamp, bytes(tampered_nonce), msg_sig, public_key
    )
    assert not is_nonce_tampered, "Should detect nonce tampering!"
    
    print("   ✓ All message tampering correctly detected!")
    
    print("\n" + "="*50)
    print("All RSA-PSS tests passed! ✓")
    print("="*50)