"""RSA-OAEP helpers for SecureChat.

Provides encrypt_key and decrypt_key using OAEP with SHA-256 and a few convenience helpers.
"""
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def encrypt_key(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt plaintext using RSA-OAEP with SHA-256.

    Args:
        plaintext: Bytes to encrypt (e.g., session key).
        public_key: RSA public key object.

    Returns:
        bytes: RSA-OAEP ciphertext.

    Raises:
        ValueError: On encryption failure.
    """
    try:
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        raise ValueError(f"Failed to encrypt key: {e}")


def decrypt_key(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt ciphertext using RSA-OAEP with SHA-256.

    Args:
        ciphertext: RSA-OAEP ciphertext bytes.
        private_key: RSA private key object.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        ValueError: On decryption failure.
    """
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except Exception as e:
        raise ValueError(f"Failed to decrypt: {e}")


def get_max_session_key_size(public_key: rsa.RSAPublicKey) -> int:
    """
    Calculate the maximum plaintext size (in bytes) that can be encrypted with
    RSA-OAEP (SHA-256) for the given public key.

    Formula:
        max_plaintext = k - 2*hLen - 2
    where k = key size in bytes, hLen = hash length (SHA-256 -> 32).

    Args:
        public_key: RSA public key object.

    Returns:
        int: Maximum number of plaintext bytes supported by OAEP/SHA-256.
    """
    key_size_bytes = public_key.key_size // 8
    hash_len = hashes.SHA256().digest_size
    return key_size_bytes - 2 * hash_len - 2


def encrypt_key_with_fingerprint(plaintext: bytes, public_key: rsa.RSAPublicKey, fingerprint: Optional[bytes] = None) -> bytes:
    """
    Convenience wrapper that encrypts plaintext and (optionally) associates it
    with a fingerprint. For compatibility with package imports; currently this
    behaves the same as encrypt_key.

    Args:
        plaintext: Bytes to encrypt.
        public_key: RSA public key to use.
        fingerprint: Optional fingerprint (unused in this simple wrapper).

    Returns:
        bytes: Ciphertext.
    """
    # In a fuller implementation, fingerprint could be embedded or used to select keys.
    return encrypt_key(plaintext, public_key)


def decrypt_key_with_fingerprint(ciphertext: bytes, private_key: rsa.RSAPrivateKey, fingerprint: Optional[bytes] = None) -> bytes:
    """
    Convenience wrapper that decrypts ciphertext. The fingerprint parameter is
    accepted for API symmetry but not used in this demo implementation.

    Args:
        ciphertext: Ciphertext to decrypt.
        private_key: RSA private key to use.
        fingerprint: Optional fingerprint (unused).

    Returns:
        bytes: Decrypted plaintext.
    """
    return decrypt_key(ciphertext, private_key)


# Backwards-compatible aliases
rsa_encrypt = encrypt_key
rsa_decrypt = decrypt_key