"""
Cryptographic Module Tests

Tests for all cryptographic modules:
- AES-256-GCM encryption/decryption
- RSA key generation and serialization
- RSA-OAEP encrypt/decrypt
- RSA-PSS sign/verify
"""

import os
import pytest
from cryptography.exceptions import InvalidTag

from backend.crypto import aes_gcm, rsa_keys, rsa_oaep, rsa_pss


class TestAESGCM:
    """Tests for AES-256-GCM encryption module."""

    def test_generate_key_returns_32_bytes(self):
        """Test that generated key is 32 bytes (256 bits)."""
        key = aes_gcm.generate_key()
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_key_is_random(self):
        """Test that each generated key is unique."""
        keys = [aes_gcm.generate_key() for _ in range(10)]
        # All keys should be unique
        assert len(set(keys)) == 10

    def test_encrypt_decrypt_basic(self, sample_aes_key, sample_plaintext):
        """Test basic encryption and decryption."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        decrypted = aes_gcm.decrypt(ciphertext, sample_aes_key, iv, tag)
        assert decrypted == sample_plaintext

    def test_encrypt_produces_correct_components(self, sample_aes_key):
        """Test that encryption produces correct component sizes."""
        plaintext = b"Test message"
        ciphertext, iv, tag = aes_gcm.encrypt(plaintext, sample_aes_key)
        
        assert len(iv) == 12  # 96 bits
        assert len(tag) == 16  # 128 bits
        assert isinstance(ciphertext, bytes)

    def test_encrypt_iv_is_unique(self, sample_aes_key):
        """Test that each encryption uses a unique IV."""
        plaintext = b"Same message"
        results = [aes_gcm.encrypt(plaintext, sample_aes_key) for _ in range(5)]
        ivs = [r[1] for r in results]
        # All IVs should be unique
        assert len(set(ivs)) == 5

    def test_encrypt_ciphertext_is_randomized(self, sample_aes_key):
        """Test that same plaintext produces different ciphertext."""
        plaintext = b"Same message"
        results = [aes_gcm.encrypt(plaintext, sample_aes_key) for _ in range(5)]
        ciphertexts = [r[0] for r in results]
        # All ciphertexts should be unique due to random IV
        assert len(set(ciphertexts)) == 5

    def test_encrypt_empty_plaintext(self, sample_aes_key):
        """Test encryption of empty plaintext."""
        ciphertext, iv, tag = aes_gcm.encrypt(b"", sample_aes_key)
        decrypted = aes_gcm.decrypt(ciphertext, sample_aes_key, iv, tag)
        assert decrypted == b""

    def test_encrypt_large_plaintext(self, sample_aes_key):
        """Test encryption of large plaintext (1 MB)."""
        large_plaintext = os.urandom(1024 * 1024)
        ciphertext, iv, tag = aes_gcm.encrypt(large_plaintext, sample_aes_key)
        decrypted = aes_gcm.decrypt(ciphertext, sample_aes_key, iv, tag)
        assert decrypted == large_plaintext

    def test_decrypt_invalid_key_size(self, sample_aes_key, sample_plaintext):
        """Test decryption with invalid key size."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            aes_gcm.decrypt(ciphertext, b"short_key", iv, tag)

    def test_decrypt_invalid_iv_size(self, sample_aes_key, sample_plaintext):
        """Test decryption with invalid IV size."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        
        with pytest.raises(ValueError, match="IV must be 12 bytes"):
            aes_gcm.decrypt(ciphertext, sample_aes_key, b"short", tag)

    def test_decrypt_invalid_tag_size(self, sample_aes_key, sample_plaintext):
        """Test decryption with invalid tag size."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        
        with pytest.raises(ValueError, match="Tag must be 16 bytes"):
            aes_gcm.decrypt(ciphertext, sample_aes_key, iv, b"short")

    def test_decrypt_tampered_ciphertext(self, sample_aes_key, sample_plaintext):
        """Test that tampered ciphertext is detected."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        
        with pytest.raises(InvalidTag):
            aes_gcm.decrypt(bytes(tampered), sample_aes_key, iv, tag)

    def test_decrypt_tampered_tag(self, sample_aes_key, sample_plaintext):
        """Test that tampered tag is detected."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        
        # Tamper with tag
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0xFF
        
        with pytest.raises(InvalidTag):
            aes_gcm.decrypt(ciphertext, sample_aes_key, iv, bytes(tampered_tag))

    def test_decrypt_wrong_key(self, sample_aes_key, sample_plaintext):
        """Test decryption with wrong key fails."""
        ciphertext, iv, tag = aes_gcm.encrypt(sample_plaintext, sample_aes_key)
        wrong_key = aes_gcm.generate_key()
        
        with pytest.raises(InvalidTag):
            aes_gcm.decrypt(ciphertext, wrong_key, iv, tag)

    def test_encrypt_invalid_key_size(self, sample_plaintext):
        """Test encryption with invalid key size."""
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            aes_gcm.encrypt(sample_plaintext, b"short_key")


class TestRSAKeys:
    """Tests for RSA key management module."""

    def test_generate_key_pair_default_size(self):
        """Test key pair generation with default size (2048 bits)."""
        private_key, public_key = rsa_keys.generate_key_pair()
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048

    def test_generate_key_pair_custom_size(self):
        """Test key pair generation with custom size."""
        private_key, public_key = rsa_keys.generate_key_pair(4096)
        assert private_key.key_size == 4096

    def test_generate_key_pair_minimum_size(self):
        """Test that key size less than 2048 is rejected."""
        with pytest.raises(ValueError, match="at least 2048"):
            rsa_keys.generate_key_pair(1024)

    def test_serialize_public_key(self, sample_public_key):
        """Test public key serialization to PEM."""
        pem = rsa_keys.serialize_public_key(sample_public_key)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert pem.endswith(b"-----END PUBLIC KEY-----\n")

    def test_serialize_private_key_unencrypted(self, sample_private_key):
        """Test private key serialization without password."""
        pem = rsa_keys.serialize_private_key(sample_private_key)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_serialize_private_key_encrypted(self, sample_private_key):
        """Test private key serialization with password."""
        password = b"test_password_123"
        pem = rsa_keys.serialize_private_key(sample_private_key, password)
        assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    def test_load_public_key(self, sample_public_key):
        """Test loading public key from PEM."""
        pem = rsa_keys.serialize_public_key(sample_public_key)
        loaded = rsa_keys.load_public_key(pem)
        assert loaded.key_size == sample_public_key.key_size

    def test_load_private_key_unencrypted(self, sample_private_key):
        """Test loading unencrypted private key from PEM."""
        pem = rsa_keys.serialize_private_key(sample_private_key)
        loaded = rsa_keys.load_private_key(pem)
        assert loaded.key_size == sample_private_key.key_size

    def test_load_private_key_encrypted(self, sample_private_key):
        """Test loading encrypted private key from PEM."""
        password = b"test_password_123"
        pem = rsa_keys.serialize_private_key(sample_private_key, password)
        loaded = rsa_keys.load_private_key(pem, password)
        assert loaded.key_size == sample_private_key.key_size

    def test_load_private_key_wrong_password(self, sample_private_key):
        """Test loading encrypted private key with wrong password."""
        password = b"correct_password"
        pem = rsa_keys.serialize_private_key(sample_private_key, password)
        
        with pytest.raises(ValueError, match="Failed to load private key"):
            rsa_keys.load_private_key(pem, b"wrong_password")

    def test_load_public_key_invalid_pem(self):
        """Test loading invalid PEM data."""
        with pytest.raises(ValueError, match="Failed to load public key"):
            rsa_keys.load_public_key(b"invalid pem data")

    def test_get_public_key_fingerprint(self, sample_public_key):
        """Test public key fingerprint generation."""
        fingerprint = rsa_keys.get_public_key_fingerprint(sample_public_key)
        assert len(fingerprint) == 32  # SHA-256 produces 32 bytes
        assert isinstance(fingerprint, bytes)

    def test_fingerprint_is_deterministic(self, sample_public_key):
        """Test that fingerprint is deterministic for same key."""
        fp1 = rsa_keys.get_public_key_fingerprint(sample_public_key)
        fp2 = rsa_keys.get_public_key_fingerprint(sample_public_key)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self):
        """Test that different keys have different fingerprints."""
        _, pub1 = rsa_keys.generate_key_pair()
        _, pub2 = rsa_keys.generate_key_pair()
        
        fp1 = rsa_keys.get_public_key_fingerprint(pub1)
        fp2 = rsa_keys.get_public_key_fingerprint(pub2)
        
        assert fp1 != fp2


class TestRSAOAEP:
    """Tests for RSA-OAEP key encryption module."""

    def test_encrypt_decrypt_session_key(self, sample_keys, sample_aes_key):
        """Test basic session key encryption and decryption."""
        private_key, public_key = sample_keys
        
        encrypted = rsa_oaep.encrypt_key(sample_aes_key, public_key)
        decrypted = rsa_oaep.decrypt_key(encrypted, private_key)
        
        assert decrypted == sample_aes_key

    def test_encrypted_key_size(self, sample_public_key, sample_aes_key):
        """Test that encrypted key has correct size (256 bytes for RSA-2048)."""
        encrypted = rsa_oaep.encrypt_key(sample_aes_key, sample_public_key)
        assert len(encrypted) == 256  # RSA-2048 produces 256-byte ciphertext

    def test_encryption_is_randomized(self, sample_public_key, sample_aes_key):
        """Test that same key encrypts to different ciphertext (IND-CPA)."""
        enc1 = rsa_oaep.encrypt_key(sample_aes_key, sample_public_key)
        enc2 = rsa_oaep.encrypt_key(sample_aes_key, sample_public_key)
        assert enc1 != enc2

    def test_decrypt_with_wrong_key(self, sample_aes_key):
        """Test decryption with wrong private key fails."""
        _, pub1 = rsa_keys.generate_key_pair()
        priv2, _ = rsa_keys.generate_key_pair()
        
        encrypted = rsa_oaep.encrypt_key(sample_aes_key, pub1)
        
        with pytest.raises(ValueError, match="Failed to decrypt"):
            rsa_oaep.decrypt_key(encrypted, priv2)

    def test_decrypt_corrupted_ciphertext(self, sample_keys, sample_aes_key):
        """Test decryption of corrupted ciphertext fails."""
        private_key, public_key = sample_keys
        
        encrypted = rsa_oaep.encrypt_key(sample_aes_key, public_key)
        corrupted = bytearray(encrypted)
        corrupted[50] ^= 0xFF
        
        with pytest.raises(ValueError, match="Failed to decrypt"):
            rsa_oaep.decrypt_key(bytes(corrupted), private_key)

    def test_different_key_sizes(self, sample_keys):
        """Test encryption with different session key sizes."""
        private_key, public_key = sample_keys
        
        for key_size in [16, 24, 32]:  # 128, 192, 256 bit keys
            key = os.urandom(key_size)
            encrypted = rsa_oaep.encrypt_key(key, public_key)
            decrypted = rsa_oaep.decrypt_key(encrypted, private_key)
            assert decrypted == key

    def test_max_plaintext_size(self, sample_keys):
        """Test maximum plaintext size for RSA-2048 with SHA-256."""
        private_key, public_key = sample_keys
        
        # Max size for RSA-2048 with OAEP/SHA-256: 256 - 2*32 - 2 = 190 bytes
        max_size = 190
        large_data = os.urandom(max_size)
        
        encrypted = rsa_oaep.encrypt_key(large_data, public_key)
        decrypted = rsa_oaep.decrypt_key(encrypted, private_key)
        assert decrypted == large_data


class TestRSAPSS:
    """Tests for RSA-PSS digital signature module."""

    def test_sign_verify_basic(self, sample_keys):
        """Test basic signing and verification."""
        private_key, public_key = sample_keys
        message = b"Hello, World!"
        
        signature = rsa_pss.sign(message, private_key)
        is_valid = rsa_pss.verify(message, signature, public_key)
        
        assert is_valid is True

    def test_signature_size(self, sample_private_key):
        """Test that signature has correct size (256 bytes for RSA-2048)."""
        message = b"Test message"
        signature = rsa_pss.sign(message, sample_private_key)
        assert len(signature) == 256

    def test_verify_modified_message(self, sample_keys):
        """Test that modified message fails verification."""
        private_key, public_key = sample_keys
        message = b"Original message"
        modified = b"Modified message"
        
        signature = rsa_pss.sign(message, private_key)
        is_valid = rsa_pss.verify(modified, signature, public_key)
        
        assert is_valid is False

    def test_verify_wrong_public_key(self, sample_private_key):
        """Test verification with wrong public key fails."""
        _, wrong_public = rsa_keys.generate_key_pair()
        message = b"Test message"
        
        signature = rsa_pss.sign(message, sample_private_key)
        is_valid = rsa_pss.verify(message, signature, wrong_public)
        
        assert is_valid is False

    def test_verify_corrupted_signature(self, sample_keys):
        """Test verification with corrupted signature fails."""
        private_key, public_key = sample_keys
        message = b"Test message"
        
        signature = rsa_pss.sign(message, private_key)
        corrupted = bytearray(signature)
        corrupted[100] ^= 0xFF
        
        is_valid = rsa_pss.verify(message, bytes(corrupted), public_key)
        assert is_valid is False

    def test_signatures_are_randomized(self, sample_private_key):
        """Test that PSS signatures are randomized."""
        message = b"Same message"
        
        sig1 = rsa_pss.sign(message, sample_private_key)
        sig2 = rsa_pss.sign(message, sample_private_key)
        
        assert sig1 != sig2

    def test_sign_empty_message(self, sample_keys):
        """Test signing and verifying empty message."""
        private_key, public_key = sample_keys
        
        signature = rsa_pss.sign(b"", private_key)
        is_valid = rsa_pss.verify(b"", signature, public_key)
        
        assert is_valid is True

    def test_sign_large_message(self, sample_keys):
        """Test signing and verifying large message (1 MB)."""
        private_key, public_key = sample_keys
        large_message = os.urandom(1024 * 1024)
        
        signature = rsa_pss.sign(large_message, private_key)
        is_valid = rsa_pss.verify(large_message, signature, public_key)
        
        assert is_valid is True

    def test_sign_data_for_message(self, sample_private_key):
        """Test SecureChat message signing."""
        ciphertext = os.urandom(100)
        iv = os.urandom(12)
        timestamp = 1234567890000
        nonce = os.urandom(16)
        
        signature = rsa_pss.sign_data_for_message(
            ciphertext, iv, timestamp, nonce, sample_private_key
        )
        
        assert len(signature) == 256

    def test_verify_message_signature(self, sample_keys):
        """Test SecureChat message signature verification."""
        private_key, public_key = sample_keys
        ciphertext = os.urandom(100)
        iv = os.urandom(12)
        timestamp = 1234567890000
        nonce = os.urandom(16)
        
        signature = rsa_pss.sign_data_for_message(
            ciphertext, iv, timestamp, nonce, private_key
        )
        
        is_valid = rsa_pss.verify_message_signature(
            ciphertext, iv, timestamp, nonce, signature, public_key
        )
        
        assert is_valid is True

    def test_verify_message_signature_detects_tampering(self, sample_keys):
        """Test message signature detects tampering."""
        private_key, public_key = sample_keys
        ciphertext = os.urandom(100)
        iv = os.urandom(12)
        timestamp = 1234567890000
        nonce = os.urandom(16)
        
        signature = rsa_pss.sign_data_for_message(
            ciphertext, iv, timestamp, nonce, private_key
        )
        
        # Tamper with ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0xFF
        
        is_valid = rsa_pss.verify_message_signature(
            bytes(tampered_ct), iv, timestamp, nonce, signature, public_key
        )
        
        assert is_valid is False
        
        # Tamper with timestamp
        is_valid = rsa_pss.verify_message_signature(
            ciphertext, iv, timestamp + 1, nonce, signature, public_key
        )
        
        assert is_valid is False