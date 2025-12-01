"""
Message Protocol Tests

Tests for the Message model:
- Message creation and validation
- Serialization (to_bytes, from_bytes)
- Dict conversion (to_dict, from_dict)
- Flag checking methods
- Timestamp validation
"""

import os
import time
import pytest

from backend.models.message import (
    Message, MessageFlags, PROTOCOL_VERSION,
    NONCE_SIZE, SENDER_ID_SIZE, IV_SIZE, AUTH_TAG_SIZE, SIGNATURE_SIZE, HEADER_SIZE
)


class TestMessageCreation:
    """Tests for Message creation and initialization."""

    def test_create_message_with_defaults(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test creating message with required fields."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.version == PROTOCOL_VERSION
        assert msg.flags == (MessageFlags.ENCRYPTED | MessageFlags.SIGNED)
        assert msg.ciphertext == b"test ciphertext"

    def test_create_message_with_custom_flags(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test creating message with custom flags."""
        msg = Message(
            flags=MessageFlags.ENCRYPTED | MessageFlags.KEY_EXCHANGE,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_encrypted()
        assert not msg.is_signed()
        assert msg.is_key_exchange()

    def test_create_message_with_custom_timestamp(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test creating message with custom timestamp."""
        custom_ts = 1234567890000
        msg = Message(
            timestamp=custom_ts,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.timestamp == custom_ts

    def test_create_message_with_recipient(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test creating message with recipient_id."""
        recipient = os.urandom(SENDER_ID_SIZE)
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature,
            recipient_id=recipient
        )
        
        assert msg.recipient_id == recipient


class TestMessageValidation:
    """Tests for Message validation."""

    def test_invalid_version(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that invalid version is rejected."""
        with pytest.raises(ValueError, match="version"):
            Message(
                version=256,  # Out of byte range
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature
            )

    def test_invalid_nonce_size(self, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that invalid nonce size is rejected."""
        with pytest.raises(ValueError, match="nonce"):
            Message(
                nonce=b"short",
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature
            )

    def test_invalid_sender_id_size(self, sample_nonce, sample_iv, sample_auth_tag, sample_signature):
        """Test that invalid sender_id size is rejected."""
        with pytest.raises(ValueError, match="sender_id"):
            Message(
                nonce=sample_nonce,
                sender_id=b"short",
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature
            )

    def test_invalid_iv_size(self, sample_nonce, sample_sender_id, sample_auth_tag, sample_signature):
        """Test that invalid IV size is rejected."""
        with pytest.raises(ValueError, match="iv"):
            Message(
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=b"short",
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature
            )

    def test_invalid_auth_tag_size(self, sample_nonce, sample_sender_id, sample_iv, sample_signature):
        """Test that invalid auth_tag size is rejected."""
        with pytest.raises(ValueError, match="auth_tag"):
            Message(
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=b"short",
                signature=sample_signature
            )

    def test_invalid_signature_size(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag):
        """Test that invalid signature size is rejected."""
        with pytest.raises(ValueError, match="signature"):
            Message(
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=b"short"
            )

    def test_invalid_recipient_id_size(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that invalid recipient_id size is rejected."""
        with pytest.raises(ValueError, match="recipient_id"):
            Message(
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature,
                recipient_id=b"short"
            )

    def test_negative_timestamp(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that negative timestamp is rejected."""
        with pytest.raises(ValueError, match="timestamp"):
            Message(
                timestamp=-1,
                nonce=sample_nonce,
                sender_id=sample_sender_id,
                iv=sample_iv,
                ciphertext=b"test",
                auth_tag=sample_auth_tag,
                signature=sample_signature
            )


class TestMessageSerialization:
    """Tests for Message byte serialization."""

    def test_to_bytes_from_bytes_roundtrip(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test serialization roundtrip."""
        original = Message(
            version=PROTOCOL_VERSION,
            flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED,
            timestamp=int(time.time() * 1000),
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext data",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        serialized = original.to_bytes()
        restored = Message.from_bytes(serialized)
        
        assert restored.version == original.version
        assert restored.flags == original.flags
        assert restored.timestamp == original.timestamp
        assert restored.nonce == original.nonce
        assert restored.sender_id == original.sender_id
        assert restored.iv == original.iv
        assert restored.ciphertext == original.ciphertext
        assert restored.auth_tag == original.auth_tag
        assert restored.signature == original.signature

    def test_from_bytes_too_short(self):
        """Test that too-short data raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            Message.from_bytes(b"short")

    def test_to_bytes_with_empty_ciphertext(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test serialization with empty ciphertext."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        serialized = msg.to_bytes()
        restored = Message.from_bytes(serialized)
        
        assert restored.ciphertext == b""

    def test_to_bytes_with_large_ciphertext(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test serialization with large ciphertext."""
        large_ct = os.urandom(10000)
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=large_ct,
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        serialized = msg.to_bytes()
        restored = Message.from_bytes(serialized)
        
        assert restored.ciphertext == large_ct

    def test_serialized_size_calculation(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that get_size matches actual serialized size."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.get_size() == len(msg.to_bytes())


class TestMessageDictConversion:
    """Tests for Message dict conversion."""

    def test_to_dict_from_dict_roundtrip(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test dict conversion roundtrip."""
        original = Message(
            version=PROTOCOL_VERSION,
            flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED,
            timestamp=int(time.time() * 1000),
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        as_dict = original.to_dict()
        restored = Message.from_dict(as_dict)
        
        assert restored.version == original.version
        assert restored.flags == original.flags
        assert restored.timestamp == original.timestamp
        assert restored.nonce == original.nonce
        assert restored.sender_id == original.sender_id
        assert restored.ciphertext == original.ciphertext

    def test_to_dict_hex_encoding(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that binary fields are hex-encoded in dict."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        as_dict = msg.to_dict()
        
        assert as_dict['nonce'] == sample_nonce.hex()
        assert as_dict['sender_id'] == sample_sender_id.hex()
        assert as_dict['iv'] == sample_iv.hex()
        assert as_dict['ciphertext'] == b"test".hex()
        assert as_dict['auth_tag'] == sample_auth_tag.hex()
        assert as_dict['signature'] == sample_signature.hex()

    def test_to_dict_with_recipient(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test dict conversion with recipient_id."""
        recipient = os.urandom(SENDER_ID_SIZE)
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature,
            recipient_id=recipient
        )
        
        as_dict = msg.to_dict()
        assert as_dict['recipient_id'] == recipient.hex()

    def test_to_dict_without_recipient(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test dict conversion without recipient_id."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        as_dict = msg.to_dict()
        assert as_dict['recipient_id'] is None

    def test_from_dict_missing_field(self):
        """Test that missing required field raises ValueError."""
        incomplete_dict = {
            'version': 1,
            'flags': 3,
            # Missing other required fields
        }
        
        with pytest.raises(ValueError, match="Missing required field"):
            Message.from_dict(incomplete_dict)


class TestMessageFlags:
    """Tests for Message flag checking methods."""

    def test_is_encrypted(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test is_encrypted flag check."""
        msg = Message(
            flags=MessageFlags.ENCRYPTED,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_encrypted() is True
        assert msg.is_signed() is False

    def test_is_signed(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test is_signed flag check."""
        msg = Message(
            flags=MessageFlags.SIGNED,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_signed() is True
        assert msg.is_encrypted() is False

    def test_is_compressed(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test is_compressed flag check."""
        msg = Message(
            flags=MessageFlags.COMPRESSED,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_compressed() is True

    def test_is_key_exchange(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test is_key_exchange flag check."""
        msg = Message(
            flags=MessageFlags.KEY_EXCHANGE,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_key_exchange() is True

    def test_combined_flags(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test message with multiple flags."""
        msg = Message(
            flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED | MessageFlags.COMPRESSED,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.is_encrypted()
        assert msg.is_signed()
        assert msg.is_compressed()
        assert not msg.is_key_exchange()


class TestMessageTimestamp:
    """Tests for Message timestamp validation."""

    def test_validate_timestamp_valid(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that current timestamp is valid."""
        msg = Message(
            timestamp=int(time.time() * 1000),
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.validate_timestamp(window_seconds=300) is True

    def test_validate_timestamp_too_old(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that old timestamp is rejected."""
        old_timestamp = int((time.time() - 600) * 1000)  # 10 minutes ago
        msg = Message(
            timestamp=old_timestamp,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.validate_timestamp(window_seconds=300) is False

    def test_validate_timestamp_within_window(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that timestamp within window is valid."""
        within_window = int((time.time() - 60) * 1000)  # 1 minute ago
        msg = Message(
            timestamp=within_window,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        assert msg.validate_timestamp(window_seconds=300) is True

    def test_validate_timestamp_custom_window(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test timestamp validation with custom window."""
        two_min_ago = int((time.time() - 120) * 1000)
        msg = Message(
            timestamp=two_min_ago,
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        # Should fail with 1 minute window
        assert msg.validate_timestamp(window_seconds=60) is False
        # Should pass with 5 minute window
        assert msg.validate_timestamp(window_seconds=300) is True


class TestMessageDataToSign:
    """Tests for Message.get_data_to_sign method."""

    def test_get_data_to_sign(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that get_data_to_sign returns correct data."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        data_to_sign = msg.get_data_to_sign()
        
        # Should include header + iv + ciphertext + auth_tag
        expected_size = HEADER_SIZE + IV_SIZE + len(msg.ciphertext) + AUTH_TAG_SIZE
        assert len(data_to_sign) == expected_size

    def test_get_data_to_sign_excludes_signature(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test that signature is not included in data to sign."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        data_to_sign = msg.get_data_to_sign()
        
        # Signature should NOT be in the data to sign
        assert sample_signature not in data_to_sign


class TestMessageRepr:
    """Tests for Message string representation."""

    def test_repr(self, sample_nonce, sample_sender_id, sample_iv, sample_auth_tag, sample_signature):
        """Test Message __repr__ method."""
        msg = Message(
            nonce=sample_nonce,
            sender_id=sample_sender_id,
            iv=sample_iv,
            ciphertext=b"test ciphertext",
            auth_tag=sample_auth_tag,
            signature=sample_signature
        )
        
        repr_str = repr(msg)
        
        assert "Message" in repr_str
        assert "version=" in repr_str
        assert "flags=" in repr_str
        assert "ciphertext_len=" in repr_str