"""
SecureChat Message Model

This module defines the message format for SecureChat, following the
protocol specification from ARCHITECTURE.md.

Message Structure:
==================
Byte Offset | Field        | Size    | Description
------------|--------------|---------|----------------------------------
0           | version      | 1       | Protocol version (0x01)
1           | flags        | 1       | Bit flags for message options
2-9         | timestamp    | 8       | Unix timestamp (milliseconds)
10-25       | nonce        | 16      | Random nonce for replay protection
26-57       | sender_id    | 32      | SHA-256 of sender's public key
58-69       | iv           | 12      | AES-GCM initialization vector
70-N        | ciphertext   | var     | Encrypted message content
N+1-N+16    | auth_tag     | 16      | AES-GCM authentication tag
N+17-N+272  | signature    | 256     | RSA-PSS signature

Flags (byte 1):
===============
Bit 0: Encrypted (1 = yes)
Bit 1: Signed (1 = yes)
Bit 2: Compressed (1 = yes)
Bit 3: Key exchange message (1 = yes)
Bits 4-7: Reserved
"""

import struct
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import IntFlag


# Protocol constants
PROTOCOL_VERSION = 0x01
HEADER_SIZE = 58  # version(1) + flags(1) + timestamp(8) + nonce(16) + sender_id(32)
IV_SIZE = 12
AUTH_TAG_SIZE = 16
SIGNATURE_SIZE = 256
SENDER_ID_SIZE = 32
NONCE_SIZE = 16


class MessageFlags(IntFlag):
    """Message flags enumeration."""
    NONE = 0x00
    ENCRYPTED = 0x01
    SIGNED = 0x02
    COMPRESSED = 0x04
    KEY_EXCHANGE = 0x08


@dataclass
class Message:
    """
    Represents an encrypted SecureChat message.
    
    This class handles serialization and deserialization of messages
    following the SecureChat protocol specification.
    """
    
    # Header fields
    version: int = PROTOCOL_VERSION
    flags: int = MessageFlags.ENCRYPTED | MessageFlags.SIGNED
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    nonce: bytes = field(default_factory=lambda: b'\x00' * NONCE_SIZE)
    sender_id: bytes = field(default_factory=lambda: b'\x00' * SENDER_ID_SIZE)
    
    # Body fields
    iv: bytes = field(default_factory=lambda: b'\x00' * IV_SIZE)
    ciphertext: bytes = field(default_factory=bytes)
    auth_tag: bytes = field(default_factory=lambda: b'\x00' * AUTH_TAG_SIZE)
    
    # Trailer field
    signature: bytes = field(default_factory=lambda: b'\x00' * SIGNATURE_SIZE)
    
    # Optional: recipient for routing
    recipient_id: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate message fields after initialization."""
        self._validate()
    
    def _validate(self):
        """Validate message field sizes and types."""
        errors = []
        
        if not isinstance(self.version, int) or not (0 <= self.version <= 255):
            errors.append("version must be a byte (0-255)")
        
        if not isinstance(self.flags, int) or not (0 <= self.flags <= 255):
            errors.append("flags must be a byte (0-255)")
        
        if not isinstance(self.timestamp, int) or self.timestamp < 0:
            errors.append("timestamp must be a non-negative integer")
        
        if not isinstance(self.nonce, bytes) or len(self.nonce) != NONCE_SIZE:
            errors.append(f"nonce must be {NONCE_SIZE} bytes")
        
        if not isinstance(self.sender_id, bytes) or len(self.sender_id) != SENDER_ID_SIZE:
            errors.append(f"sender_id must be {SENDER_ID_SIZE} bytes")
        
        if not isinstance(self.iv, bytes) or len(self.iv) != IV_SIZE:
            errors.append(f"iv must be {IV_SIZE} bytes")
        
        if not isinstance(self.ciphertext, bytes):
            errors.append("ciphertext must be bytes")
        
        if not isinstance(self.auth_tag, bytes) or len(self.auth_tag) != AUTH_TAG_SIZE:
            errors.append(f"auth_tag must be {AUTH_TAG_SIZE} bytes")
        
        if not isinstance(self.signature, bytes) or len(self.signature) != SIGNATURE_SIZE:
            errors.append(f"signature must be {SIGNATURE_SIZE} bytes")
        
        if self.recipient_id is not None:
            if not isinstance(self.recipient_id, bytes) or len(self.recipient_id) != SENDER_ID_SIZE:
                errors.append(f"recipient_id must be {SENDER_ID_SIZE} bytes or None")
        
        if errors:
            raise ValueError("Message validation failed: " + "; ".join(errors))
    
    def to_bytes(self) -> bytes:
        """
        Serialize the message to bytes.
        
        Returns:
            bytes: The serialized message.
        
        Format:
            [header][iv][ciphertext][auth_tag][signature]
        """
        # Pack header
        header = struct.pack(
            '>BB Q',  # Big-endian: version(1), flags(1), timestamp(8)
            self.version,
            self.flags,
            self.timestamp
        )
        header += self.nonce  # 16 bytes
        header += self.sender_id  # 32 bytes
        
        # Combine all parts
        return (
            header +           # 58 bytes
            self.iv +          # 12 bytes
            self.ciphertext +  # variable
            self.auth_tag +    # 16 bytes
            self.signature     # 256 bytes
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        """
        Deserialize a message from bytes.
        
        Args:
            data: The serialized message bytes.
        
        Returns:
            Message: The deserialized message.
        
        Raises:
            ValueError: If the data is too short or invalid.
        """
        min_size = HEADER_SIZE + IV_SIZE + AUTH_TAG_SIZE + SIGNATURE_SIZE
        if len(data) < min_size:
            raise ValueError(f"Message data too short: {len(data)} < {min_size}")
        
        # Unpack header
        version, flags, timestamp = struct.unpack('>BB Q', data[0:10])
        nonce = data[10:26]
        sender_id = data[26:58]
        
        # Body
        iv = data[58:70]
        
        # Calculate ciphertext length
        ciphertext_len = len(data) - HEADER_SIZE - IV_SIZE - AUTH_TAG_SIZE - SIGNATURE_SIZE
        ciphertext_end = 70 + ciphertext_len
        ciphertext = data[70:ciphertext_end]
        
        # Auth tag and signature
        auth_tag = data[ciphertext_end:ciphertext_end + AUTH_TAG_SIZE]
        signature = data[ciphertext_end + AUTH_TAG_SIZE:]
        
        return cls(
            version=version,
            flags=flags,
            timestamp=timestamp,
            nonce=nonce,
            sender_id=sender_id,
            iv=iv,
            ciphertext=ciphertext,
            auth_tag=auth_tag,
            signature=signature
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the message to a dictionary (JSON-serializable).
        
        Binary fields are hex-encoded.
        
        Returns:
            dict: The message as a dictionary.
        """
        return {
            'version': self.version,
            'flags': self.flags,
            'timestamp': self.timestamp,
            'nonce': self.nonce.hex(),
            'sender_id': self.sender_id.hex(),
            'iv': self.iv.hex(),
            'ciphertext': self.ciphertext.hex(),
            'auth_tag': self.auth_tag.hex(),
            'signature': self.signature.hex(),
            'recipient_id': self.recipient_id.hex() if self.recipient_id else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """
        Create a message from a dictionary.
        
        Binary fields should be hex-encoded strings.
        
        Args:
            data: The message dictionary.
        
        Returns:
            Message: The constructed message.
        
        Raises:
            ValueError: If required fields are missing or invalid.
        """
        required_fields = ['version', 'flags', 'timestamp', 'nonce', 'sender_id',
                          'iv', 'ciphertext', 'auth_tag', 'signature']
        
        for field_name in required_fields:
            if field_name not in data:
                raise ValueError(f"Missing required field: {field_name}")
        
        return cls(
            version=data['version'],
            flags=data['flags'],
            timestamp=data['timestamp'],
            nonce=bytes.fromhex(data['nonce']),
            sender_id=bytes.fromhex(data['sender_id']),
            iv=bytes.fromhex(data['iv']),
            ciphertext=bytes.fromhex(data['ciphertext']),
            auth_tag=bytes.fromhex(data['auth_tag']),
            signature=bytes.fromhex(data['signature']),
            recipient_id=bytes.fromhex(data['recipient_id']) if data.get('recipient_id') else None
        )
    
    def is_encrypted(self) -> bool:
        """Check if the message is encrypted."""
        return bool(self.flags & MessageFlags.ENCRYPTED)
    
    def is_signed(self) -> bool:
        """Check if the message is signed."""
        return bool(self.flags & MessageFlags.SIGNED)
    
    def is_compressed(self) -> bool:
        """Check if the message is compressed."""
        return bool(self.flags & MessageFlags.COMPRESSED)
    
    def is_key_exchange(self) -> bool:
        """Check if this is a key exchange message."""
        return bool(self.flags & MessageFlags.KEY_EXCHANGE)
    
    def get_data_to_sign(self) -> bytes:
        """
        Get the message data that should be signed/verified.
        
        This includes everything except the signature itself:
        version, flags, timestamp, nonce, sender_id, iv, ciphertext, auth_tag
        
        Returns:
            bytes: The data to be signed.
        """
        header = struct.pack(
            '>BB Q',
            self.version,
            self.flags,
            self.timestamp
        )
        header += self.nonce
        header += self.sender_id
        
        return header + self.iv + self.ciphertext + self.auth_tag
    
    def get_size(self) -> int:
        """
        Get the total size of the serialized message.
        
        Returns:
            int: Size in bytes.
        """
        return HEADER_SIZE + IV_SIZE + len(self.ciphertext) + AUTH_TAG_SIZE + SIGNATURE_SIZE
    
    def validate_timestamp(self, window_seconds: int = 300) -> bool:
        """
        Validate that the message timestamp is within acceptable window.
        
        Args:
            window_seconds: Maximum age in seconds (default: 5 minutes).
        
        Returns:
            bool: True if timestamp is valid.
        """
        now_ms = int(time.time() * 1000)
        age_ms = now_ms - self.timestamp
        
        # Check if timestamp is not in the future (with small tolerance)
        # and not too old
        return -5000 <= age_ms <= (window_seconds * 1000)
    
    def __repr__(self) -> str:
        return (
            f"Message(version={self.version}, flags={self.flags:#04x}, "
            f"timestamp={self.timestamp}, sender={self.sender_id.hex()[:16]}..., "
            f"ciphertext_len={len(self.ciphertext)})"
        )


# Simple test when run directly
if __name__ == "__main__":
    import os
    
    print("Testing Message model implementation...")
    
    # Test 1: Create message
    print("\n1. Testing message creation:")
    msg = Message(
        version=PROTOCOL_VERSION,
        flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED,
        timestamp=int(time.time() * 1000),
        nonce=os.urandom(NONCE_SIZE),
        sender_id=os.urandom(SENDER_ID_SIZE),
        iv=os.urandom(IV_SIZE),
        ciphertext=b"Hello, encrypted world!",
        auth_tag=os.urandom(AUTH_TAG_SIZE),
        signature=os.urandom(SIGNATURE_SIZE)
    )
    print(f"   Created: {msg}")
    print("   ✓ Message created!")
    
    # Test 2: Serialize to bytes
    print("\n2. Testing serialization to bytes:")
    msg_bytes = msg.to_bytes()
    print(f"   Size: {len(msg_bytes)} bytes")
    print(f"   Header: {msg_bytes[:10].hex()}")
    print("   ✓ Serialized to bytes!")
    
    # Test 3: Deserialize from bytes
    print("\n3. Testing deserialization from bytes:")
    msg_restored = Message.from_bytes(msg_bytes)
    assert msg_restored.version == msg.version
    assert msg_restored.flags == msg.flags
    assert msg_restored.timestamp == msg.timestamp
    assert msg_restored.nonce == msg.nonce
    assert msg_restored.sender_id == msg.sender_id
    assert msg_restored.iv == msg.iv
    assert msg_restored.ciphertext == msg.ciphertext
    assert msg_restored.auth_tag == msg.auth_tag
    assert msg_restored.signature == msg.signature
    print("   ✓ Deserialized correctly!")
    
    # Test 4: Serialize to dict
    print("\n4. Testing serialization to dict:")
    msg_dict = msg.to_dict()
    print(f"   Keys: {list(msg_dict.keys())}")
    assert all(k in msg_dict for k in ['version', 'flags', 'timestamp', 'nonce', 
                                       'sender_id', 'iv', 'ciphertext', 'auth_tag', 'signature'])
    print("   ✓ Serialized to dict!")
    
    # Test 5: Deserialize from dict
    print("\n5. Testing deserialization from dict:")
    msg_from_dict = Message.from_dict(msg_dict)
    assert msg_from_dict.version == msg.version
    assert msg_from_dict.ciphertext == msg.ciphertext
    print("   ✓ Deserialized from dict!")
    
    # Test 6: Flag checking
    print("\n6. Testing flag checking:")
    assert msg.is_encrypted()
    assert msg.is_signed()
    assert not msg.is_compressed()
    assert not msg.is_key_exchange()
    print("   ✓ Flag checks work!")
    
    # Test 7: Timestamp validation
    print("\n7. Testing timestamp validation:")
    assert msg.validate_timestamp(window_seconds=300)
    
    # Create old message
    old_msg = Message(
        timestamp=int((time.time() - 600) * 1000),  # 10 minutes ago
        nonce=os.urandom(NONCE_SIZE),
        sender_id=os.urandom(SENDER_ID_SIZE),
        iv=os.urandom(IV_SIZE),
        ciphertext=b"old message",
        auth_tag=os.urandom(AUTH_TAG_SIZE),
        signature=os.urandom(SIGNATURE_SIZE)
    )
    assert not old_msg.validate_timestamp(window_seconds=300)
    print("   ✓ Timestamp validation works!")
    
    # Test 8: Data to sign
    print("\n8. Testing get_data_to_sign:")
    data_to_sign = msg.get_data_to_sign()
    expected_size = HEADER_SIZE + IV_SIZE + len(msg.ciphertext) + AUTH_TAG_SIZE
    assert len(data_to_sign) == expected_size
    print(f"   Data to sign size: {len(data_to_sign)} bytes")
    print("   ✓ get_data_to_sign works!")
    
    # Test 9: Size calculation
    print("\n9. Testing size calculation:")
    calculated_size = msg.get_size()
    actual_size = len(msg.to_bytes())
    assert calculated_size == actual_size
    print(f"   Calculated: {calculated_size}, Actual: {actual_size}")
    print("   ✓ Size calculation correct!")
    
    # Test 10: Validation errors
    print("\n10. Testing validation errors:")
    try:
        Message(nonce=b"short")  # Should fail
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected invalid nonce: {str(e)[:50]}...")
    
    # Test 11: Empty ciphertext
    print("\n11. Testing empty ciphertext:")
    empty_msg = Message(
        nonce=os.urandom(NONCE_SIZE),
        sender_id=os.urandom(SENDER_ID_SIZE),
        iv=os.urandom(IV_SIZE),
        ciphertext=b"",
        auth_tag=os.urandom(AUTH_TAG_SIZE),
        signature=os.urandom(SIGNATURE_SIZE)
    )
    empty_bytes = empty_msg.to_bytes()
    empty_restored = Message.from_bytes(empty_bytes)
    assert empty_restored.ciphertext == b""
    print("   ✓ Empty ciphertext handled correctly!")
    
    # Test 12: Large ciphertext
    print("\n12. Testing large ciphertext:")
    large_ct = os.urandom(10000)  # 10 KB
    large_msg = Message(
        nonce=os.urandom(NONCE_SIZE),
        sender_id=os.urandom(SENDER_ID_SIZE),
        iv=os.urandom(IV_SIZE),
        ciphertext=large_ct,
        auth_tag=os.urandom(AUTH_TAG_SIZE),
        signature=os.urandom(SIGNATURE_SIZE)
    )
    large_bytes = large_msg.to_bytes()
    large_restored = Message.from_bytes(large_bytes)
    assert large_restored.ciphertext == large_ct
    print(f"   Large message size: {len(large_bytes)} bytes")
    print("   ✓ Large ciphertext handled correctly!")
    
    print("\n" + "="*50)
    print("All Message model tests passed! ✓")
    print("="*50)