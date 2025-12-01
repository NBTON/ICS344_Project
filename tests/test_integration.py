"""
Integration Tests

Full integration tests for SecureChat:
- Complete message flow (encrypt, sign, send, verify, decrypt)
- Key exchange flow
- End-to-end secure communication
"""

import os
import time
import pytest

from backend.crypto import aes_gcm, rsa_keys, rsa_oaep, rsa_pss
from backend.models.message import Message, MessageFlags, NONCE_SIZE, SENDER_ID_SIZE, IV_SIZE, AUTH_TAG_SIZE, SIGNATURE_SIZE
from backend.services.key_manager import KeyManager


class TestEndToEndMessageFlow:
    """Tests for complete secure message flow."""

    def test_complete_message_encrypt_sign_verify_decrypt(self):
        """Test complete message flow: encrypt, sign, verify, decrypt."""
        # Setup: Generate key pairs for Alice and Bob
        alice_private, alice_public = rsa_keys.generate_key_pair()
        bob_private, bob_public = rsa_keys.generate_key_pair()
        
        # Generate shared session key
        session_key = aes_gcm.generate_key()
        
        # Original message from Alice
        plaintext = b"Hello Bob! This is a secret message from Alice."
        
        # Step 1: Alice encrypts the message with session key
        ciphertext, iv, tag = aes_gcm.encrypt(plaintext, session_key)
        
        # Step 2: Alice creates message with metadata
        timestamp = int(time.time() * 1000)
        nonce = os.urandom(NONCE_SIZE)
        sender_id = rsa_keys.get_public_key_fingerprint(alice_public)
        
        # Step 3: Alice signs the message
        data_to_sign = ciphertext + iv + timestamp.to_bytes(8, 'big') + nonce
        signature = rsa_pss.sign(data_to_sign, alice_private)
        
        # Create the message object
        message = Message(
            version=1,
            flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED,
            timestamp=timestamp,
            nonce=nonce,
            sender_id=sender_id,
            iv=iv,
            ciphertext=ciphertext,
            auth_tag=tag,
            signature=signature
        )
        
        # Serialize for transmission
        message_bytes = message.to_bytes()
        
        # --- Network transmission simulation ---
        
        # Bob receives and deserializes the message
        received_message = Message.from_bytes(message_bytes)
        
        # Step 4: Bob verifies the signature
        data_to_verify = (
            received_message.ciphertext + 
            received_message.iv + 
            received_message.timestamp.to_bytes(8, 'big') + 
            received_message.nonce
        )
        signature_valid = rsa_pss.verify(
            data_to_verify, 
            received_message.signature, 
            alice_public
        )
        assert signature_valid, "Signature verification should pass"
        
        # Step 5: Bob validates the timestamp
        assert received_message.validate_timestamp(), "Timestamp should be valid"
        
        # Step 6: Bob decrypts the message
        decrypted = aes_gcm.decrypt(
            received_message.ciphertext,
            session_key,
            received_message.iv,
            received_message.auth_tag
        )
        
        assert decrypted == plaintext, "Decrypted message should match original"

    def test_message_flow_detects_tampering(self):
        """Test that message tampering is detected."""
        # Setup
        alice_private, alice_public = rsa_keys.generate_key_pair()
        session_key = aes_gcm.generate_key()
        plaintext = b"Transfer $1000 to Bob"
        
        # Alice creates and signs message
        ciphertext, iv, tag = aes_gcm.encrypt(plaintext, session_key)
        timestamp = int(time.time() * 1000)
        nonce = os.urandom(NONCE_SIZE)
        
        data_to_sign = ciphertext + iv + timestamp.to_bytes(8, 'big') + nonce
        signature = rsa_pss.sign(data_to_sign, alice_private)
        
        # Simulate attacker tampering with ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        
        # Verify tampered data - signature should fail
        tampered_data = bytes(tampered_ciphertext) + iv + timestamp.to_bytes(8, 'big') + nonce
        is_valid = rsa_pss.verify(tampered_data, signature, alice_public)
        
        assert not is_valid, "Tampered message should fail signature verification"

    def test_message_flow_detects_replay(self):
        """Test that replay attacks are detected via timestamp."""
        sender_id = os.urandom(SENDER_ID_SIZE)
        
        # Create an old message
        old_timestamp = int((time.time() - 600) * 1000)  # 10 minutes ago
        
        message = Message(
            timestamp=old_timestamp,
            nonce=os.urandom(NONCE_SIZE),
            sender_id=sender_id,
            iv=os.urandom(IV_SIZE),
            ciphertext=b"old message",
            auth_tag=os.urandom(AUTH_TAG_SIZE),
            signature=os.urandom(SIGNATURE_SIZE)
        )
        
        # Timestamp validation should fail
        assert not message.validate_timestamp(window_seconds=300), \
            "Old message timestamp should be rejected"


class TestKeyExchangeFlow:
    """Tests for complete key exchange flow."""

    def test_complete_key_exchange_flow(self):
        """Test complete key exchange between two users."""
        km = KeyManager()
        
        # Step 1: Both users register
        alice_info = km.register_user("alice")
        bob_info = km.register_user("bob")
        
        # Step 2: Alice initiates key exchange
        session_info = km.create_session("alice", "bob")
        
        # Step 3: Both users can retrieve the same session key
        alice_key = km.get_session_key(session_info['session_id'], "alice")
        bob_key = km.get_session_key(session_info['session_id'], "bob")
        
        assert alice_key is not None, "Alice should have access to session key"
        assert bob_key is not None, "Bob should have access to session key"
        assert alice_key == bob_key, "Both users should have the same session key"
        
        # Step 4: Verify the signature on the key exchange
        encrypted_key_for_bob = bytes.fromhex(session_info['encrypted_key_for_recipient'])
        signature = bytes.fromhex(session_info['initiator_signature'])
        
        is_valid = km.verify_key_exchange_signature(
            encrypted_key_for_bob, signature, "alice"
        )
        assert is_valid, "Key exchange signature should be valid"

    def test_key_exchange_with_encrypted_key_decryption(self):
        """Test that users can decrypt their encrypted session keys."""
        km = KeyManager()
        
        km.register_user("alice")
        km.register_user("bob")
        
        session_info = km.create_session("alice", "bob")
        
        # Alice decrypts her copy of the session key
        encrypted_for_alice = bytes.fromhex(session_info['encrypted_key_for_initiator'])
        decrypted_by_alice = km.decrypt_session_key_for_user(encrypted_for_alice, "alice")
        
        # Bob decrypts his copy
        encrypted_for_bob = bytes.fromhex(session_info['encrypted_key_for_recipient'])
        decrypted_by_bob = km.decrypt_session_key_for_user(encrypted_for_bob, "bob")
        
        # Both should get the same key
        assert decrypted_by_alice == decrypted_by_bob, \
            "Both should decrypt to the same session key"
        
        # And it should match the actual session key
        actual_key = km.get_session_key(session_info['session_id'], "alice")
        assert decrypted_by_alice == actual_key


class TestSecureCommunicationFlow:
    """Tests for complete secure communication between users."""

    def test_alice_bob_secure_chat(self):
        """Test full secure chat flow between Alice and Bob."""
        km = KeyManager()
        
        # Registration
        km.register_user("alice")
        km.register_user("bob")
        
        # Key exchange
        session = km.create_session("alice", "bob")
        session_key = km.get_session_key(session['session_id'], "alice")
        
        # Get user keys for signing
        alice_keys = km.get_user_keys("alice")
        bob_keys = km.get_user_keys("bob")
        
        # Alice sends a message
        alice_message = b"Hey Bob, how are you?"
        
        # Encrypt
        ct, iv, tag = aes_gcm.encrypt(alice_message, session_key)
        
        # Sign
        timestamp = int(time.time() * 1000)
        nonce = os.urandom(NONCE_SIZE)
        data_to_sign = ct + iv + timestamp.to_bytes(8, 'big') + nonce
        signature = rsa_pss.sign(data_to_sign, alice_keys.private_key)
        
        # Bob verifies and decrypts
        is_signed_by_alice = rsa_pss.verify(
            data_to_sign, signature, alice_keys.public_key
        )
        assert is_signed_by_alice
        
        decrypted = aes_gcm.decrypt(ct, session_key, iv, tag)
        assert decrypted == alice_message
        
        # Bob replies
        bob_message = b"Hi Alice! I'm doing great, thanks!"
        
        ct2, iv2, tag2 = aes_gcm.encrypt(bob_message, session_key)
        timestamp2 = int(time.time() * 1000)
        nonce2 = os.urandom(NONCE_SIZE)
        data_to_sign2 = ct2 + iv2 + timestamp2.to_bytes(8, 'big') + nonce2
        signature2 = rsa_pss.sign(data_to_sign2, bob_keys.private_key)
        
        # Alice verifies and decrypts
        is_signed_by_bob = rsa_pss.verify(
            data_to_sign2, signature2, bob_keys.public_key
        )
        assert is_signed_by_bob
        
        decrypted2 = aes_gcm.decrypt(ct2, session_key, iv2, tag2)
        assert decrypted2 == bob_message


class TestAPIIntegration:
    """Integration tests using the API."""

    def test_register_exchange_communicate(self, client):
        """Test full flow through API endpoints."""
        # Reset key manager for clean test
        import backend.services.key_manager as km_module
        km_module._key_manager_instance = KeyManager()
        
        # Register Alice
        response = client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        assert response.status_code == 201
        alice_data = response.get_json()
        
        # Register Bob
        response = client.post(
            '/api/register',
            json={'user_id': 'bob'},
            content_type='application/json'
        )
        assert response.status_code == 201
        bob_data = response.get_json()
        
        # Verify both users appear in user list
        response = client.get('/api/users')
        users = response.get_json()['users']
        user_ids = [u['user_id'] for u in users]
        assert 'alice' in user_ids
        assert 'bob' in user_ids
        
        # Get Alice's public key
        response = client.get('/api/keys/public/alice')
        assert response.status_code == 200
        alice_public = response.get_json()['public_key']
        assert 'BEGIN PUBLIC KEY' in alice_public
        
        # Exchange keys
        response = client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        assert response.status_code == 201
        session_data = response.get_json()
        session_id = session_data['session_id']
        
        # Check Alice's sessions
        response = client.get('/api/keys/sessions/alice')
        sessions = response.get_json()['sessions']
        assert len(sessions) == 1
        assert sessions[0]['peer_id'] == 'bob'
        
        # Get session info
        response = client.get(f'/api/keys/session/{session_id}?user_id=alice')
        assert response.status_code == 200
        session_info = response.get_json()
        assert session_info['user1_id'] == 'alice'
        assert session_info['user2_id'] == 'bob'
        
        # Revoke session
        response = client.delete(f'/api/keys/session/{session_id}?user_id=alice')
        assert response.status_code == 200
        
        # Verify session is gone
        response = client.get(f'/api/keys/session/{session_id}?user_id=alice')
        assert response.status_code == 404


class TestMessageSerializationIntegration:
    """Integration tests for message serialization across the system."""

    def test_message_dict_json_serializable(self):
        """Test that message dict can be JSON serialized."""
        import json
        
        message = Message(
            timestamp=int(time.time() * 1000),
            nonce=os.urandom(NONCE_SIZE),
            sender_id=os.urandom(SENDER_ID_SIZE),
            iv=os.urandom(IV_SIZE),
            ciphertext=b"test ciphertext data",
            auth_tag=os.urandom(AUTH_TAG_SIZE),
            signature=os.urandom(SIGNATURE_SIZE)
        )
        
        # Convert to dict
        msg_dict = message.to_dict()
        
        # Should be JSON serializable
        json_str = json.dumps(msg_dict)
        
        # Should be able to deserialize back
        restored_dict = json.loads(json_str)
        restored_message = Message.from_dict(restored_dict)
        
        assert restored_message.ciphertext == message.ciphertext
        assert restored_message.timestamp == message.timestamp

    def test_message_bytes_transmission_simulation(self):
        """Test message bytes can survive network transmission."""
        original = Message(
            timestamp=int(time.time() * 1000),
            nonce=os.urandom(NONCE_SIZE),
            sender_id=os.urandom(SENDER_ID_SIZE),
            iv=os.urandom(IV_SIZE),
            ciphertext=os.urandom(1000),  # Realistic message size
            auth_tag=os.urandom(AUTH_TAG_SIZE),
            signature=os.urandom(SIGNATURE_SIZE)
        )
        
        # Serialize
        data = original.to_bytes()
        
        # Simulate network - could add base64 encoding etc.
        import base64
        encoded = base64.b64encode(data)
        decoded = base64.b64decode(encoded)
        
        # Deserialize
        restored = Message.from_bytes(decoded)
        
        assert restored.version == original.version
        assert restored.flags == original.flags
        assert restored.timestamp == original.timestamp
        assert restored.nonce == original.nonce
        assert restored.sender_id == original.sender_id
        assert restored.iv == original.iv
        assert restored.ciphertext == original.ciphertext
        assert restored.auth_tag == original.auth_tag
        assert restored.signature == original.signature