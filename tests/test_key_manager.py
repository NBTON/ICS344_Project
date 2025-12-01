"""
Key Manager Tests

Tests for the KeyManager service:
- User registration
- Key retrieval
- Session creation
- Session key management
- Key exchange
"""

import os
import time
import pytest

from backend.services.key_manager import KeyManager, get_key_manager, UserKeys, Session


class TestUserRegistration:
    """Tests for user registration functionality."""

    def test_register_user_success(self, key_manager):
        """Test successful user registration."""
        result = key_manager.register_user("alice")
        
        assert result['user_id'] == "alice"
        assert 'public_key' in result
        assert 'fingerprint' in result
        assert result['public_key'].startswith("-----BEGIN PUBLIC KEY-----")

    def test_register_user_returns_hex_fingerprint(self, key_manager):
        """Test that fingerprint is hex-encoded."""
        result = key_manager.register_user("alice")
        
        # Should be a valid hex string (64 chars for SHA-256)
        assert len(result['fingerprint']) == 64
        bytes.fromhex(result['fingerprint'])  # Should not raise

    def test_register_duplicate_user_fails(self, key_manager):
        """Test that registering duplicate user raises ValueError."""
        key_manager.register_user("alice")
        
        with pytest.raises(ValueError, match="already registered"):
            key_manager.register_user("alice")

    def test_register_multiple_users(self, key_manager):
        """Test registering multiple users."""
        alice = key_manager.register_user("alice")
        bob = key_manager.register_user("bob")
        
        assert alice['user_id'] != bob['user_id']
        assert alice['fingerprint'] != bob['fingerprint']


class TestKeyRetrieval:
    """Tests for key retrieval functionality."""

    def test_get_user_keys(self, key_manager):
        """Test getting user keys object."""
        key_manager.register_user("alice")
        
        user_keys = key_manager.get_user_keys("alice")
        
        assert user_keys is not None
        assert isinstance(user_keys, UserKeys)
        assert user_keys.user_id == "alice"

    def test_get_user_keys_not_found(self, key_manager):
        """Test getting keys for non-existent user returns None."""
        user_keys = key_manager.get_user_keys("nonexistent")
        assert user_keys is None

    def test_get_public_key(self, key_manager):
        """Test getting user's public key PEM."""
        key_manager.register_user("alice")
        
        public_key = key_manager.get_public_key("alice")
        
        assert public_key is not None
        assert b"-----BEGIN PUBLIC KEY-----" in public_key

    def test_get_public_key_not_found(self, key_manager):
        """Test getting public key for non-existent user returns None."""
        public_key = key_manager.get_public_key("nonexistent")
        assert public_key is None

    def test_get_all_users_empty(self, key_manager):
        """Test getting users when none registered."""
        users = key_manager.get_all_users()
        assert users == []

    def test_get_all_users(self, key_manager):
        """Test getting list of all users."""
        key_manager.register_user("alice")
        key_manager.register_user("bob")
        
        users = key_manager.get_all_users()
        
        assert len(users) == 2
        user_ids = [u['user_id'] for u in users]
        assert "alice" in user_ids
        assert "bob" in user_ids

    def test_user_info_contains_created_at(self, key_manager):
        """Test that user info includes created_at timestamp."""
        key_manager.register_user("alice")
        
        users = key_manager.get_all_users()
        
        assert 'created_at' in users[0]
        assert users[0]['created_at'] <= time.time()


class TestSessionCreation:
    """Tests for session creation functionality."""

    def test_create_session_success(self, registered_users):
        """Test successful session creation."""
        km = registered_users["key_manager"]
        
        session = km.create_session("alice", "bob")
        
        assert 'session_id' in session
        assert 'encrypted_key_for_initiator' in session
        assert 'encrypted_key_for_recipient' in session
        assert 'initiator_signature' in session
        assert 'created_at' in session
        assert 'expires_at' in session

    def test_create_session_generates_unique_id(self, registered_users):
        """Test that each session has unique ID."""
        km = registered_users["key_manager"]
        
        session1 = km.create_session("alice", "bob")
        session2 = km.create_session("alice", "bob")
        
        assert session1['session_id'] != session2['session_id']

    def test_create_session_invalid_initiator(self, registered_users):
        """Test that invalid initiator raises ValueError."""
        km = registered_users["key_manager"]
        
        with pytest.raises(ValueError, match="not registered"):
            km.create_session("nonexistent", "bob")

    def test_create_session_invalid_recipient(self, registered_users):
        """Test that invalid recipient raises ValueError."""
        km = registered_users["key_manager"]
        
        with pytest.raises(ValueError, match="not registered"):
            km.create_session("alice", "nonexistent")

    def test_session_expiration_time(self, registered_users):
        """Test that session has correct expiration time."""
        km = registered_users["key_manager"]
        
        session = km.create_session("alice", "bob")
        
        # Default timeout is 3600 seconds (1 hour)
        expected_expiry = session['created_at'] + 3600
        assert abs(session['expires_at'] - expected_expiry) < 1


class TestSessionKeyManagement:
    """Tests for session key management functionality."""

    def test_get_session_key_initiator(self, registered_users):
        """Test that initiator can retrieve session key."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        key = km.get_session_key(session['session_id'], "alice")
        
        assert key is not None
        assert len(key) == 32  # AES-256

    def test_get_session_key_recipient(self, registered_users):
        """Test that recipient can retrieve session key."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        key = km.get_session_key(session['session_id'], "bob")
        
        assert key is not None
        assert len(key) == 32

    def test_both_users_get_same_key(self, registered_users):
        """Test that both users get the same session key."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        alice_key = km.get_session_key(session['session_id'], "alice")
        bob_key = km.get_session_key(session['session_id'], "bob")
        
        assert alice_key == bob_key

    def test_get_session_key_unauthorized(self, registered_users):
        """Test that unauthorized user cannot get session key."""
        km = registered_users["key_manager"]
        km.register_user("eve")
        session = km.create_session("alice", "bob")
        
        key = km.get_session_key(session['session_id'], "eve")
        
        assert key is None

    def test_get_session_key_invalid_session(self, registered_users):
        """Test getting key for invalid session returns None."""
        km = registered_users["key_manager"]
        
        key = km.get_session_key("invalid_session_id", "alice")
        
        assert key is None


class TestSessionManagement:
    """Tests for session management functionality."""

    def test_get_session(self, registered_users):
        """Test getting session info."""
        km = registered_users["key_manager"]
        session_data = km.create_session("alice", "bob")
        
        session = km.get_session(session_data['session_id'])
        
        assert session is not None
        assert isinstance(session, Session)
        assert session.user1_id == "alice"
        assert session.user2_id == "bob"

    def test_get_session_not_found(self, key_manager):
        """Test getting non-existent session returns None."""
        session = key_manager.get_session("nonexistent")
        assert session is None

    def test_get_user_sessions(self, registered_users):
        """Test getting user's active sessions."""
        km = registered_users["key_manager"]
        km.create_session("alice", "bob")
        
        sessions = km.get_user_sessions("alice")
        
        assert len(sessions) == 1
        assert sessions[0]['peer_id'] == "bob"

    def test_get_user_sessions_multiple(self, registered_users):
        """Test getting multiple sessions for a user."""
        km = registered_users["key_manager"]
        km.register_user("charlie")
        
        km.create_session("alice", "bob")
        km.create_session("alice", "charlie")
        
        sessions = km.get_user_sessions("alice")
        
        assert len(sessions) == 2

    def test_revoke_session(self, registered_users):
        """Test session revocation."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        result = km.revoke_session(session['session_id'], "alice")
        
        assert result is True
        assert km.get_session(session['session_id']) is None

    def test_revoke_session_by_participant(self, registered_users):
        """Test that any participant can revoke session."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        result = km.revoke_session(session['session_id'], "bob")
        
        assert result is True

    def test_revoke_session_unauthorized(self, registered_users):
        """Test that unauthorized user cannot revoke session."""
        km = registered_users["key_manager"]
        km.register_user("eve")
        session = km.create_session("alice", "bob")
        
        result = km.revoke_session(session['session_id'], "eve")
        
        assert result is False
        # Session should still exist
        assert km.get_session(session['session_id']) is not None

    def test_revoke_session_nonexistent(self, key_manager):
        """Test revoking non-existent session returns False."""
        result = key_manager.revoke_session("nonexistent", "alice")
        assert result is False


class TestSessionExpiration:
    """Tests for session expiration handling."""

    def test_expired_session_key_not_returned(self, key_manager):
        """Test that expired session key is not returned."""
        # Register users
        key_manager.register_user("alice")
        key_manager.register_user("bob")
        
        # Create session
        session_data = key_manager.create_session("alice", "bob")
        
        # Manually expire the session
        session = key_manager.get_session(session_data['session_id'])
        session.expires_at = time.time() - 1  # Already expired
        
        # Should return None for expired session
        key = key_manager.get_session_key(session_data['session_id'], "alice")
        assert key is None

    def test_cleanup_expired_sessions(self, key_manager):
        """Test cleanup of expired sessions."""
        key_manager.register_user("alice")
        key_manager.register_user("bob")
        
        # Create an expired session directly
        key_manager._sessions["expired_test"] = Session(
            session_id="expired_test",
            user1_id="alice",
            user2_id="bob",
            session_key=os.urandom(32),
            created_at=time.time() - 7200,
            expires_at=time.time() - 3600
        )
        
        cleaned = key_manager.cleanup_expired_sessions()
        
        assert cleaned == 1
        assert "expired_test" not in key_manager._sessions


class TestKeyExchangeVerification:
    """Tests for key exchange signature verification."""

    def test_verify_key_exchange_signature(self, registered_users):
        """Test verification of key exchange signature."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        encrypted_key = bytes.fromhex(session['encrypted_key_for_recipient'])
        signature = bytes.fromhex(session['initiator_signature'])
        
        is_valid = km.verify_key_exchange_signature(encrypted_key, signature, "alice")
        
        assert is_valid is True

    def test_verify_key_exchange_signature_invalid(self, registered_users):
        """Test that invalid signature is rejected."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        encrypted_key = bytes.fromhex(session['encrypted_key_for_recipient'])
        # Create invalid signature
        invalid_signature = os.urandom(256)
        
        is_valid = km.verify_key_exchange_signature(encrypted_key, invalid_signature, "alice")
        
        assert is_valid is False

    def test_verify_key_exchange_signature_wrong_sender(self, registered_users):
        """Test that signature with wrong sender fails."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        encrypted_key = bytes.fromhex(session['encrypted_key_for_recipient'])
        signature = bytes.fromhex(session['initiator_signature'])
        
        # Verify with wrong sender
        is_valid = km.verify_key_exchange_signature(encrypted_key, signature, "bob")
        
        assert is_valid is False

    def test_decrypt_session_key_for_user(self, registered_users):
        """Test decrypting session key for a user."""
        km = registered_users["key_manager"]
        session = km.create_session("alice", "bob")
        
        encrypted_key = bytes.fromhex(session['encrypted_key_for_initiator'])
        decrypted = km.decrypt_session_key_for_user(encrypted_key, "alice")
        
        # Should match the actual session key
        actual_key = km.get_session_key(session['session_id'], "alice")
        assert decrypted == actual_key

    def test_decrypt_session_key_invalid_user(self, key_manager):
        """Test decrypting with invalid user returns None."""
        result = key_manager.decrypt_session_key_for_user(b"encrypted", "nonexistent")
        assert result is None


class TestSingletonKeyManager:
    """Tests for the singleton KeyManager accessor."""

    def test_get_key_manager_returns_same_instance(self):
        """Test that get_key_manager returns singleton."""
        km1 = get_key_manager()
        km2 = get_key_manager()
        
        assert km1 is km2

    def test_get_key_manager_returns_key_manager(self):
        """Test that get_key_manager returns KeyManager instance."""
        km = get_key_manager()
        assert isinstance(km, KeyManager)