"""
Key Management Service

This module provides key management functionality for SecureChat:
- User registration and key pair management
- Session key generation and storage
- Key exchange protocol implementation

Keys are stored in-memory for demonstration purposes.
In production, use secure key storage (HSM, encrypted database, etc.).
"""

import os
import time
import hashlib
import threading
from typing import Dict, Optional, Tuple, Any, Set, List
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from backend.crypto.rsa_keys import (
    generate_key_pair,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key,
    get_public_key_fingerprint
)
from backend.crypto.rsa_oaep import encrypt_key, decrypt_key
from backend.crypto.rsa_pss import sign, verify
from backend.crypto.aes_gcm import generate_key as generate_aes_key


@dataclass
class UserKeys:
    """Container for user's cryptographic keys."""
    user_id: str
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey
    public_key_pem: bytes
    fingerprint: bytes
    created_at: float = field(default_factory=time.time)


@dataclass
class Session:
    """Container for a messaging session between two users."""
    session_id: str
    user1_id: str
    user2_id: str
    session_key: bytes
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)


class KeyManager:
    """
    Manages cryptographic keys for SecureChat users.
    
    This class provides:
    - User registration with RSA key pair generation
    - Public key distribution
    - Session key creation and management
    - Key exchange protocol implementation
    
    Note: This implementation uses in-memory storage for demonstration.
    """
    
    def __init__(self, key_size: int = 2048, session_timeout: int = 3600):
        """
        Initialize the KeyManager.
        
        Args:
            key_size: RSA key size in bits (default: 2048).
            session_timeout: Session key timeout in seconds (default: 1 hour).
        """
        self._key_size = key_size
        self._session_timeout = session_timeout
        
        # In-memory storage
        self._users: Dict[str, UserKeys] = {}
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, list] = {}  # user_id -> [session_ids]
        self.revoked_keys: Set[bytes] = set()
        self.audit_logs: List[Dict[str, Any]] = []
    
    def register_user(self, user_id: str) -> Dict[str, Any]:
        """
        Register a new user and generate their RSA key pair.
        
        Args:
            user_id: Unique identifier for the user.
        
        Returns:
            dict: Registration result containing:
                - user_id: The user's ID
                - public_key: PEM-encoded public key
                - fingerprint: SHA-256 fingerprint of the public key
        
        Raises:
            ValueError: If user_id is already registered.
        """
        if user_id in self._users:
            raise ValueError(f"User '{user_id}' is already registered")
        
        # Generate RSA key pair
        private_key, public_key = generate_key_pair(self._key_size)
        public_key_pem = serialize_public_key(public_key)
        fingerprint = get_public_key_fingerprint(public_key)
        
        # Store user keys
        user_keys = UserKeys(
            user_id=user_id,
            public_key=public_key,
            private_key=private_key,
            public_key_pem=public_key_pem,
            fingerprint=fingerprint
        )
        self._users[user_id] = user_keys
        self._user_sessions[user_id] = []
        
        return {
            'user_id': user_id,
            'public_key': public_key_pem.decode('utf-8'),
            'fingerprint': fingerprint.hex()
        }
    
    def get_user_keys(self, user_id: str) -> Optional[UserKeys]:
        """
        Get a user's key information.
        
        Args:
            user_id: The user's ID.
        
        Returns:
            UserKeys or None: The user's keys if found and key is not revoked.
        """
        user = self._users.get(user_id)
        if not user:
            return None
            
        if user.fingerprint in self.revoked_keys:
            return None
            
        return user
    
    def get_public_key(self, user_id: str) -> Optional[bytes]:
        """
        Get a user's public key in PEM format.
        
        Args:
            user_id: The user's ID.
        
        Returns:
            bytes or None: PEM-encoded public key if user exists and key is not revoked.
        """
        user = self._users.get(user_id)
        if not user:
            return None
            
        # Check if user's key is revoked
        if user.fingerprint in self.revoked_keys:
            return None
            
        return user.public_key_pem
    
    def get_all_users(self) -> list:
        """
        Get a list of all registered users.
        
        Returns:
            list: List of dicts with user_id, fingerprint, created_at, and revoked status.
        """
        return [
            {
                'user_id': user.user_id,
                'fingerprint': user.fingerprint.hex(),
                'created_at': user.created_at,
                'revoked': user.fingerprint in self.revoked_keys
            }
            for user in self._users.values()
        ]
    
    def create_session(self, initiator_id: str, recipient_id: str) -> Dict[str, Any]:
        """
        Create a new messaging session between two users.
        
        This generates a new AES-256 session key and encrypts it
        for both participants using their RSA public keys.
        
        Args:
            initiator_id: The user initiating the session.
            recipient_id: The user receiving the session invitation.
        
        Returns:
            dict: Session information containing:
                - session_id: Unique session identifier
                - encrypted_key_for_initiator: Session key encrypted for initiator
                - encrypted_key_for_recipient: Session key encrypted for recipient
                - created_at: Session creation timestamp
                - expires_at: Session expiration timestamp
        
        Raises:
            ValueError: If either user is not registered or has a revoked key.
        """
        # Validate users exist
        initiator = self._users.get(initiator_id)
        recipient = self._users.get(recipient_id)
        
        if not initiator:
            raise ValueError(f"Initiator '{initiator_id}' is not registered")
        if not recipient:
            raise ValueError(f"Recipient '{recipient_id}' is not registered")
            
        # Check if initiator or recipient's keys are revoked
        if initiator.fingerprint in self.revoked_keys:
            raise ValueError(f"Initiator '{initiator_id}' has a revoked key")
        if recipient.fingerprint in self.revoked_keys:
            raise ValueError(f"Recipient '{recipient_id}' has a revoked key")
        
        # Generate session key
        session_key = generate_aes_key()
        
        # Create session ID
        session_id = hashlib.sha256(
            f"{initiator_id}:{recipient_id}:{time.time()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()[:32]
        
        # Create session
        now = time.time()
        session = Session(
            session_id=session_id,
            user1_id=initiator_id,
            user2_id=recipient_id,
            session_key=session_key,
            created_at=now,
            expires_at=now + self._session_timeout
        )
        
        # Store session
        self._sessions[session_id] = session
        self._user_sessions[initiator_id].append(session_id)
        self._user_sessions[recipient_id].append(session_id)
        
        # Audit log
        self.audit_logs.append({
            'timestamp': time.time(),
            'action': 'create_session',
            'session_id': session_id,
            'initiator_id': initiator_id,
            'recipient_id': recipient_id,
            'expires_at': session.expires_at
        })
        
        # Encrypt session key for both users
        encrypted_for_initiator = encrypt_key(session_key, initiator.public_key)
        encrypted_for_recipient = encrypt_key(session_key, recipient.public_key)
        
        # Sign the encrypted keys
        initiator_signature = sign(encrypted_for_recipient, initiator.private_key)
        
        return {
            'session_id': session_id,
            'encrypted_key_for_initiator': encrypted_for_initiator.hex(),
            'encrypted_key_for_recipient': encrypted_for_recipient.hex(),
            'initiator_signature': initiator_signature.hex(),
            'created_at': session.created_at,
            'expires_at': session.expires_at
        }
    
    def get_session_key(
        self,
        session_id: str,
        user_id: str
    ) -> Optional[bytes]:
        """
        Get the session key for a user.
        
        Args:
            session_id: The session ID.
            user_id: The user requesting the key.
        
        Returns:
            bytes or None: The session key if user is authorized and session is valid.
        """
        session = self._sessions.get(session_id)
        
        if not session:
            return None
        
        # Check user is part of session
        if user_id not in (session.user1_id, session.user2_id):
            return None
            
        user = self._users.get(user_id)
        if not user:
            return None
            
        # Check if user's key is revoked
        if user.fingerprint in self.revoked_keys:
            return None
        
        # Check session hasn't expired
        if time.time() > session.expires_at:
            return None
        
        return session.session_key
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get session information.
        
        Args:
            session_id: The session ID.
        
        Returns:
            Session or None: The session if found.
        """
        return self._sessions.get(session_id)
    
    def get_user_sessions(self, user_id: str) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: The user's ID.
        
        Returns:
            list: List of active session IDs.
        """
        session_ids = self._user_sessions.get(user_id, [])
        now = time.time()
        
        # Filter to active sessions only
        active_sessions = []
        for sid in session_ids:
            session = self._sessions.get(sid)
            if session and session.expires_at > now:
                active_sessions.append({
                    'session_id': sid,
                    'peer_id': session.user2_id if session.user1_id == user_id else session.user1_id,
                    'created_at': session.created_at,
                    'expires_at': session.expires_at
                })
        
        return active_sessions
    
    def revoke_user_keys(self, user_id: str) -> None:
        """
        Revoke keys for a user by adding their fingerprint to revoked keys.
        
        Args:
            user_id: The user ID to revoke keys for.
        """
        user = self._users.get(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")
        
        # Add fingerprint to revoked keys
        self.revoked_keys.add(user.fingerprint)
        
        # Audit log
        self.audit_logs.append({
            'timestamp': time.time(),
            'action': 'revoke_user_keys',
            'user_id': user_id,
            'fingerprint': user.fingerprint.hex()
        })
        
        # Invalidate all sessions involving this user
        for session_id in list(self._sessions.keys()):
            session = self._sessions[session_id]
            if user_id in (session.user1_id, session.user2_id):
                self.revoke_session(session_id, user_id)

    def _rotate_session_key(self, session_id: str) -> None:
        """
        Rotate the session key for a session with session fixation protection.
        
        Args:
            session_id: The session ID to rotate.
        """
        session = self._sessions.get(session_id)
        if not session:
            return
            
        # Generate new session key
        new_session_key = generate_aes_key()
        
        # Generate new session ID to prevent fixation
        new_session_id = hashlib.sha256(
            f"{session.user1_id}:{session.user2_id}:{time.time()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()[:32]
        
        # Update session with new key, extended expiration, and new ID
        now = time.time()
        new_session = Session(
            session_id=new_session_id,
            user1_id=session.user1_id,
            user2_id=session.user2_id,
            session_key=new_session_key,
            created_at=now,
            expires_at=now + self._session_timeout
        )
        
        # Re-encrypt keys for both users
        initiator = self._users.get(new_session.user1_id)
        recipient = self._users.get(new_session.user2_id)
        
        if initiator and recipient:
            encrypted_for_initiator = encrypt_key(new_session_key, initiator.public_key)
            encrypted_for_recipient = encrypt_key(new_session_key, recipient.public_key)
            
            # Sign the encrypted keys (initiator signs)
            initiator_signature = sign(encrypted_for_recipient, initiator.private_key)
            
            # TODO: Implement notification to users about key rotation
            # This would typically involve WebSocket updates or API calls
            
            # Audit log
            self.audit_logs.append({
                'timestamp': now,
                'action': 'rotate_session_key',
                'old_session_id': session_id,
                'new_session_id': new_session_id,
                'new_expires_at': new_session.expires_at
            })
        
        # Store new session and update user session lists
        self._sessions[new_session_id] = new_session
        self._user_sessions[new_session.user1_id].append(new_session_id)
        self._user_sessions[new_session.user2_id].append(new_session_id)
        
        # Remove old session
        if session_id in self._sessions:
            del self._sessions[session_id]

    def revoke_session(self, session_id: str, user_id: str) -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: The session to revoke.
            user_id: The user revoking the session (must be participant).
        
        Returns:
            bool: True if session was revoked, False otherwise.
        """
        session = self._sessions.get(session_id)
        
        if not session:
            return False
        
        if user_id not in (session.user1_id, session.user2_id):
            return False
        
        # Remove session
        del self._sessions[session_id]
        
        # Remove from user session lists
        for uid in (session.user1_id, session.user2_id):
            if uid in self._user_sessions and session_id in self._user_sessions[uid]:
                self._user_sessions[uid].remove(session_id)
        
        # Audit log
        self.audit_logs.append({
            'timestamp': time.time(),
            'action': 'revoke_session',
            'session_id': session_id,
            'user_id': user_id
        })
        
        return True
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions.
        
        Returns:
            int: Number of sessions removed.
        """
        now = time.time()
        expired = [
            sid for sid, session in self._sessions.items()
            if session.expires_at <= now
        ]
        
        for sid in expired:
            session = self._sessions[sid]
            for uid in (session.user1_id, session.user2_id):
                if uid in self._user_sessions and sid in self._user_sessions[uid]:
                    self._user_sessions[uid].remove(sid)
            del self._sessions[sid]
            
            # Audit log
            self.audit_logs.append({
                'timestamp': now,
                'action': 'cleanup_expired_sessions',
                'session_id': sid
            })
        
        return len(expired)
    
    def decrypt_session_key_for_user(
        self,
        encrypted_key: bytes,
        user_id: str,
        sender_id: str = None
    ) -> Optional[bytes]:
        """
        Decrypt an encrypted session key for a user.
        
        Args:
            encrypted_key: The encrypted session key.
            user_id: The user whose private key should be used.
            sender_id: The ID of the user who sent the encrypted key.
        
        Returns:
            bytes or None: The decrypted session key if successful.
        """
        user = self._users.get(user_id)
        if not user:
            return None
            
        # Check if user's key is revoked
        if user.fingerprint in self.revoked_keys:
            return None
            
        # Check if sender's key is revoked
        if sender_id:
            sender_user = self._users.get(sender_id)
            if sender_user and sender_user.fingerprint in self.revoked_keys:
                return None
        
        try:
            decrypted_key = decrypt_key(encrypted_key, user.private_key)
            # Audit log
            self.audit_logs.append({
                'timestamp': time.time(),
                'action': 'decrypt_session_key',
                'user_id': user_id,
                'sender_id': sender_id
            })
            return decrypted_key
        except Exception:
            return None
    
    def verify_key_exchange_signature(
        self,
        encrypted_key: bytes,
        signature: bytes,
        sender_id: str
    ) -> bool:
        """
        Verify a key exchange signature.
        
        Args:
            encrypted_key: The encrypted session key.
            signature: The signature to verify.
            sender_id: The ID of the user who signed.
        
        Returns:
            bool: True if signature is valid.
        """
        sender = self._users.get(sender_id)
        if not sender:
            return False
            
        # Check if sender's key is revoked
        if sender.fingerprint in self.revoked_keys:
            return False
        
        return verify(encrypted_key, signature, sender.public_key)


# Singleton instance for the application
_key_manager_instance: Optional[KeyManager] = None


def get_key_manager() -> KeyManager:
    """
    Get the global KeyManager instance.
    
    Returns:
        KeyManager: The singleton KeyManager instance.
    """
    global _key_manager_instance
    if _key_manager_instance is None:
        _key_manager_instance = KeyManager()
    return _key_manager_instance


# Simple test when run directly
if __name__ == "__main__":
    print("Testing Key Manager implementation...")
    
    # Create key manager
    km = KeyManager()
    
    # Test 1: User registration
    print("\n1. Testing user registration:")
    alice = km.register_user("alice")
    bob = km.register_user("bob")
    print(f"   Alice registered: {alice['user_id']}")
    print(f"   Alice fingerprint: {alice['fingerprint'][:32]}...")
    print(f"   Bob registered: {bob['user_id']}")
    print("   ✓ Users registered successfully!")
    
    # Test 2: Duplicate registration
    print("\n2. Testing duplicate registration prevention:")
    try:
        km.register_user("alice")
        print("   ✗ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✓ Correctly rejected: {e}")
    
    # Test 3: Get public key
    print("\n3. Testing public key retrieval:")
    alice_pub = km.get_public_key("alice")
    assert alice_pub is not None
    assert b"BEGIN PUBLIC KEY" in alice_pub
    print("   ✓ Public key retrieved!")
    
    # Test 4: List users
    print("\n4. Testing user listing:")
    users = km.get_all_users()
    assert len(users) == 2
    print(f"   Found {len(users)} users: {[u['user_id'] for u in users]}")
    print("   ✓ User listing works!")
    
    # Test 5: Create session
    print("\n5. Testing session creation:")
    session = km.create_session("alice", "bob")
    print(f"   Session ID: {session['session_id']}")
    print(f"   Expires at: {session['expires_at']}")
    print("   ✓ Session created!")
    
    # Test 6: Get session key
    print("\n6. Testing session key retrieval:")
    alice_key = km.get_session_key(session['session_id'], "alice")
    bob_key = km.get_session_key(session['session_id'], "bob")
    assert alice_key == bob_key
    assert len(alice_key) == 32  # AES-256
    print(f"   Session key (hex): {alice_key.hex()[:32]}...")
    print("   ✓ Both users can access session key!")
    
    # Test 7: Unauthorized access
    print("\n7. Testing unauthorized session access:")
    km.register_user("eve")
    eve_key = km.get_session_key(session['session_id'], "eve")
    assert eve_key is None
    print("   ✓ Unauthorized user correctly denied!")
    
    # Test 8: Get user sessions
    print("\n8. Testing user session listing:")
    alice_sessions = km.get_user_sessions("alice")
    assert len(alice_sessions) == 1
    print(f"   Alice has {len(alice_sessions)} session(s)")
    print(f"   Peer: {alice_sessions[0]['peer_id']}")
    print("   ✓ User sessions listed!")
    
    # Test 9: Signature verification
    print("\n9. Testing key exchange signature verification:")
    encrypted_key = bytes.fromhex(session['encrypted_key_for_recipient'])
    signature = bytes.fromhex(session['initiator_signature'])
    is_valid = km.verify_key_exchange_signature(encrypted_key, signature, "alice")
    assert is_valid
    print("   ✓ Signature verified!")
    
    # Test 10: Session revocation
    print("\n10. Testing session revocation:")
    revoked = km.revoke_session(session['session_id'], "alice")
    assert revoked
    assert km.get_session_key(session['session_id'], "alice") is None
    print("   ✓ Session revoked!")
    
    # Test 11: Expired session cleanup
    print("\n11. Testing expired session cleanup:")
    # Create a session that's already expired
    km._sessions["expired_test"] = Session(
        session_id="expired_test",
        user1_id="alice",
        user2_id="bob",
        session_key=os.urandom(32),
        created_at=time.time() - 7200,
        expires_at=time.time() - 3600
    )
    cleaned = km.cleanup_expired_sessions()
    assert cleaned == 1
    print(f"   Cleaned {cleaned} expired session(s)")
    print("   ✓ Cleanup works!")
    
    print("\n" + "="*50)
    print("All Key Manager tests passed! ✓")
    def _rotate_session_key(self, session_id: str) -> None:
        """
        Rotate the session key for a session with session fixation protection.
        
        Args:
            session_id: The session ID to rotate.
        """
        session = self._sessions.get(session_id)
        if not session:
            return
            
        # Generate new session key
        new_session_key = generate_aes_key()
        
        # Generate new session ID to prevent fixation
        new_session_id = hashlib.sha256(
            f"{session.user1_id}:{session.user2_id}:{time.time()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()[:32]
        
        # Update session with new key, extended expiration, and new ID
        now = time.time()
        new_session = Session(
            session_id=new_session_id,
            user1_id=session.user1_id,
            user2_id=session.user2_id,
            session_key=new_session_key,
            created_at=now,
            expires_at=now + self._session_timeout
        )
        
        # Re-encrypt keys for both users
        initiator = self._users.get(new_session.user1_id)
        recipient = self._users.get(new_session.user2_id)
        
        if initiator and recipient:
            encrypted_for_initiator = encrypt_key(new_session_key, initiator.public_key)
            encrypted_for_recipient = encrypt_key(new_session_key, recipient.public_key)
            
            # Sign the encrypted keys (initiator signs)
            initiator_signature = sign(encrypted_for_recipient, initiator.private_key)
            
            # TODO: Implement notification to users about key rotation
            # This would typically involve WebSocket updates or API calls
            
            # Audit log
            self.audit_logs.append({
                'timestamp': now,
                'action': 'rotate_session_key',
                'old_session_id': session_id,
                'new_session_id': new_session_id,
                'new_expires_at': new_session.expires_at
            })
        
        # Store new session and update user session lists
        self._sessions[new_session_id] = new_session
        self._user_sessions[new_session.user1_id].append(new_session_id)
        self._user_sessions[new_session.user2_id].append(new_session_id)
        
        # Remove old session and rotation timer
        if session_id in self._sessions:
            del self._sessions[session_id]
        if session_id in self._rotation_timers:
            del self._rotation_timers[session_id]
    print("="*50)