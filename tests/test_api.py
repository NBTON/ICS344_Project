"""
REST API Tests

Tests for all REST API endpoints:
- POST /api/register
- GET /api/users
- POST /api/keys/exchange
- GET /api/keys/public/<user_id>
- Error responses
"""

import json
import pytest

from backend.services.key_manager import KeyManager


@pytest.fixture
def fresh_client(app):
    """Create a fresh test client with reset key manager."""
    # Reset the key manager singleton for clean tests
    import backend.services.key_manager as km_module
    km_module._key_manager_instance = KeyManager()
    return app.test_client()


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self, fresh_client):
        """Test GET /api/health returns healthy status."""
        response = fresh_client.get('/api/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert data['service'] == 'SecureChat API'
        assert 'version' in data


class TestRegisterEndpoint:
    """Tests for user registration endpoint."""

    def test_register_user_success(self, fresh_client):
        """Test successful user registration."""
        response = fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = response.get_json()
        assert data['user_id'] == 'alice'
        assert 'public_key' in data
        assert 'fingerprint' in data

    def test_register_user_returns_public_key(self, fresh_client):
        """Test that registration returns valid PEM public key."""
        response = fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        data = response.get_json()
        assert data['public_key'].startswith('-----BEGIN PUBLIC KEY-----')

    def test_register_user_missing_user_id(self, fresh_client):
        """Test registration without user_id returns 400."""
        response = fresh_client.post(
            '/api/register',
            json={},
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_register_user_empty_user_id(self, fresh_client):
        """Test registration with empty user_id returns 400."""
        response = fresh_client.post(
            '/api/register',
            json={'user_id': ''},
            content_type='application/json'
        )
        
        assert response.status_code == 400

    def test_register_user_too_long_id(self, fresh_client):
        """Test registration with user_id > 64 chars returns 400."""
        long_id = 'a' * 65
        response = fresh_client.post(
            '/api/register',
            json={'user_id': long_id},
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'at most 64' in data['message']

    def test_register_duplicate_user(self, fresh_client):
        """Test registering duplicate user returns 409."""
        # First registration
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        # Duplicate registration
        response = fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        assert response.status_code == 409
        data = response.get_json()
        assert 'already registered' in data['message']

    def test_register_user_non_json(self, fresh_client):
        """Test registration without JSON content type returns 400."""
        response = fresh_client.post(
            '/api/register',
            data='user_id=alice'
        )
        
        assert response.status_code == 400


class TestUsersEndpoint:
    """Tests for users list endpoint."""

    def test_list_users_empty(self, fresh_client):
        """Test listing users when none registered."""
        response = fresh_client.get('/api/users')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['users'] == []
        assert data['count'] == 0

    def test_list_users_single(self, fresh_client):
        """Test listing single registered user."""
        # Register a user
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.get('/api/users')
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['users']) == 1
        assert data['count'] == 1
        assert data['users'][0]['user_id'] == 'alice'

    def test_list_users_multiple(self, fresh_client):
        """Test listing multiple registered users."""
        # Register users
        for name in ['alice', 'bob', 'charlie']:
            fresh_client.post(
                '/api/register',
                json={'user_id': name},
                content_type='application/json'
            )
        
        response = fresh_client.get('/api/users')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['count'] == 3
        user_ids = [u['user_id'] for u in data['users']]
        assert 'alice' in user_ids
        assert 'bob' in user_ids
        assert 'charlie' in user_ids

    def test_list_users_includes_fingerprint(self, fresh_client):
        """Test that user list includes fingerprints."""
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.get('/api/users')
        
        data = response.get_json()
        assert 'fingerprint' in data['users'][0]
        assert len(data['users'][0]['fingerprint']) == 64  # SHA-256 hex


class TestPublicKeyEndpoint:
    """Tests for public key retrieval endpoint."""

    def test_get_public_key_success(self, fresh_client):
        """Test getting user's public key."""
        # Register user
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.get('/api/keys/public/alice')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['user_id'] == 'alice'
        assert 'public_key' in data
        assert 'fingerprint' in data

    def test_get_public_key_pem_format(self, fresh_client):
        """Test that public key is in PEM format."""
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.get('/api/keys/public/alice')
        
        data = response.get_json()
        assert data['public_key'].startswith('-----BEGIN PUBLIC KEY-----')
        assert '-----END PUBLIC KEY-----' in data['public_key']

    def test_get_public_key_not_found(self, fresh_client):
        """Test getting public key for non-existent user returns 404."""
        response = fresh_client.get('/api/keys/public/nonexistent')
        
        assert response.status_code == 404
        data = response.get_json()
        assert 'Not Found' in data['error']


class TestKeyExchangeEndpoint:
    """Tests for key exchange endpoint."""

    def test_key_exchange_success(self, fresh_client):
        """Test successful key exchange."""
        # Register users
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        fresh_client.post(
            '/api/register',
            json={'user_id': 'bob'},
            content_type='application/json'
        )
        
        response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = response.get_json()
        assert 'session_id' in data
        assert 'encrypted_key_for_initiator' in data
        assert 'encrypted_key_for_recipient' in data
        assert 'initiator_signature' in data

    def test_key_exchange_missing_fields(self, fresh_client):
        """Test key exchange with missing fields returns 400."""
        response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice'},
            content_type='application/json'
        )
        
        assert response.status_code == 400

    def test_key_exchange_self_session(self, fresh_client):
        """Test key exchange with self returns 400."""
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'alice'},
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'yourself' in data['message']

    def test_key_exchange_invalid_initiator(self, fresh_client):
        """Test key exchange with invalid initiator returns 400."""
        fresh_client.post(
            '/api/register',
            json={'user_id': 'bob'},
            content_type='application/json'
        )
        
        response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'nonexistent', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        
        assert response.status_code == 400

    def test_key_exchange_invalid_recipient(self, fresh_client):
        """Test key exchange with invalid recipient returns 400."""
        fresh_client.post(
            '/api/register',
            json={'user_id': 'alice'},
            content_type='application/json'
        )
        
        response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'nonexistent'},
            content_type='application/json'
        )
        
        assert response.status_code == 400


class TestSessionInfoEndpoint:
    """Tests for session info endpoint."""

    def test_get_session_info_success(self, fresh_client):
        """Test getting session info as participant."""
        # Setup users and session
        fresh_client.post('/api/register', json={'user_id': 'alice'}, content_type='application/json')
        fresh_client.post('/api/register', json={'user_id': 'bob'}, content_type='application/json')
        
        exchange_response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        session_id = exchange_response.get_json()['session_id']
        
        response = fresh_client.get(f'/api/keys/session/{session_id}?user_id=alice')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['session_id'] == session_id
        assert data['user1_id'] == 'alice'
        assert data['user2_id'] == 'bob'

    def test_get_session_info_missing_user_id(self, fresh_client):
        """Test getting session info without user_id returns 400."""
        response = fresh_client.get('/api/keys/session/some_session_id')
        
        assert response.status_code == 400

    def test_get_session_info_not_found(self, fresh_client):
        """Test getting non-existent session returns 404."""
        response = fresh_client.get('/api/keys/session/nonexistent?user_id=alice')
        
        assert response.status_code == 404

    def test_get_session_info_unauthorized(self, fresh_client):
        """Test getting session info as non-participant returns 403."""
        # Setup users and session
        fresh_client.post('/api/register', json={'user_id': 'alice'}, content_type='application/json')
        fresh_client.post('/api/register', json={'user_id': 'bob'}, content_type='application/json')
        fresh_client.post('/api/register', json={'user_id': 'eve'}, content_type='application/json')
        
        exchange_response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        session_id = exchange_response.get_json()['session_id']
        
        response = fresh_client.get(f'/api/keys/session/{session_id}?user_id=eve')
        
        assert response.status_code == 403


class TestUserSessionsEndpoint:
    """Tests for user sessions endpoint."""

    def test_get_user_sessions_empty(self, fresh_client):
        """Test getting sessions for user with no sessions."""
        fresh_client.post('/api/register', json={'user_id': 'alice'}, content_type='application/json')
        
        response = fresh_client.get('/api/keys/sessions/alice')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['sessions'] == []
        assert data['count'] == 0

    def test_get_user_sessions_with_sessions(self, fresh_client):
        """Test getting sessions for user with active sessions."""
        # Reset key manager and rate limiter for this specific test
        import backend.services.key_manager as km_module
        import backend.middleware.rate_limiter as rl_module
        km_module._key_manager_instance = KeyManager()
        rl_module._rate_limiter_instance = rl_module.RateLimiter()
        
        fresh_client.post('/api/register', json={'user_id': 'alice'}, content_type='application/json')
        fresh_client.post('/api/register', json={'user_id': 'bob'}, content_type='application/json')
        
        exchange_resp = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        assert exchange_resp.status_code == 201, f"Exchange failed: {exchange_resp.get_json()}"
        
        response = fresh_client.get('/api/keys/sessions/alice')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['count'] == 1
        assert data['sessions'][0]['peer_id'] == 'bob'

    def test_get_user_sessions_not_found(self, fresh_client):
        """Test getting sessions for non-existent user returns 404."""
        response = fresh_client.get('/api/keys/sessions/nonexistent')
        
        assert response.status_code == 404


class TestRevokeSessionEndpoint:
    """Tests for session revocation endpoint."""

    def test_revoke_session_success(self, fresh_client):
        """Test successful session revocation."""
        # Reset key manager and rate limiter for this specific test
        import backend.services.key_manager as km_module
        import backend.middleware.rate_limiter as rl_module
        km_module._key_manager_instance = KeyManager()
        rl_module._rate_limiter_instance = rl_module.RateLimiter()
        
        # Setup
        fresh_client.post('/api/register', json={'user_id': 'alice'}, content_type='application/json')
        fresh_client.post('/api/register', json={'user_id': 'bob'}, content_type='application/json')
        
        exchange_response = fresh_client.post(
            '/api/keys/exchange',
            json={'initiator_id': 'alice', 'recipient_id': 'bob'},
            content_type='application/json'
        )
        assert exchange_response.status_code == 201, f"Exchange failed: {exchange_response.get_json()}"
        session_id = exchange_response.get_json()['session_id']
        
        response = fresh_client.delete(f'/api/keys/session/{session_id}?user_id=alice')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['session_id'] == session_id

    def test_revoke_session_missing_user_id(self, fresh_client):
        """Test revoking session without user_id returns 400."""
        response = fresh_client.delete('/api/keys/session/some_session_id')
        
        assert response.status_code == 400

    def test_revoke_session_not_found(self, fresh_client):
        """Test revoking non-existent session returns 404."""
        response = fresh_client.delete('/api/keys/session/nonexistent?user_id=alice')
        
        assert response.status_code == 404


class TestFrontendRoutes:
    """Tests for frontend page routes."""

    def test_index_page(self, fresh_client):
        """Test GET / returns index page."""
        response = fresh_client.get('/')
        
        assert response.status_code == 200
        # Should return HTML
        assert b'<!DOCTYPE html>' in response.data or b'<html' in response.data

    def test_chat_page(self, fresh_client):
        """Test GET /chat returns chat page."""
        response = fresh_client.get('/chat')
        
        assert response.status_code == 200

    def test_attack_lab_page(self, fresh_client):
        """Test GET /attack-lab returns attack lab page."""
        response = fresh_client.get('/attack-lab')
        
        assert response.status_code == 200