"""
SecureChat REST API Routes

This module defines the REST API endpoints for SecureChat:
- POST /api/register - Register new user, return public key
- GET /api/users - List registered users
- POST /api/keys/exchange - Exchange session keys
- GET /api/keys/public/<user_id> - Get user's public key

Frontend routes:
- GET / - Landing/login page
- GET /chat - Chat interface
- GET /attack-lab - Attack Lab interface
"""

from flask import Blueprint, request, jsonify, render_template
from functools import wraps

from backend.services.key_manager import get_key_manager
from backend.middleware.rate_limiter import get_rate_limiter


# Create API blueprint
api_bp = Blueprint('api', __name__)


def rate_limit(limit_type: str = 'api_general'):
    """
    Rate limiting decorator for API endpoints.
    
    Args:
        limit_type: Type of rate limit ('messages', 'key_exchange', 'api_general')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            limiter = get_rate_limiter()
            client_ip = request.remote_addr or '127.0.0.1'
            
            if not limiter.is_allowed(client_ip, limit_type):
                return jsonify({
                    'error': 'Too Many Requests',
                    'message': 'Rate limit exceeded. Please try again later.'
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_json(*required_fields):
    """
    Decorator to validate required JSON fields in request body.
    
    Args:
        *required_fields: Field names that must be present in the JSON body.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'error': 'Bad Request',
                    'message': 'Content-Type must be application/json'
                }), 400
            
            data = request.get_json()
            missing = [field for field in required_fields if field not in data]
            
            if missing:
                return jsonify({
                    'error': 'Bad Request',
                    'message': f'Missing required fields: {", ".join(missing)}'
                }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Health check endpoint
@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'SecureChat API',
        'version': '1.0.0'
    })


# User registration endpoint
@api_bp.route('/register', methods=['POST'])
@rate_limit('api_general')
@validate_json('user_id')
def register_user():
    """
    Register a new user and generate their RSA key pair.
    
    Request body:
        {
            "user_id": "string"
        }
    
    Response:
        {
            "user_id": "string",
            "public_key": "PEM-encoded public key",
            "fingerprint": "hex-encoded key fingerprint"
        }
    """
    data = request.get_json()
    user_id = data['user_id']
    
    # Validate user_id
    if not user_id or not isinstance(user_id, str):
        return jsonify({
            'error': 'Bad Request',
            'message': 'user_id must be a non-empty string'
        }), 400
    
    if len(user_id) > 64:
        return jsonify({
            'error': 'Bad Request',
            'message': 'user_id must be at most 64 characters'
        }), 400
    
    km = get_key_manager()
    
    try:
        result = km.register_user(user_id)
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({
            'error': 'Conflict',
            'message': str(e)
        }), 409


# List users endpoint
@api_bp.route('/users', methods=['GET'])
@rate_limit('api_general')
def list_users():
    """
    List all registered users.
    
    Response:
        {
            "users": [
                {
                    "user_id": "string",
                    "fingerprint": "hex-encoded key fingerprint",
                    "created_at": timestamp
                }
            ]
        }
    """
    km = get_key_manager()
    users = km.get_all_users()
    
    return jsonify({
        'users': users,
        'count': len(users)
    })


# Get public key endpoint
@api_bp.route('/keys/public/<user_id>', methods=['GET'])
@rate_limit('api_general')
def get_public_key(user_id: str):
    """
    Get a user's public key.
    
    Path parameters:
        user_id: The user's ID
    
    Response:
        {
            "user_id": "string",
            "public_key": "PEM-encoded public key",
            "fingerprint": "hex-encoded key fingerprint"
        }
    """
    km = get_key_manager()
    user_keys = km.get_user_keys(user_id)
    
    if not user_keys:
        return jsonify({
            'error': 'Not Found',
            'message': f"User '{user_id}' not found"
        }), 404
    
    return jsonify({
        'user_id': user_id,
        'public_key': user_keys.public_key_pem.decode('utf-8'),
        'fingerprint': user_keys.fingerprint.hex()
    })


# Key exchange endpoint
@api_bp.route('/keys/exchange', methods=['POST'])
@rate_limit('key_exchange')
@validate_json('initiator_id', 'recipient_id')
def exchange_keys():
    """
    Initiate a key exchange between two users.
    
    This creates a new session with a shared AES-256 key.
    
    Request body:
        {
            "initiator_id": "string",
            "recipient_id": "string"
        }
    
    Response:
        {
            "session_id": "string",
            "encrypted_key_for_initiator": "hex-encoded encrypted key",
            "encrypted_key_for_recipient": "hex-encoded encrypted key",
            "initiator_signature": "hex-encoded signature",
            "created_at": timestamp,
            "expires_at": timestamp
        }
    """
    data = request.get_json()
    initiator_id = data['initiator_id']
    recipient_id = data['recipient_id']
    
    # Validate IDs
    if initiator_id == recipient_id:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Cannot create session with yourself'
        }), 400
    
    km = get_key_manager()
    
    try:
        result = km.create_session(initiator_id, recipient_id)
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({
            'error': 'Bad Request',
            'message': str(e)
        }), 400


# Get session info endpoint
@api_bp.route('/keys/session/<session_id>', methods=['GET'])
@rate_limit('api_general')
def get_session_info(session_id: str):
    """
    Get information about a session.
    
    Query parameters:
        user_id: The requesting user's ID (for authorization)
    
    Response:
        {
            "session_id": "string",
            "user1_id": "string",
            "user2_id": "string",
            "created_at": timestamp,
            "expires_at": timestamp
        }
    """
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({
            'error': 'Bad Request',
            'message': 'user_id query parameter required'
        }), 400
    
    km = get_key_manager()
    session = km.get_session(session_id)
    
    if not session:
        return jsonify({
            'error': 'Not Found',
            'message': 'Session not found'
        }), 404
    
    # Check authorization
    if user_id not in (session.user1_id, session.user2_id):
        return jsonify({
            'error': 'Forbidden',
            'message': 'Not authorized to view this session'
        }), 403
    
    return jsonify({
        'session_id': session.session_id,
        'user1_id': session.user1_id,
        'user2_id': session.user2_id,
        'created_at': session.created_at,
        'expires_at': session.expires_at
    })


# Get user's sessions endpoint
@api_bp.route('/keys/sessions/<user_id>', methods=['GET'])
@rate_limit('api_general')
def get_user_sessions(user_id: str):
    """
    Get all active sessions for a user.
    
    Response:
        {
            "user_id": "string",
            "sessions": [
                {
                    "session_id": "string",
                    "peer_id": "string",
                    "created_at": timestamp,
                    "expires_at": timestamp
                }
            ]
        }
    """
    km = get_key_manager()
    
    # Verify user exists
    if not km.get_user_keys(user_id):
        return jsonify({
            'error': 'Not Found',
            'message': f"User '{user_id}' not found"
        }), 404
    
    sessions = km.get_user_sessions(user_id)
    
    return jsonify({
        'user_id': user_id,
        'sessions': sessions,
        'count': len(sessions)
    })


# Revoke session endpoint
@api_bp.route('/keys/session/<session_id>', methods=['DELETE'])
@rate_limit('api_general')
def revoke_session(session_id: str):
    """
    Revoke a session.
    
    Query parameters:
        user_id: The requesting user's ID (must be a participant)
    
    Response:
        {
            "message": "Session revoked",
            "session_id": "string"
        }
    """
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({
            'error': 'Bad Request',
            'message': 'user_id query parameter required'
        }), 400
    
    km = get_key_manager()
    
    if km.revoke_session(session_id, user_id):
        return jsonify({
            'message': 'Session revoked',
            'session_id': session_id
        })
    else:
        return jsonify({
            'error': 'Not Found',
            'message': 'Session not found or not authorized'
        }), 404


# Error handlers for the blueprint
@api_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': 'Bad Request',
        'message': str(error)
    }), 400


@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not Found',
        'message': str(error)
    }), 404


@api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500