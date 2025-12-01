"""
SecureChat WebSocket Handlers

This module defines the WebSocket event handlers for real-time messaging:
- on_connect - Handle connection
- on_disconnect - Handle disconnection
- on_message - Handle encrypted message
- on_key_exchange - Handle key exchange
"""

import time
from typing import Dict, Set, Optional
from flask import request
from flask_socketio import emit, join_room, leave_room

from backend.app import socketio
from backend.services.key_manager import get_key_manager
from backend.models.message import Message
from backend.middleware.rate_limiter import get_rate_limiter


# Track connected users and their socket IDs
connected_users: Dict[str, str] = {}  # user_id -> socket_id
user_sockets: Dict[str, str] = {}      # socket_id -> user_id
user_rooms: Dict[str, Set[str]] = {}   # user_id -> set of room_ids

# Nonce cache for replay protection
nonce_cache: Dict[str, float] = {}  # nonce_hex -> timestamp
NONCE_CACHE_TTL = 600  # 10 minutes
MAX_NONCE_CACHE_SIZE = 10000


def cleanup_nonce_cache():
    """Remove expired nonces from the cache."""
    global nonce_cache
    now = time.time()
    expired = [nonce for nonce, ts in nonce_cache.items() if now - ts > NONCE_CACHE_TTL]
    for nonce in expired:
        del nonce_cache[nonce]


def is_nonce_used(nonce: bytes) -> bool:
    """Check if a nonce has been used recently."""
    nonce_hex = nonce.hex()
    return nonce_hex in nonce_cache


def mark_nonce_used(nonce: bytes):
    """Mark a nonce as used."""
    global nonce_cache
    
    # Cleanup if cache is too large
    if len(nonce_cache) >= MAX_NONCE_CACHE_SIZE:
        cleanup_nonce_cache()
    
    nonce_cache[nonce.hex()] = time.time()


@socketio.on('connect')
def handle_connect():
    """
    Handle client connection.
    
    The client should authenticate by sending a 'register' event
    with their user_id after connecting.
    """
    socket_id = request.sid
    client_ip = request.remote_addr or '127.0.0.1'
    
    # Check rate limit
    limiter = get_rate_limiter()
    if not limiter.is_allowed(client_ip, 'api_general'):
        emit('error', {
            'type': 'rate_limit',
            'message': 'Too many connection attempts'
        })
        return False
    
    print(f"[WebSocket] Client connected: {socket_id} from {client_ip}")
    
    emit('connected', {
        'socket_id': socket_id,
        'message': 'Connected to SecureChat. Please register with your user_id.'
    })
    
    return True


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    socket_id = request.sid
    
    # Find and remove user mapping
    user_id = user_sockets.get(socket_id)
    
    if user_id:
        print(f"[WebSocket] User disconnected: {user_id} ({socket_id})")
        
        # Clean up user mappings
        if user_id in connected_users:
            del connected_users[user_id]
        if socket_id in user_sockets:
            del user_sockets[socket_id]
        
        # Leave all rooms
        if user_id in user_rooms:
            for room in user_rooms[user_id]:
                leave_room(room)
            del user_rooms[user_id]
        
        # Notify other users
        emit('user_offline', {'user_id': user_id}, broadcast=True)
    else:
        print(f"[WebSocket] Unknown client disconnected: {socket_id}")


@socketio.on('register')
def handle_register(data: dict):
    """
    Register a connected socket with a user_id.
    
    Event data:
        {
            "user_id": "string"
        }
    
    Emits:
        - 'registered': On successful registration
        - 'error': On failure
    """
    socket_id = request.sid
    user_id = data.get('user_id')
    
    if not user_id:
        emit('error', {
            'type': 'validation_error',
            'message': 'user_id is required'
        })
        return
    
    # Verify user exists in key manager
    km = get_key_manager()
    if not km.get_user_keys(user_id):
        emit('error', {
            'type': 'user_not_found',
            'message': f"User '{user_id}' is not registered. Call /api/register first."
        })
        return
    
    # Check if user is already connected (kick old connection)
    if user_id in connected_users:
        old_socket = connected_users[user_id]
        if old_socket != socket_id:
            # Could emit disconnect to old socket
            print(f"[WebSocket] User {user_id} reconnecting (old: {old_socket})")
    
    # Register the user
    connected_users[user_id] = socket_id
    user_sockets[socket_id] = user_id
    user_rooms[user_id] = set()
    
    # Join user's personal room
    join_room(user_id)
    user_rooms[user_id].add(user_id)
    
    print(f"[WebSocket] User registered: {user_id} ({socket_id})")
    
    emit('registered', {
        'user_id': user_id,
        'message': f'Registered as {user_id}'
    })
    
    # Notify others that user is online
    emit('user_online', {'user_id': user_id}, broadcast=True, include_self=False)


@socketio.on('join_session')
def handle_join_session(data: dict):
    """
    Join a messaging session room.
    
    Event data:
        {
            "session_id": "string"
        }
    """
    socket_id = request.sid
    user_id = user_sockets.get(socket_id)
    
    if not user_id:
        emit('error', {
            'type': 'not_registered',
            'message': 'Please register first'
        })
        return
    
    session_id = data.get('session_id')
    if not session_id:
        emit('error', {
            'type': 'validation_error',
            'message': 'session_id is required'
        })
        return
    
    # Verify user is part of the session
    km = get_key_manager()
    session = km.get_session(session_id)
    
    if not session:
        emit('error', {
            'type': 'session_not_found',
            'message': 'Session not found'
        })
        return
    
    if user_id not in (session.user1_id, session.user2_id):
        emit('error', {
            'type': 'unauthorized',
            'message': 'Not authorized to join this session'
        })
        return
    
    # Join the session room
    join_room(session_id)
    user_rooms[user_id].add(session_id)
    
    emit('joined_session', {
        'session_id': session_id,
        'message': f'Joined session {session_id}'
    })
    
    print(f"[WebSocket] User {user_id} joined session {session_id}")


@socketio.on('leave_session')
def handle_leave_session(data: dict):
    """
    Leave a messaging session room.
    
    Event data:
        {
            "session_id": "string"
        }
    """
    socket_id = request.sid
    user_id = user_sockets.get(socket_id)
    
    if not user_id:
        return
    
    session_id = data.get('session_id')
    if session_id:
        leave_room(session_id)
        if user_id in user_rooms and session_id in user_rooms[user_id]:
            user_rooms[user_id].remove(session_id)
        
        emit('left_session', {
            'session_id': session_id
        })


@socketio.on('message')
def handle_message(data: dict):
    """
    Handle an encrypted message.
    
    Event data (message in dict format):
        {
            "session_id": "string",
            "message": {
                "version": int,
                "flags": int,
                "timestamp": int,
                "nonce": "hex",
                "sender_id": "hex",
                "iv": "hex",
                "ciphertext": "hex",
                "auth_tag": "hex",
                "signature": "hex",
                "recipient_id": "hex" (optional)
            }
        }
    
    Emits:
        - 'message': Broadcast to session room
        - 'message_sent': Confirmation to sender
        - 'error': On failure
    """
    socket_id = request.sid
    user_id = user_sockets.get(socket_id)
    client_ip = request.remote_addr or '127.0.0.1'
    
    if not user_id:
        emit('error', {
            'type': 'not_registered',
            'message': 'Please register first'
        })
        return
    
    # Rate limiting
    limiter = get_rate_limiter()
    if not limiter.is_allowed(client_ip, 'messages'):
        emit('error', {
            'type': 'rate_limit',
            'message': 'Message rate limit exceeded'
        })
        return
    
    # Validate required fields
    session_id = data.get('session_id')
    message_data = data.get('message')
    
    if not session_id or not message_data:
        emit('error', {
            'type': 'validation_error',
            'message': 'session_id and message are required'
        })
        return
    
    # Verify user is in the session
    km = get_key_manager()
    session = km.get_session(session_id)
    
    if not session:
        emit('error', {
            'type': 'session_not_found',
            'message': 'Session not found or expired'
        })
        return
    
    if user_id not in (session.user1_id, session.user2_id):
        emit('error', {
            'type': 'unauthorized',
            'message': 'Not authorized for this session'
        })
        return
    
    try:
        # Parse and validate message
        message = Message.from_dict(message_data)
        
        # Replay protection: Check timestamp
        if not message.validate_timestamp(window_seconds=300):
            emit('error', {
                'type': 'replay_detected',
                'message': 'Message timestamp is outside acceptable window'
            })
            return
        
        # Replay protection: Check nonce
        if is_nonce_used(message.nonce):
            emit('error', {
                'type': 'replay_detected',
                'message': 'Duplicate message nonce detected'
            })
            return
        
        # Mark nonce as used
        mark_nonce_used(message.nonce)
        
        # Determine recipient
        peer_id = session.user2_id if session.user1_id == user_id else session.user1_id
        
        # Broadcast message to session room (including recipient)
        emit('message', {
            'session_id': session_id,
            'sender_id': user_id,
            'message': message_data,
            'timestamp': time.time()
        }, room=session_id, include_self=False)
        
        # Also send directly to recipient's personal room if they're online
        if peer_id in connected_users:
            emit('message', {
                'session_id': session_id,
                'sender_id': user_id,
                'message': message_data,
                'timestamp': time.time()
            }, room=peer_id)
        
        # Confirm to sender
        emit('message_sent', {
            'session_id': session_id,
            'timestamp': time.time()
        })
        
        print(f"[WebSocket] Message from {user_id} in session {session_id}")
        
    except ValueError as e:
        emit('error', {
            'type': 'validation_error',
            'message': f'Invalid message format: {str(e)}'
        })
    except Exception as e:
        print(f"[WebSocket] Error handling message: {e}")
        emit('error', {
            'type': 'server_error',
            'message': 'Failed to process message'
        })


@socketio.on('key_exchange')
def handle_key_exchange(data: dict):
    """
    Handle key exchange events.
    
    This is used to notify the recipient when a new session is created.
    
    Event data:
        {
            "session_id": "string",
            "recipient_id": "string",
            "encrypted_key": "hex",
            "signature": "hex"
        }
    """
    socket_id = request.sid
    user_id = user_sockets.get(socket_id)
    client_ip = request.remote_addr or '127.0.0.1'
    
    if not user_id:
        emit('error', {
            'type': 'not_registered',
            'message': 'Please register first'
        })
        return
    
    # Rate limiting
    limiter = get_rate_limiter()
    if not limiter.is_allowed(client_ip, 'key_exchange'):
        emit('error', {
            'type': 'rate_limit',
            'message': 'Key exchange rate limit exceeded'
        })
        return
    
    session_id = data.get('session_id')
    recipient_id = data.get('recipient_id')
    encrypted_key = data.get('encrypted_key')
    signature = data.get('signature')
    
    if not all([session_id, recipient_id, encrypted_key, signature]):
        emit('error', {
            'type': 'validation_error',
            'message': 'Missing required fields'
        })
        return
    
    # Verify session exists and user is the initiator
    km = get_key_manager()
    session = km.get_session(session_id)
    
    if not session:
        emit('error', {
            'type': 'session_not_found',
            'message': 'Session not found'
        })
        return
    
    if session.user1_id != user_id:
        emit('error', {
            'type': 'unauthorized',
            'message': 'Only session initiator can send key exchange'
        })
        return
    
    if session.user2_id != recipient_id:
        emit('error', {
            'type': 'validation_error',
            'message': 'Recipient does not match session'
        })
        return
    
    # Send key exchange to recipient
    if recipient_id in connected_users:
        emit('key_exchange', {
            'session_id': session_id,
            'initiator_id': user_id,
            'encrypted_key': encrypted_key,
            'signature': signature
        }, room=recipient_id)
        
        emit('key_exchange_sent', {
            'session_id': session_id,
            'recipient_id': recipient_id
        })
        
        print(f"[WebSocket] Key exchange from {user_id} to {recipient_id}")
    else:
        emit('key_exchange_pending', {
            'session_id': session_id,
            'recipient_id': recipient_id,
            'message': 'Recipient is offline. They will receive the key when they connect.'
        })


@socketio.on('typing')
def handle_typing(data: dict):
    """
    Handle typing indicator.
    
    Event data:
        {
            "session_id": "string",
            "is_typing": bool
        }
    """
    socket_id = request.sid
    user_id = user_sockets.get(socket_id)
    
    if not user_id:
        return
    
    session_id = data.get('session_id')
    is_typing = data.get('is_typing', False)
    
    if session_id:
        emit('typing', {
            'user_id': user_id,
            'is_typing': is_typing
        }, room=session_id, include_self=False)


@socketio.on('ping')
def handle_ping():
    """Handle ping for connection keep-alive."""
    emit('pong', {'timestamp': time.time()})


# Helper function to get online status
def get_online_users() -> list:
    """Get list of currently online users."""
    return list(connected_users.keys())


def is_user_online(user_id: str) -> bool:
    """Check if a user is online."""
    return user_id in connected_users


def get_user_socket(user_id: str) -> Optional[str]:
    """Get the socket ID for a user."""
    return connected_users.get(user_id)