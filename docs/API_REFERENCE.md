# SecureChat API Reference

This document provides complete API documentation for developers integrating with or extending SecureChat.

---

## Table of Contents

1. [Overview](#1-overview)
2. [REST API Endpoints](#2-rest-api-endpoints)
3. [WebSocket Events](#3-websocket-events)
4. [Attack Lab API](#4-attack-lab-api)
5. [Data Formats](#5-data-formats)
6. [Error Handling](#6-error-handling)
7. [Rate Limiting](#7-rate-limiting)

---

## 1. Overview

### Base URL

```
http://localhost:5000
```

### API Prefix

All REST API endpoints are prefixed with `/api`:

```
http://localhost:5000/api
```

### Content Type

All API requests and responses use JSON:

```
Content-Type: application/json
```

### Authentication

Currently, SecureChat uses user ID-based identification. Include the `user_id` in request bodies or query parameters as specified for each endpoint.

---

## 2. REST API Endpoints

### 2.1 Health Check

Check if the API is operational.

```http
GET /api/health
```

#### Response

```json
{
  "status": "healthy",
  "service": "SecureChat API",
  "version": "1.0.0"
}
```

---

### 2.2 User Registration

Register a new user and generate their RSA key pair.

```http
POST /api/register
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | string | Yes | Unique username (3-64 characters) |

#### Example Request

```json
{
  "user_id": "alice"
}
```

#### Success Response (201 Created)

```json
{
  "user_id": "alice",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
  "fingerprint": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
}
```

#### Error Responses

| Status | Description |
|--------|-------------|
| 400 | Invalid user_id (empty, too long, or invalid format) |
| 409 | User already exists |
| 429 | Rate limit exceeded |

---

### 2.3 List Users

Get all registered users.

```http
GET /api/users
```

#### Success Response (200 OK)

```json
{
  "users": [
    {
      "user_id": "alice",
      "fingerprint": "a1b2c3d4...",
      "created_at": 1701445200.123
    },
    {
      "user_id": "bob",
      "fingerprint": "b2c3d4e5...",
      "created_at": 1701445300.456
    }
  ],
  "count": 2
}
```

---

### 2.4 Get Public Key

Retrieve a user's public key for encryption.

```http
GET /api/keys/public/{user_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | string | The user's ID |

#### Success Response (200 OK)

```json
{
  "user_id": "alice",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
  "fingerprint": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
}
```

#### Error Response (404 Not Found)

```json
{
  "error": "Not Found",
  "message": "User 'unknown_user' not found"
}
```

---

### 2.5 Key Exchange

Initiate a key exchange to create a secure session between two users.

```http
POST /api/keys/exchange
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `initiator_id` | string | Yes | ID of the user initiating the exchange |
| `recipient_id` | string | Yes | ID of the user receiving the exchange |

#### Example Request

```json
{
  "initiator_id": "alice",
  "recipient_id": "bob"
}
```

#### Success Response (201 Created)

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "encrypted_key_for_initiator": "a1b2c3d4...",
  "encrypted_key_for_recipient": "b2c3d4e5...",
  "initiator_signature": "c3d4e5f6...",
  "created_at": 1701445400.789,
  "expires_at": 1701449000.789
}
```

#### Error Responses

| Status | Description |
|--------|-------------|
| 400 | Invalid request (same user, missing fields) |
| 400 | User not found |
| 429 | Rate limit exceeded |

---

### 2.6 Get Session Info

Get information about an existing session.

```http
GET /api/keys/session/{session_id}?user_id={user_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | The session's unique ID |

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | Requesting user's ID (for authorization) |

#### Success Response (200 OK)

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user1_id": "alice",
  "user2_id": "bob",
  "created_at": 1701445400.789,
  "expires_at": 1701449000.789
}
```

#### Error Responses

| Status | Description |
|--------|-------------|
| 400 | Missing user_id query parameter |
| 403 | User not authorized to view session |
| 404 | Session not found |

---

### 2.7 Get User Sessions

Get all active sessions for a user.

```http
GET /api/keys/sessions/{user_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | string | The user's ID |

#### Success Response (200 OK)

```json
{
  "user_id": "alice",
  "sessions": [
    {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "peer_id": "bob",
      "created_at": 1701445400.789,
      "expires_at": 1701449000.789
    }
  ],
  "count": 1
}
```

---

### 2.8 Revoke Session

Revoke/delete an existing session.

```http
DELETE /api/keys/session/{session_id}?user_id={user_id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | The session's unique ID |

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | Requesting user's ID (must be a participant) |

#### Success Response (200 OK)

```json
{
  "message": "Session revoked",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

## 3. WebSocket Events

SecureChat uses Socket.IO for real-time communication. Connect to the WebSocket server at the same base URL.

### Connection URL

```javascript
const socket = io('http://localhost:5000');
```

---

### 3.1 Client → Server Events

#### `register`

Register the socket connection with a user ID.

```javascript
socket.emit('register', {
  user_id: 'alice'
});
```

**Response Events:**
- `registered` — Success
- `error` — Failure

---

#### `join_session`

Join a messaging session room.

```javascript
socket.emit('join_session', {
  session_id: '550e8400-e29b-41d4-a716-446655440000'
});
```

**Response Events:**
- `joined_session` — Success
- `error` — Failure

---

#### `leave_session`

Leave a messaging session room.

```javascript
socket.emit('leave_session', {
  session_id: '550e8400-e29b-41d4-a716-446655440000'
});
```

**Response Events:**
- `left_session` — Success

---

#### `message`

Send an encrypted message.

```javascript
socket.emit('message', {
  session_id: '550e8400-e29b-41d4-a716-446655440000',
  message: {
    version: 1,
    flags: 3,
    timestamp: 1701445500000,
    nonce: 'a1b2c3d4e5f6789012345678901234567',
    sender_id: 'a1b2c3d4...',
    iv: 'f6789012345678901234',
    ciphertext: 'encrypted_data_here...',
    auth_tag: 'gcm_auth_tag_here...',
    signature: 'rsa_pss_signature_here...'
  }
});
```

**Response Events:**
- `message_sent` — Confirmation to sender
- `error` — Failure (validation, replay detected, etc.)

---

#### `key_exchange`

Notify recipient of a new session key.

```javascript
socket.emit('key_exchange', {
  session_id: '550e8400-e29b-41d4-a716-446655440000',
  recipient_id: 'bob',
  encrypted_key: 'rsa_oaep_encrypted_key...',
  signature: 'rsa_pss_signature...'
});
```

**Response Events:**
- `key_exchange_sent` — Success (recipient online)
- `key_exchange_pending` — Recipient offline
- `error` — Failure

---

#### `typing`

Send typing indicator.

```javascript
socket.emit('typing', {
  session_id: '550e8400-e29b-41d4-a716-446655440000',
  is_typing: true
});
```

---

#### `ping`

Keep-alive ping.

```javascript
socket.emit('ping');
```

**Response Events:**
- `pong` — Server response with timestamp

---

### 3.2 Server → Client Events

#### `connected`

Received upon initial connection.

```javascript
socket.on('connected', (data) => {
  console.log(data.socket_id);
  console.log(data.message);
});
```

```json
{
  "socket_id": "abc123...",
  "message": "Connected to SecureChat. Please register with your user_id."
}
```

---

#### `registered`

Successful registration.

```javascript
socket.on('registered', (data) => {
  console.log(`Registered as ${data.user_id}`);
});
```

```json
{
  "user_id": "alice",
  "message": "Registered as alice"
}
```

---

#### `user_online`

Another user came online.

```javascript
socket.on('user_online', (data) => {
  console.log(`${data.user_id} is now online`);
});
```

---

#### `user_offline`

A user went offline.

```javascript
socket.on('user_offline', (data) => {
  console.log(`${data.user_id} is now offline`);
});
```

---

#### `joined_session`

Successfully joined a session.

```javascript
socket.on('joined_session', (data) => {
  console.log(`Joined session ${data.session_id}`);
});
```

---

#### `message`

Received an encrypted message.

```javascript
socket.on('message', (data) => {
  console.log(`Message from ${data.sender_id}`);
  console.log(data.message); // Encrypted message object
  console.log(data.timestamp);
});
```

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "sender_id": "alice",
  "message": {
    "version": 1,
    "flags": 3,
    "timestamp": 1701445500000,
    "nonce": "a1b2c3d4...",
    "sender_id": "a1b2c3d4...",
    "iv": "f6789012...",
    "ciphertext": "...",
    "auth_tag": "...",
    "signature": "..."
  },
  "timestamp": 1701445500.123
}
```

---

#### `message_sent`

Confirmation that message was sent.

```javascript
socket.on('message_sent', (data) => {
  console.log(`Message sent to session ${data.session_id}`);
});
```

---

#### `key_exchange`

Received a key exchange notification.

```javascript
socket.on('key_exchange', (data) => {
  console.log(`Key exchange from ${data.initiator_id}`);
  // Decrypt the encrypted_key using your private key
  // Verify the signature using initiator's public key
});
```

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "initiator_id": "alice",
  "encrypted_key": "rsa_oaep_encrypted_key...",
  "signature": "rsa_pss_signature..."
}
```

---

#### `typing`

Typing indicator from chat partner.

```javascript
socket.on('typing', (data) => {
  if (data.is_typing) {
    showTypingIndicator(data.user_id);
  } else {
    hideTypingIndicator(data.user_id);
  }
});
```

---

#### `error`

Error notification.

```javascript
socket.on('error', (data) => {
  console.error(`Error: ${data.type} - ${data.message}`);
});
```

**Error Types:**
- `rate_limit` — Too many requests
- `validation_error` — Invalid data format
- `not_registered` — Socket not registered
- `user_not_found` — User doesn't exist
- `session_not_found` — Session doesn't exist
- `unauthorized` — Not authorized for action
- `replay_detected` — Replay attack detected
- `server_error` — Internal server error

---

#### `pong`

Response to ping.

```javascript
socket.on('pong', (data) => {
  const latency = Date.now() - pingStartTime;
  console.log(`Latency: ${latency}ms`);
});
```

---

## 4. Attack Lab API

The Attack Lab provides endpoints for running security demonstrations.

### Base URL

```
/api/attack-lab
```

---

### 4.1 Get Status

Get Attack Lab status and available attacks.

```http
GET /api/attack-lab/status
```

#### Response

```json
{
  "status": "ready",
  "version": "1.0.0",
  "attacks": {
    "replay": {
      "name": "Replay Attack",
      "description": "Demonstrates capturing and resending valid encrypted messages",
      "endpoint": "/api/attack-lab/replay",
      "defense": "Timestamp + Nonce validation"
    },
    "tampering": {
      "name": "Ciphertext Tampering",
      "description": "Demonstrates modifying encrypted data in transit",
      "endpoint": "/api/attack-lab/tampering",
      "defense": "AES-GCM authentication tag"
    },
    "mitm": {
      "name": "Man-in-the-Middle",
      "description": "Demonstrates intercepting and manipulating key exchanges",
      "endpoint": "/api/attack-lab/mitm",
      "defense": "RSA-PSS digital signatures"
    },
    "dos": {
      "name": "Denial of Service",
      "description": "Demonstrates flooding server with requests",
      "endpoint": "/api/attack-lab/dos",
      "defense": "Token bucket rate limiting"
    }
  }
}
```

---

### 4.2 Replay Attack Demo

Run replay attack demonstration.

```http
POST /api/attack-lab/replay
```

#### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `with_defense` | boolean | No | false | Enable replay protection |

#### Example Requests

**Vulnerable Mode:**
```json
{
  "with_defense": false
}
```

**Defended Mode:**
```json
{
  "with_defense": true
}
```

#### Response

```json
{
  "attack_type": "replay",
  "with_defense": false,
  "attack_success": true,
  "steps": [
    {
      "step": 1,
      "action": "Alice sends encrypted message",
      "status": "success"
    },
    {
      "step": 2,
      "action": "Attacker captures message",
      "status": "success"
    },
    {
      "step": 3,
      "action": "Attacker replays message",
      "status": "success"
    },
    {
      "step": 4,
      "action": "Server accepts duplicate",
      "status": "success"
    }
  ],
  "logs": [
    "[*] Generating test message...",
    "[*] Encrypting with AES-256-GCM...",
    "[!] Attacker captures packet",
    "[!] Attacker replays packet",
    "[!] Server accepted replay - ATTACK SUCCEEDED"
  ],
  "summary": "Replay attack succeeded. Message was accepted twice."
}
```

---

### 4.3 Tampering Attack Demo

Run ciphertext tampering demonstration.

```http
POST /api/attack-lab/tampering
```

#### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `with_defense` | boolean | No | false | Enable GCM authentication |

#### Response

```json
{
  "attack_type": "tampering",
  "with_defense": true,
  "attack_success": false,
  "steps": [
    {
      "step": 1,
      "action": "Encrypt message with AES-GCM",
      "status": "success"
    },
    {
      "step": 2,
      "action": "Attacker modifies ciphertext",
      "status": "success"
    },
    {
      "step": 3,
      "action": "Recipient decrypts message",
      "status": "failed"
    }
  ],
  "logs": [
    "[*] Original message: 'Transfer $100 to Bob'",
    "[*] Encrypting with AES-256-GCM...",
    "[!] Attacker flips bits in ciphertext",
    "[*] Attempting decryption...",
    "[+] Authentication tag verification FAILED",
    "[+] Tampering detected - ATTACK BLOCKED"
  ],
  "summary": "Tampering attack blocked. GCM authentication tag detected modification."
}
```

---

### 4.4 MITM Attack Demo

Run Man-in-the-Middle attack demonstration.

```http
POST /api/attack-lab/mitm
```

#### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `with_defense` | boolean | No | false | Enable signature verification |

---

### 4.5 DoS Attack Demo

Run Denial of Service attack demonstration.

```http
POST /api/attack-lab/dos
```

#### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `with_defense` | boolean | No | false | Enable rate limiting |

---

### 4.6 Run All Attacks

Run all four attack demonstrations.

```http
POST /api/attack-lab/run-all
```

#### Request Body

```json
{
  "with_defense": true
}
```

#### Response

```json
{
  "with_defense": true,
  "results": {
    "replay": { ... },
    "tampering": { ... },
    "mitm": { ... },
    "dos": { ... }
  },
  "summary": {
    "total_attacks": 4,
    "attacks_succeeded": 0,
    "attacks_blocked": 4,
    "defense_effective": true
  }
}
```

---

### 4.7 Compare Attack

Run an attack with and without defense for comparison.

```http
GET /api/attack-lab/compare/{attack_type}
```

#### Path Parameters

| Parameter | Type | Valid Values |
|-----------|------|--------------|
| `attack_type` | string | `replay`, `tampering`, `mitm`, `dos` |

#### Response

```json
{
  "attack_type": "replay",
  "vulnerable": {
    "attack_success": true,
    "summary": "Attack succeeded",
    "steps": [...]
  },
  "defended": {
    "attack_success": false,
    "summary": "Attack blocked",
    "steps": [...]
  },
  "comparison": {
    "vulnerable_attack_succeeds": true,
    "defended_attack_blocked": true,
    "defense_effective": true
  }
}
```

---

## 5. Data Formats

### 5.1 Message Structure

The encrypted message format used in WebSocket communication:

```json
{
  "version": 1,
  "flags": 3,
  "timestamp": 1701445500000,
  "nonce": "a1b2c3d4e5f6789012345678901234567",
  "sender_id": "sha256_hash_of_public_key",
  "iv": "12_byte_hex_string",
  "ciphertext": "variable_length_hex_string",
  "auth_tag": "16_byte_hex_string",
  "signature": "256_byte_hex_string",
  "recipient_id": "optional_recipient_hash"
}
```

#### Field Details

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `version` | integer | 1 byte | Protocol version (currently 1) |
| `flags` | integer | 1 byte | Bit flags (see below) |
| `timestamp` | integer | 8 bytes | Unix timestamp in milliseconds |
| `nonce` | hex string | 16 bytes | Random nonce for replay protection |
| `sender_id` | hex string | 32 bytes | SHA-256 of sender's public key |
| `iv` | hex string | 12 bytes | AES-GCM initialization vector |
| `ciphertext` | hex string | variable | Encrypted message content |
| `auth_tag` | hex string | 16 bytes | AES-GCM authentication tag |
| `signature` | hex string | 256 bytes | RSA-PSS signature |
| `recipient_id` | hex string | 32 bytes | Optional recipient identifier |

#### Flag Bits

| Bit | Name | Description |
|-----|------|-------------|
| 0 | Encrypted | Message is encrypted (always 1) |
| 1 | Signed | Message is signed (always 1) |
| 2 | Compressed | Content is compressed |
| 3 | Key Exchange | This is a key exchange message |
| 4-7 | Reserved | Reserved for future use |

---

### 5.2 Key Exchange Structure

```json
{
  "session_id": "uuid-string",
  "encrypted_key_for_initiator": "hex-encoded RSA-OAEP encrypted AES key",
  "encrypted_key_for_recipient": "hex-encoded RSA-OAEP encrypted AES key",
  "initiator_signature": "hex-encoded RSA-PSS signature",
  "created_at": 1701445400.789,
  "expires_at": 1701449000.789
}
```

---

### 5.3 User Structure

```json
{
  "user_id": "string",
  "public_key": "PEM-encoded RSA public key",
  "fingerprint": "hex-encoded SHA-256 of public key",
  "created_at": 1701445200.123
}
```

---

### 5.4 Session Structure

```json
{
  "session_id": "uuid-string",
  "user1_id": "string",
  "user2_id": "string",
  "created_at": 1701445400.789,
  "expires_at": 1701449000.789
}
```

---

## 6. Error Handling

### 6.1 HTTP Error Responses

All error responses follow this format:

```json
{
  "error": "Error Type",
  "message": "Human-readable error description"
}
```

### 6.2 HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful GET, DELETE |
| 201 | Created | Successful POST (resource created) |
| 400 | Bad Request | Invalid input, missing fields |
| 403 | Forbidden | Not authorized for resource |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource already exists |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |

### 6.3 WebSocket Error Events

```javascript
socket.on('error', (data) => {
  // data.type - Error category
  // data.message - Error description
});
```

---

## 7. Rate Limiting

SecureChat implements rate limiting to protect against abuse.

### 7.1 Rate Limits

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| General API | 100 requests | per minute |
| Messages | 30 messages | per minute |
| Key Exchange | 5 exchanges | per minute |

### 7.2 Rate Limit Response

When rate limited, you receive:

**HTTP:**
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Please try again later."
}
```

**WebSocket:**
```json
{
  "type": "rate_limit",
  "message": "Message rate limit exceeded"
}
```

### 7.3 Best Practices

1. Implement exponential backoff on 429 responses
2. Cache user lists and public keys locally
3. Batch operations where possible
4. Use WebSocket for real-time updates instead of polling

---

## Code Examples

### JavaScript: Complete Chat Flow

```javascript
// 1. Register user
async function registerUser(userId) {
  const response = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId })
  });
  return response.json();
}

// 2. Connect WebSocket
const socket = io('http://localhost:5000');

socket.on('connect', () => {
  socket.emit('register', { user_id: 'alice' });
});

socket.on('registered', (data) => {
  console.log('Registered:', data.user_id);
});

// 3. Exchange keys
async function exchangeKeys(initiatorId, recipientId) {
  const response = await fetch('/api/keys/exchange', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      initiator_id: initiatorId,
      recipient_id: recipientId
    })
  });
  return response.json();
}

// 4. Send message
function sendMessage(sessionId, encryptedMessage) {
  socket.emit('message', {
    session_id: sessionId,
    message: encryptedMessage
  });
}

// 5. Receive messages
socket.on('message', (data) => {
  console.log('Message from:', data.sender_id);
  // Decrypt data.message using session key
});
```

### Python: API Client

```python
import requests
import socketio

BASE_URL = 'http://localhost:5000'

# REST API
def register_user(user_id: str) -> dict:
    response = requests.post(
        f'{BASE_URL}/api/register',
        json={'user_id': user_id}
    )
    response.raise_for_status()
    return response.json()

def get_public_key(user_id: str) -> dict:
    response = requests.get(f'{BASE_URL}/api/keys/public/{user_id}')
    response.raise_for_status()
    return response.json()

def exchange_keys(initiator_id: str, recipient_id: str) -> dict:
    response = requests.post(
        f'{BASE_URL}/api/keys/exchange',
        json={
            'initiator_id': initiator_id,
            'recipient_id': recipient_id
        }
    )
    response.raise_for_status()
    return response.json()

# WebSocket
sio = socketio.Client()

@sio.on('connected')
def on_connect(data):
    print(f"Connected: {data['socket_id']}")
    sio.emit('register', {'user_id': 'alice'})

@sio.on('registered')
def on_registered(data):
    print(f"Registered as: {data['user_id']}")

@sio.on('message')
def on_message(data):
    print(f"Message from {data['sender_id']}")

sio.connect(BASE_URL)
```

---

*Document Version: 1.0*  
*Last Updated: December 2024*  
*Project: SecureChat - ICS344 Security Project*