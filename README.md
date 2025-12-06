# SecureChat — Web-based Secure Messaging App

**AES-256-GCM + RSA-PSS / RSA-OAEP**  
**Defending against Replay, Ciphertext Tampering, MITM, and DoS attacks**

---

## 📋 Project Overview

SecureChat is a web-based secure messaging application that demonstrates industry-standard cryptographic protocols and attack defense mechanisms. This project implements end-to-end encryption with comprehensive security measures against common network attacks.

### 🎯 Project Objectives

- **Confidentiality**: AES-256-GCM encryption with per-message IVs and session keys
- **Integrity & Authentication**: RSA-PSS digital signatures for message authentication
- **Key Exchange**: RSA-OAEP for secure session key distribution
- **Attack Defense**: Comprehensive protections against Replay, Ciphertext Tampering, MITM, and DoS attacks
- **User Experience**: Modern web interface with real-time messaging and interactive Attack Lab

### 👥 Group Members

- **Member 1**: Ali Asiri (202027780) — 4
- **Member 2**: Omar alshahrani (202040640) — 4

---

## 🛠️ Technical Stack

### Backend
- **Language**: Python 3.8+
- **Framework**: Flask with SocketIO
- **Cryptography**: cryptography library (AES-256-GCM, RSA-2048/3072, RSA-PSS, RSA-OAEP)
- **WebSocket**: Flask-SocketIO for real-time communication

### Frontend
- **Framework**: Pure HTML/CSS/JavaScript (no frameworks)
- **Real-time**: Socket.IO client
- **Cryptography**: Web Crypto API for client-side operations
- **UI**: Responsive design with Bootstrap-like styling

### Security Features
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Exchange**: RSA-OAEP (2048/3072-bit)
- **Signatures**: RSA-PSS with SHA-256
- **Session Management**: Time-based session keys with rotation
- **Rate Limiting**: Token bucket algorithm for DoS protection

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SecureChat
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment**
   ```bash
   # Copy environment configuration
   cp .env.example .env
   
   # Optional: Edit .env to customize settings
   ```

### Running the Application

1. **Start the server**
   ```bash
   python run.py
   ```

2. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`
   - The application will automatically start on port 5000

3. **Default configuration**
   - **Host**: 0.0.0.0 (accessible from network)
   - **Port**: 5000
   - **Debug**: False (set to True in .env for development)

### Command Line Options

```bash
python run.py --host 127.0.0.1 --port 8080 --debug
```

Available options:
- `--host`: Server host (default: 0.0.0.0)
- `--port`: Server port (default: 5000)
- `--debug`: Enable debug mode
- `--no-reload`: Disable auto-reload in debug mode

---

## 📖 User Guide

### Registration and Login

1. **New User Registration**
   - Navigate to the homepage
   - Enter a username (3-64 characters, alphanumeric + underscores)
   - Click "Register"
   - The system will generate your RSA key pair automatically
   - Your public key fingerprint will be displayed

2. **Returning User Login**
   - Enter your existing username
   - Click "Login"
   - Your keys will be restored from local storage

### Key Management

- **Automatic Key Generation**: RSA-2048 key pairs are generated automatically
- **Key Storage**: Keys are stored securely in your browser's localStorage
- **Key Fingerprint**: Each user has a unique SHA-256 fingerprint for key verification
- **Key Rotation**: Session keys are rotated automatically for enhanced security

### Messaging Features

1. **Starting a Conversation**
   - Select a user from the online users list
   - Click "Exchange Keys" to establish a secure session
   - Once keys are exchanged, the session is ready for messaging

2. **Sending Messages**
   - Type your message in the input field
   - Press Enter or click Send
   - Messages are automatically encrypted with AES-256-GCM
   - Each message is signed with your RSA-PSS private key

3. **Message Security Features**
   - **End-to-End Encryption**: Only you and the recipient can read messages
   - **Message Authentication**: RSA-PSS signatures ensure message integrity
   - **Replay Protection**: Timestamps and nonces prevent replay attacks
   - **Perfect Forward Secrecy**: Session keys are ephemeral

### Security Status Panel

The right sidebar shows your current security status:
- **User Identity**: Your username and key fingerprint
- **Session Status**: Active session information and expiration
- **Encryption**: AES-256-GCM status
- **Signatures**: RSA-PSS status
- **Connection**: WebSocket connection status and latency

### Key Verification

To verify your conversation partner's identity:
1. Click "Verify Keys" in the security panel
2. Compare the fingerprint with your partner through a secure channel
3. If fingerprints match, your conversation is secure

---

## 🧪 Attack Lab

The Attack Lab is an interactive demonstration of common security attacks and their defenses.

### Accessing the Attack Lab

1. Click "Attack Lab" in the navigation bar
2. The Attack Lab interface will open
3. Select an attack type to demonstrate

### Available Attacks

#### 1. Replay Attack
**Description**: Demonstrates capturing and replaying valid encrypted messages

**Vulnerable Scenario**:
- Attacker captures a valid encrypted message
- Replays it multiple times to cause duplicate actions
- Without protection, server accepts each replay as new

**Defense Demonstration**:
- Timestamp validation (5-minute window)
- Nonce uniqueness tracking
- Replay cache with automatic expiration

#### 2. Ciphertext Tampering
**Description**: Demonstrates modifying encrypted data in transit

**Vulnerable Scenario**:
- Attacker intercepts encrypted message
- Modifies ciphertext bytes (bit-flipping attacks)
- Without authentication, corrupted data may be accepted

**Defense Demonstration**:
- AES-GCM authenticated encryption
- Authentication tag verification
- Cryptographic integrity checking

#### 3. Man-in-the-Middle (MITM)
**Description**: Demonstrates intercepting and manipulating key exchanges

**Vulnerable Scenario**:
- Attacker intercepts key exchange between users
- Substitutes fake public keys
- Can decrypt all subsequent communications

**Defense Demonstration**:
- RSA-PSS digital signatures
- Public key authentication
- Signature verification during key exchange

#### 4. Denial of Service (DoS)
**Description**: Demonstrates flooding server with requests

**Vulnerable Scenario**:
- Attacker floods server with thousands of requests
- Server becomes overwhelmed and unresponsive
- Legitimate users cannot access the service

**Defense Demonstration**:
- Token bucket rate limiting
- Connection limits per IP
- Request timeout enforcement

### Running Attack Demonstrations

1. **Individual Attack Demo**
   ```bash
   # Via API
   curl -X POST http://localhost:5000/api/attack-lab/replay \
        -H "Content-Type: application/json" \
        -d '{"with_defense": false}'
   ```

2. **Compare Vulnerable vs Defended**
   ```bash
   # Get comparison for any attack
   curl http://localhost:5000/api/attack-lab/compare/replay
   ```

3. **Run All Attacks**
   ```bash
   # Via API
   curl -X POST http://localhost:5000/api/attack-lab/run-all \
        -H "Content-Type: application/json" \
        -d '{"with_defense": true}'
   ```

---

## 🔧 API Reference

### Authentication Endpoints

#### POST /api/register
Register a new user and generate RSA key pair.

**Request Body**:
```json
{
  "user_id": "string"
}
```

**Response**:
```json
{
  "user_id": "string",
  "public_key": "PEM-encoded public key",
  "fingerprint": "hex-encoded key fingerprint"
}
```

#### GET /api/users
List all registered users.

**Response**:
```json
{
  "users": [
    {
      "user_id": "string",
      "fingerprint": "hex",
      "created_at": timestamp,
      "revoked": boolean
    }
  ],
  "count": number
}
```

### Key Management Endpoints

#### POST /api/keys/exchange
Initiate key exchange between two users.

**Request Body**:
```json
{
  "initiator_id": "string",
  "recipient_id": "string"
}
```

**Response**:
```json
{
  "session_id": "string",
  "encrypted_key_for_initiator": "hex",
  "encrypted_key_for_recipient": "hex",
  "initiator_signature": "hex",
  "created_at": timestamp,
  "expires_at": timestamp
}
```

#### GET /api/keys/public/{user_id}
Get a user's public key.

**Response**:
```json
{
  "user_id": "string",
  "public_key": "PEM-encoded public key",
  "fingerprint": "hex"
}
```

#### POST /api/keys/rotate-session
Rotate session key with specified expiration.

**Request Body**:
```json
{
  "user_id": "string",
  "session_id": "string",
  "expiration_minutes": number
}
```

### Messaging Endpoints

#### WebSocket Events
- `register`: Register socket with user ID
- `join_session`: Join a messaging session room
- `message`: Send encrypted message
- `key_exchange`: Handle key exchange
- `typing`: Send typing indicator

---

## 🏗️ Architecture

### System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │    │   Flask Backend  │    │   Key Manager   │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │   React     │ │    │ │   SocketIO   │ │    │ │ RSA Key     │ │
│ │   App       │ │◄──►│ │   WebSocket  │ │◄──►│ │ Generation  │ │
│ │             │ │    │ │              │ │    │ │             │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Web Crypto  │ │    │ │   REST API   │ │    │ │ Session     │ │
│ │   API       │ │◄──►│ │              │ │◄──►│ │ Management  │ │
│ │             │ │    │ │              │ │    │ │             │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Security Protocol Flow

1. **User Registration**
   ```
   User → Register → Backend → Generate RSA Key Pair → Store Keys
   ```

2. **Key Exchange**
   ```
   Alice → Request Exchange → Bob
   Bob → Generate Session Key → Encrypt with Alice's Public Key
   Bob → Send Encrypted Key + Signature → Alice
   Alice → Decrypt + Verify → Establish Session
   ```

3. **Secure Messaging**
   ```
   Alice → Encrypt Message (AES-256-GCM) → Sign (RSA-PSS) → Bob
   Bob → Verify Signature → Decrypt Message → Display
   ```

### Message Format

```
┌─────────────────────────────────────────────────────────┐
│                        Message                            │
├─────────────────┬─────────────────┬─────────────────────┤
│   Header (58B)  │   Body (var)    │   Trailer (256B)    │
├─────────────────┼─────────────────┼─────────────────────┤
│ Version │ Flags │   Timestamp     │   Signature (RSA)   │
│ (1B)    │ (1B)  │     (8B)        │      (256B)         │
├─────────────────┼─────────────────┤                     │
│     Nonce       │       IV        │                     │
│     (16B)       │     (12B)       │                     │
├─────────────────┼─────────────────┤                     │
│   Sender ID     │   Ciphertext    │                     │
│     (32B)       │     (var)       │                     │
├─────────────────┤                 │                     │
│       IV        │                 │                     │
│     (12B)       │                 │                     │
├─────────────────┤                 ├─────────────────────┤
│   Ciphertext    │                 │   Auth Tag (16B)    │
│     (var)       │                 │                     │
├─────────────────┤                 ├─────────────────────┤
│   Auth Tag      │                 │                     │
│     (16B)       │                 │                     │
└─────────────────┴─────────────────┴─────────────────────┘
```

### Cryptographic Protocol

#### Key Exchange (RSA-OAEP)
```
Session Key (32B) + OAEP Padding → RSA-2048 Encryption → Ciphertext
```

#### Message Encryption (AES-256-GCM)
```
Plaintext + IV + AAD → AES-256-GCM → Ciphertext + Auth Tag
```

#### Digital Signatures (RSA-PSS)
```
Message Hash + Salt + PSS Padding → RSA-2048 → Signature
```

---

## 🛡️ Security Features

### Defense Mechanisms

#### 1. Replay Attack Protection
- **Timestamp Validation**: 5-minute window for message acceptance
- **Nonce Uniqueness**: Per-message random nonces stored in cache
- **Replay Cache**: Automatic expiration of used nonces
- **Implementation**: Nonce cache with TTL in WebSocket handler

#### 2. Ciphertext Tampering Protection
- **Authenticated Encryption**: AES-256-GCM provides built-in authentication
- **Authentication Tags**: 16-byte tags verify message integrity
- **Tamper Detection**: Invalid tags cause immediate rejection
- **Implementation**: GCM mode in cryptography library

#### 3. MITM Attack Protection
- **Digital Signatures**: RSA-PSS signatures on all key exchanges
- **Public Key Authentication**: Signature verification during key exchange
- **Key Fingerprinting**: SHA-256 fingerprints for manual verification
- **Implementation**: PSS padding with salt in RSA operations

#### 4. DoS Attack Protection
- **Rate Limiting**: Token bucket algorithm per IP address
- **Request Limits**: Different limits for different endpoints
- **Connection Management**: WebSocket connection limits
- **Implementation**: Custom rate limiter middleware

### Cryptographic Parameters

#### AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - recommended for GCM
- **Tag Size**: 128 bits (16 bytes)
- **Nonce**: 96 bits random per message
- **AAD**: Associated data for additional authentication

#### RSA-2048/3072
- **Key Size**: 2048 bits (default) or 3072 bits
- **Padding**: OAEP with SHA-256 and MGF1
- **Signature**: PSS with SHA-256 and maximum salt length
- **Security**: 112-bit security (2048) or 128-bit security (3072)

#### Hash Functions
- **SHA-256**: For fingerprints, message digests, and AAD
- **HMAC-SHA-256**: For message authentication (conceptual)
- **PBKDF2**: For key derivation (if needed)

### Session Management

#### Session Lifecycle
1. **Creation**: Key exchange generates session key
2. **Usage**: Key encrypts/decrypts messages in session
3. **Rotation**: Automatic key rotation every hour
4. **Expiration**: Sessions expire after timeout
5. **Revocation**: Manual session termination

#### Security Measures
- **Ephemeral Keys**: Session keys are temporary
- **Perfect Forward Secrecy**: Compromised keys don't affect past sessions
- **Key Rotation**: Automatic rotation prevents long-term exposure
- **Session Isolation**: Each session has unique keys

---

## 🧪 Testing

### Running Tests

1. **Unit Tests**
   ```bash
   # Run all tests
   pytest
   
   # Run specific test modules
   pytest tests/test_crypto.py
   pytest tests/test_api.py
   pytest tests/test_key_manager.py
   ```

2. **Integration Tests**
   ```bash
   pytest tests/test_integration.py
   ```

3. **Attack Lab Tests**
   ```bash
   pytest tests/test_attack_lab.py
   ```

### Test Coverage

- **Cryptography**: AES-GCM, RSA-OAEP, RSA-PSS implementations
- **API Endpoints**: REST API functionality and error handling
- **WebSocket**: Real-time communication and message handling
- **Key Management**: User registration, key exchange, session management
- **Attack Lab**: All attack demonstrations and defenses
- **Frontend**: Client-side encryption and UI interactions

### Manual Testing

1. **Multi-User Testing**
   - Open multiple browser windows/tabs
   - Register different users in each
   - Test messaging between users

2. **Attack Lab Testing**
   - Navigate to Attack Lab interface
   - Run each attack type with and without defenses
   - Verify defense mechanisms work correctly

3. **Security Testing**
   - Test message tampering detection
   - Verify replay attack prevention
   - Test rate limiting effectiveness

---

## 🚨 Security Considerations

### Production Deployment

#### Environment Configuration
```bash
# .env file for production
DEBUG=False
SECRET_KEY=your-production-secret-key
HOST=0.0.0.0
PORT=443
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

#### Security Hardening
1. **HTTPS Only**: Use SSL/TLS certificates for encryption
2. **Secure Headers**: Add security headers (HSTS, CSP, etc.)
3. **Input Validation**: Sanitize all user inputs
4. **Error Handling**: Don't expose sensitive information in errors
5. **Logging**: Monitor for suspicious activities
6. **Firewall**: Configure firewall rules for port access

#### Key Management
1. **Secure Storage**: Use HSM or encrypted key storage
2. **Key Rotation**: Implement automatic key rotation
3. **Backup**: Secure backup of critical keys
4. **Access Control**: Limit access to key management systems

### Known Limitations

1. **In-Memory Storage**: Keys stored in memory (for demo purposes)
2. **No Certificate Pinning**: Browser certificates not pinned
3. **WebSocket Security**: WebSocket connection could be enhanced
4. **Client Trust**: Browser security model assumed trusted
5. **Network Security**: Assumes secure network transport

### Security Best Practices

1. **Regular Updates**: Keep dependencies updated
2. **Code Review**: Regular security code reviews
3. **Penetration Testing**: Regular security assessments
4. **Monitoring**: Real-time security monitoring
5. **Incident Response**: Plan for security incidents

---

## 🤝 Contributing

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone <your-fork-url>
   cd SecureChat
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install Development Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # If available
   ```

4. **Code Style**
   - Follow PEP 8 for Python code
   - Use meaningful variable names
   - Add docstrings to all functions and classes
   - Write clear, concise comments

5. **Testing**
   - Write tests for new features
   - Ensure all tests pass before submitting
   - Update documentation for any API changes

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with proper commits
3. Run tests and ensure they pass
4. Update documentation if needed
5. Create a pull request with detailed description
6. Address review comments and make necessary changes

---

## 📚 Additional Documentation

### Technical Report
For detailed technical specifications, threat models, and implementation details, refer to the technical report in the `docs/` directory.

### API Documentation
Complete API documentation is available in `docs/API_REFERENCE.md`.

### User Guide
Detailed user guide with screenshots is available in `docs/USER_GUIDE.md`.

---

## 📞 Support

### Getting Help

1. **Documentation**: Check this README and the docs directory
2. **Issues**: Report bugs or request features via GitHub Issues
3. **Email**: Contact the development team (see project documentation)

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
lsof -i :5000  # Linux/Mac
netstat -ano | findstr :5000  # Windows

# Kill the process or use different port
python run.py --port 8080
```

#### Dependencies Issues
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Check Python version
python --version
```

#### Browser Issues
- Clear browser cache and localStorage
- Try incognito/private browsing mode
- Check browser console for JavaScript errors

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Course Instructors**: For guidance and support
- **Open Source Community**: For excellent libraries and tools
- **Security Researchers**: Whose work inspired these implementations

---

## 🔗 Related Resources

- [AES-GCM Standard (NIST)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RSA-OAEP Specification (RFC 3447)](https://tools.ietf.org/html/rfc3447)
- [RSA-PSS Specification (RFC 3447)](https://tools.ietf.org/html/rfc3447)
- [WebSocket Security](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers)
- [OWASP Security Guidelines](https://owasp.org/)

---

**© 2024 SecureChat Project. All rights reserved.**

*For educational purposes only. Not for production use without additional security review.*