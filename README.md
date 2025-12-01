# 🔐 SecureChat

**Web-based Secure Messaging Application with Attack Lab**

A comprehensive secure messaging platform featuring end-to-end encryption using industry-standard cryptographic primitives, real-time WebSocket communication, and an interactive Attack Lab for security demonstrations.

---

## 👥 Team Members

| Name | Student ID |
|------|------------|
| **Ali Asiri** | 202027780 |
| **Omar alshahrani** | 202040640 |

**Course:** ICS344 - Information Security  
**Project:** P15 — SecureChat: Web-based Secure Messaging App

---

## ✨ Features

### 🔒 End-to-End Encryption
- **AES-256-GCM** — Authenticated encryption for message confidentiality and integrity
- **Per-message IVs** — Fresh 96-bit initialization vector for each message

### ✍️ Digital Signatures
- **RSA-PSS (2048-bit)** — Message authentication and non-repudiation
- **SHA-256** — Secure hash algorithm with MGF1 padding

### 🔑 Secure Key Exchange
- **RSA-OAEP (2048-bit)** — Secure session key distribution
- **Key fingerprints** — Verify identities through secondary channels

### 📡 Real-Time Communication
- **WebSocket (Socket.IO)** — Instant message delivery
- **Presence indicators** — Online/offline status
- **Typing indicators** — Real-time feedback

### 🛡️ Security Defenses
- **Replay protection** — Timestamp and nonce validation
- **Rate limiting** — Token bucket algorithm for DoS protection
- **Tamper detection** — GCM authentication tags

### 🧪 Attack Lab
Interactive demonstrations of four security attacks and their defenses:
- Replay Attack
- Ciphertext Tampering
- Man-in-the-Middle Attack
- Denial of Service Attack

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python 3.10+, Flask 3.0+ |
| **Real-time** | Flask-SocketIO 5.3+ |
| **Cryptography** | cryptography 41.0+ |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+) |
| **WebCrypto** | Client-side encryption |

### Dependencies

```
flask>=3.0.0
flask-socketio>=5.3.0
flask-cors>=4.0.0
python-socketio>=5.10.0
cryptography>=41.0.0
python-dotenv>=1.0.0
eventlet>=0.34.0
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/securechat.git
cd securechat

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

### Access the Application

Open your browser and navigate to:
```
http://localhost:5000
```

### Command Line Options

```bash
python run.py --help

# Options:
#   --host HOST     Host to bind to (default: 0.0.0.0)
#   --port PORT     Port to bind to (default: 5000)
#   --debug         Enable debug mode
#   --no-reload     Disable auto-reload in debug mode
```

---

## 📁 Project Structure

```
SecureChat/
├── README.md                 # This file
├── ARCHITECTURE.md           # Detailed architecture documentation
├── requirements.txt          # Python dependencies
├── config.py                 # Application configuration
├── run.py                    # Application entry point
│
├── backend/                  # Flask backend
│   ├── __init__.py           # App factory
│   ├── app.py                # Main application
│   ├── config.py             # Backend config
│   ├── api/                  # REST API
│   │   ├── routes.py         # API endpoints
│   │   └── websocket.py      # WebSocket handlers
│   ├── crypto/               # Cryptographic modules
│   │   ├── aes_gcm.py        # AES-256-GCM encryption
│   │   ├── rsa_keys.py       # RSA key generation
│   │   ├── rsa_oaep.py       # RSA-OAEP key wrapping
│   │   └── rsa_pss.py        # RSA-PSS signatures
│   ├── models/               # Data models
│   │   └── message.py        # Message model
│   ├── services/             # Business logic
│   │   └── key_manager.py    # Key management
│   └── middleware/           # Request middleware
│       └── rate_limiter.py   # DoS protection
│
├── frontend/                 # Web frontend
│   ├── static/
│   │   ├── css/main.css      # Stylesheet
│   │   └── js/               # JavaScript modules
│   │       ├── crypto.js     # Client-side crypto
│   │       ├── chat.js       # Chat functionality
│   │       └── attack_lab.js # Attack Lab UI
│   └── templates/            # Jinja2 templates
│       ├── base.html         # Base template
│       ├── index.html        # Landing page
│       ├── chat.html         # Chat interface
│       └── attack_lab.html   # Attack Lab
│
├── attack_lab/               # Attack demonstrations
│   ├── routes.py             # Attack Lab API
│   ├── replay/               # Replay attack demo
│   ├── tampering/            # Tampering attack demo
│   ├── mitm/                 # MITM attack demo
│   └── dos/                  # DoS attack demo
│
└── docs/                     # Documentation
    ├── USER_GUIDE.md         # User guide
    └── API_REFERENCE.md      # API documentation
```

---

## 🔐 Security Features

### Encryption Algorithms

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Message Encryption | AES-256-GCM | 256-bit key, 96-bit IV, 128-bit tag |
| Key Exchange | RSA-OAEP | 2048-bit key, SHA-256, MGF1 |
| Digital Signatures | RSA-PSS | 2048-bit key, SHA-256, MGF1 |

### Defense Mechanisms

| Attack | Defense | Implementation |
|--------|---------|----------------|
| **Replay Attack** | Timestamp + Nonce | 5-minute window, unique nonce per message |
| **Ciphertext Tampering** | AES-GCM Auth Tag | 128-bit authentication tag |
| **MITM Attack** | RSA-PSS Signatures | Public key verification |
| **DoS Attack** | Rate Limiting | Token bucket (100 req/min API, 30 msg/min) |

### Message Format

```
┌──────────────────────────────────────────────────────────────┐
│                        MESSAGE PACKET                         │
├──────────────┬───────────────────────────────────────────────┤
│ Header       │ Version (1B) | Flags (1B) | Timestamp (8B)    │
│              │ Nonce (16B) | Sender ID (32B)                 │
├──────────────┼───────────────────────────────────────────────┤
│ Body         │ IV (12B) | Ciphertext (variable) | Tag (16B)  │
├──────────────┼───────────────────────────────────────────────┤
│ Signature    │ RSA-PSS Signature (256B)                      │
└──────────────┴───────────────────────────────────────────────┘
```

---

## 🧪 Attack Lab

The Attack Lab provides interactive demonstrations of security vulnerabilities and their defenses.

### Available Attacks

| Attack | Description | Defense |
|--------|-------------|---------|
| 🔄 **Replay** | Capture and resend valid messages | Timestamp + Nonce validation |
| ✏️ **Tampering** | Modify encrypted data in transit | AES-GCM authentication |
| 👤 **MITM** | Intercept key exchanges | RSA-PSS signatures |
| 💥 **DoS** | Flood server with requests | Token bucket rate limiting |

### Running Demos

1. Navigate to `http://localhost:5000/attack-lab`
2. Select an attack type from the tabs
3. Click **Run Attack (Vulnerable)** to see the attack succeed
4. Click **Run Attack (Defended)** to see the defense in action

### API Endpoints

```bash
# Get Attack Lab status
GET /api/attack-lab/status

# Run individual attacks
POST /api/attack-lab/replay      {"with_defense": false}
POST /api/attack-lab/tampering   {"with_defense": true}
POST /api/attack-lab/mitm        {"with_defense": false}
POST /api/attack-lab/dos         {"with_defense": true}

# Run all attacks
POST /api/attack-lab/run-all     {"with_defense": true}

# Compare attack with and without defense
GET /api/attack-lab/compare/replay
```

---

## 📸 Screenshots

### Login Page
![Login Screenshot Placeholder]
<!-- Screenshot: Landing page with SecureChat logo, login form, and Attack Lab link -->

### Chat Interface
![Chat Screenshot Placeholder]
<!-- Screenshot: Three-panel chat interface showing user list, messages, and security status -->

### Attack Lab
![Attack Lab Screenshot Placeholder]
<!-- Screenshot: Attack Lab interface showing side-by-side vulnerable and defended demos -->

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [USER_GUIDE.md](docs/USER_GUIDE.md) | User-friendly setup and usage instructions |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Complete API documentation for developers |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed system architecture and design |

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
HOST=0.0.0.0
PORT=5000
DEBUG=False
```

### Rate Limiting Configuration

```python
RATE_LIMITS = {
    "messages": "30 per minute",
    "key_exchange": "5 per minute",
    "api_general": "100 per minute"
}
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=html

# Run specific test file
pytest tests/unit/test_aes_gcm.py
```

---

## 📝 License

This project is developed for educational purposes as part of the ICS344 Information Security course at KFUPM.

---

## 🙏 Acknowledgments

- **King Fahd University of Petroleum & Minerals (KFUPM)**
- **ICS344 Course Instructors**
- **Python cryptography library maintainers**
- **Flask and Flask-SocketIO communities**

---

<p align="center">
  <strong>🔐 SecureChat — Secure Messaging Made Simple</strong>
  <br>
  <em>End-to-End Encrypted • Digitally Signed • Attack Resistant</em>
</p>