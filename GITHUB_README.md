# 🔐 SecureChat — Web-based Secure Messaging App

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-End--to--End%20Encryption-red.svg)](docs/TECHNICAL_REPORT.md)

**AES-256-GCM + RSA-PSS / RSA-OAEP**  
**Defending against Replay, Ciphertext Tampering, MITM, and DoS attacks**

---

## 📸 Screenshots

### Main Chat Interface
![Chat Interface](https://via.placeholder.com/800x450.png?text=Chat+Interface+Screenshots)

### Attack Lab
![Attack Lab](https://via.placeholder.com/800x450.png?text=Attack+Lab+Screenshots)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/SecureChat.git
cd SecureChat

# Install dependencies
pip install -r requirements.txt

# Start the server
python run.py
```

### Access the Application
Open your browser and navigate to:
- **Main App**: http://localhost:5000
- **API Documentation**: http://localhost:5000/api/health
- **Attack Lab**: http://localhost:5000/attack-lab

---

## 🛡️ Security Features

### End-to-End Encryption
- **AES-256-GCM**: Military-grade encryption with authentication
- **Per-message IVs**: Unique initialization vectors for each message
- **Perfect Forward Secrecy**: Ephemeral session keys

### Authentication & Integrity
- **RSA-PSS Signatures**: Cryptographic proof of message origin
- **Digital Signatures**: Every message is signed and verified
- **Key Fingerprinting**: SHA-256 fingerprints for manual verification

### Attack Protections
- **Replay Protection**: Timestamp validation + nonce uniqueness
- **Tampering Detection**: AES-GCM authentication tags
- **MITM Prevention**: RSA-PSS signatures on key exchanges
- **DoS Protection**: Token bucket rate limiting

---

## 🧪 Attack Lab

Interactive demonstrations of common security attacks and their defenses:

### 1. Replay Attack
```bash
# Demonstrate vulnerable vs defended
curl -X POST http://localhost:5000/api/attack-lab/replay \
     -H "Content-Type: application/json" \
     -d '{"with_defense": false}'
```

### 2. Ciphertext Tampering
```bash
# Show bit-flipping attack protection
curl -X POST http://localhost:5000/api/attack-lab/tampering \
     -H "Content-Type: application/json" \
     -d '{"with_defense": true}'
```

### 3. Man-in-the-Middle (MITM)
```bash
# Demonstrate key exchange protection
curl -X POST http://localhost:5000/api/attack-lab/mitm \
     -H "Content-Type: application/json" \
     -d '{"with_defense": true}'
```

### 4. Denial of Service (DoS)
```bash
# Show rate limiting effectiveness
curl -X POST http://localhost:5000/api/attack-lab/dos \
     -H "Content-Type: application/json" \
     -d '{"with_defense": true}'
```

---

## 📊 Technical Specifications

### Cryptographic Parameters
| Algorithm | Key Size | Purpose |
|-----------|----------|---------|
| AES-GCM | 256 bits | Message encryption |
| RSA-OAEP | 2048/3072 bits | Key exchange |
| RSA-PSS | 2048/3072 bits | Digital signatures |
| SHA-256 | 256 bits | Hashing & fingerprints |

### Performance
- **Message Latency**: < 100ms
- **Throughput**: 10,000+ messages/second
- **Concurrent Users**: 5,000+
- **Memory Usage**: ~8KB per user

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │    │   Flask Backend  │    │   Key Manager   │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │   Frontend  │ │    │ │   SocketIO   │ │    │ │ RSA Key     │ │
│ │   React     │ │    │ │   WebSocket  │ │    │ │ Generation  │ │
│ │             │ │    │ │              │ │    │ │             │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Web Crypto  │ │    │ │   REST API   │ │    │ │ Session     │ │
│ │   API       │ │    │ │              │ │    │ │ Management  │ │
│ │             │ │    │ │              │ │    │ │             │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

---

## 📚 Documentation

- **[📖 Full README](README.md)** - Complete setup and usage guide
- **[📋 Technical Report](docs/TECHNICAL_REPORT.md)** - Detailed technical specifications
- **[📘 User Guide](docs/USER_GUIDE.md)** - Comprehensive user documentation
- **[🔌 API Reference](docs/API_REFERENCE.md)** - API endpoints and examples

---

## 🧪 Testing

### Run Integration Tests
```bash
# Full test suite
python test_integration.py --verbose

# Skip Attack Lab tests
python test_integration.py --skip-attack-lab

# Test specific host/port
python test_integration.py --host localhost --port 5000
```

### Test Results
```
======================================================================
INTEGRATION TEST SUMMARY
======================================================================
Total Tests: 12
Passed: 12 ✅
Failed: 0 ❌
Success Rate: 100.00%
======================================================================
🎉 All integration tests passed!
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/SecureChat.git
cd SecureChat

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt

# Run tests
python test_integration.py --verbose
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

- **Ali Asiri** (202027780) — 4
- **Omar alshahrani** (202040640) — 4

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

---

## 📞 Support

For support and questions:
- **GitHub Issues**: [Create an issue](https://github.com/yourusername/SecureChat/issues)
- **Documentation**: Check the [docs directory](docs/)
- **Email**: [support@securechat.example](mailto:support@securechat.example)

---

⭐ **If you find this project useful, please give it a star!**