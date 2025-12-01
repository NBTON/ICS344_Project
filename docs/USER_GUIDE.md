# SecureChat User Guide

Welcome to SecureChat — a web-based secure messaging application featuring end-to-end encryption and an interactive Attack Lab for security demonstrations.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Using SecureChat](#2-using-securechat)
3. [Attack Lab Tutorial](#3-attack-lab-tutorial)
4. [Troubleshooting](#4-troubleshooting)
5. [Security Best Practices](#5-security-best-practices)

---

## 1. Quick Start

Get SecureChat running in 5 minutes or less!

### Prerequisites

Before you begin, ensure you have the following installed:

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Python | 3.10 or higher | `python --version` |
| pip | Latest | `pip --version` |
| Git | Any recent version | `git --version` |

### Installation Steps

#### Step 1: Clone or Download the Project

```bash
# Clone using Git
git clone https://github.com/your-repo/securechat.git
cd securechat
```

Or download and extract the ZIP file from the repository.

#### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs the following packages:
- **Flask** — Web framework
- **Flask-SocketIO** — Real-time WebSocket communication
- **cryptography** — Cryptographic primitives (AES, RSA)
- **python-dotenv** — Environment configuration
- **eventlet** — Async networking library

#### Step 3: Run the Application

```bash
python run.py
```

You should see output similar to:

```
╔═══════════════════════════════════════════════════════════════╗
║                       SECURE CHAT                              ║
║           End-to-End Encrypted Messaging                       ║
╚═══════════════════════════════════════════════════════════════╝

  🔒 SecureChat Server Starting...
  📍 Address: http://0.0.0.0:5000
  🔧 Debug Mode: OFF
  🌐 API Endpoint: http://0.0.0.0:5000/api
  📡 WebSocket: ws://0.0.0.0:5000
```

#### Step 4: Access the Web Interface

Open your browser and navigate to:

```
http://localhost:5000
```

🎉 **You're ready to start secure messaging!**

---

## 2. Using SecureChat

### 2.1 Registration

1. On the landing page, enter your desired **username** (3-64 characters, alphanumeric and underscores)
2. Click the **Register** button
3. The system will:
   - Generate your RSA-2048 key pair
   - Create your encryption keys
   - Set up your secure identity

![Registration Screenshot Placeholder]
<!-- Screenshot: Login page with username field and Register/Login buttons -->

### 2.2 Login

If you've already registered:

1. Enter your **username**
2. Click the **Login** button
3. The system verifies your identity and restores your encryption keys

### 2.3 Selecting a Chat Partner

Once logged in, you'll see the chat interface with three panels:

| Panel | Location | Purpose |
|-------|----------|---------|
| **User List** | Left sidebar | Shows online users |
| **Chat Area** | Center | Message display and input |
| **Security Status** | Right sidebar | Encryption indicators |

To start a conversation:

1. Look at the **Online Users** panel on the left
2. Click on a user's name to select them
3. If needed, click **🔑 Exchange Keys** to establish a secure session

### 2.4 Sending Encrypted Messages

1. Select a chat partner from the user list
2. Type your message in the input field at the bottom
3. Press **Enter** or click **Send**
4. Your message is automatically:
   - Encrypted with AES-256-GCM
   - Signed with RSA-PSS
   - Protected with timestamp and nonce

![Chat Interface Screenshot Placeholder]
<!-- Screenshot: Main chat interface showing messages, user list, and security panel -->

### 2.5 Understanding the Security Status Panel

The right sidebar displays real-time security information:

#### Your Identity
- **User ID**: Your username
- **Key Fingerprint**: Unique identifier for your public key (used for verification)

#### Session Status
- **Session Key**: Shows if a secure session is established
  - 🟡 **Not established**: Need to exchange keys
  - 🟢 **Active**: Secure communication ready
- **Session ID**: Unique identifier for the current session
- **Expires**: When the session key will expire

#### Message Security
- **Encryption**: AES-256-GCM (shown in green when active)
- **Signatures**: RSA-PSS (shown in green when active)
- **Last Verified**: Timestamp of last signature verification

#### Connection
- **WebSocket**: Connection status to server
- **Latency**: Round-trip time to server

### 2.6 Verifying Encryption

To verify your conversation is truly secure:

1. Click **🔍 Verify Keys** in the Security Status panel
2. A modal will display:
   - Your key fingerprint
   - Partner's key fingerprint
   - Session verification code
3. Compare these values with your chat partner through another channel (phone call, in-person)
4. If they match, your conversation is secure against man-in-the-middle attacks

---

## 3. Attack Lab Tutorial

The Attack Lab provides interactive demonstrations of security vulnerabilities and their defenses.

### 3.1 Accessing the Attack Lab

1. From the landing page: Click **Enter Attack Lab**
2. From the chat interface: Click **Attack Lab** in the navigation bar
3. Direct URL: `http://localhost:5000/attack-lab`

### 3.2 Attack Lab Interface

The Attack Lab features four attack demonstrations:

| Attack | Icon | Description |
|--------|------|-------------|
| **Replay Attack** | 🔄 | Capturing and resending valid messages |
| **Ciphertext Tampering** | ✏️ | Modifying encrypted data in transit |
| **MITM Attack** | 👤 | Intercepting key exchanges |
| **DoS Attack** | 💥 | Flooding server with requests |

### 3.3 Running Attack Demonstrations

Each attack panel has two columns:

#### ⚠️ Without Defense (Vulnerable Mode)
- Shows what happens when security measures are disabled
- Attack typically **succeeds**
- Demonstrates the vulnerability

#### 🛡️ With Defense (Defended Mode)
- Shows SecureChat's protective measures in action
- Attack is **blocked**
- Demonstrates effective security

**To run a demonstration:**

1. Select an attack type using the tabs at the top
2. Read the attack description and how it works
3. Click **Run Attack (Vulnerable)** to see the attack succeed
4. Click **Run Attack (Defended)** to see the defense in action
5. Compare the logs and results

### 3.4 Understanding Attack Results

Each demonstration provides:

- **Status**: Current state (Ready, Running, Complete)
- **Log**: Step-by-step execution details
- **Result**: Success or failure indicator

#### Example: Replay Attack Demo

**Vulnerable Mode Log:**
```
[1] Alice sends encrypted message
[2] Attacker captures message packet
[3] Server receives and processes message
[4] Attacker replays captured message
[5] Server accepts duplicate message
❌ ATTACK SUCCEEDED - Message replayed
```

**Defended Mode Log:**
```
[1] Alice sends message with timestamp + nonce
[2] Attacker captures message packet
[3] Server validates timestamp and stores nonce
[4] Attacker replays captured message
[5] Server detects: Nonce already used!
✅ ATTACK BLOCKED - Replay detected
```

### 3.5 Attack Summary Table

At the bottom of the Attack Lab page, you'll find a summary table showing all attacks and their defense status:

| Attack Type | Threat | Defense | Status |
|-------------|--------|---------|--------|
| Replay Attack | Duplicate transactions | Timestamp + Nonce | ✅ Protected |
| Ciphertext Tampering | Message corruption | AES-256-GCM auth tag | ✅ Protected |
| MITM Attack | Message interception | RSA-PSS signatures | ✅ Protected |
| DoS Attack | Service unavailability | Token bucket rate limiting | ✅ Protected |

---

## 4. Troubleshooting

### Common Issues and Solutions

#### Port Already in Use

**Error:** `Address already in use` or `Port 5000 is already in use`

**Solution:**
```bash
# Option 1: Use a different port
python run.py --port 8080

# Option 2: Find and stop the process using port 5000
# On Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# On Linux/Mac:
lsof -i :5000
kill -9 <PID>
```

#### WebSocket Connection Failed

**Symptoms:** 
- Messages not sending
- "Connecting..." status never changes
- Real-time updates not working

**Solutions:**
1. Ensure you're using a modern browser (Chrome, Firefox, Edge, Safari)
2. Check if a firewall is blocking WebSocket connections
3. Try refreshing the page
4. Clear browser cache and cookies

#### Registration Failed

**Symptoms:**
- "User already exists" error
- Registration hangs

**Solutions:**
1. Try a different username
2. Clear localStorage: Open browser console (F12) → Application → Local Storage → Clear
3. Restart the server

#### Keys Not Working

**Symptoms:**
- Messages fail to encrypt/decrypt
- "Invalid signature" errors

**Solutions:**
1. Click **🔄 Rotate Session Key** in the Security Status panel
2. Have your chat partner do the same
3. Re-establish the key exchange

### Browser Compatibility

SecureChat works best with:

| Browser | Minimum Version | Status |
|---------|-----------------|--------|
| Chrome | 60+ | ✅ Full Support |
| Firefox | 55+ | ✅ Full Support |
| Edge | 79+ | ✅ Full Support |
| Safari | 11+ | ✅ Full Support |
| Internet Explorer | Any | ❌ Not Supported |

### Server Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 512 MB | 1 GB |
| CPU | 1 core | 2+ cores |
| Storage | 100 MB | 500 MB |
| Network | Any | Low latency |

---

## 5. Security Best Practices

### Key Management Tips

1. **Verify Key Fingerprints**
   - Always verify fingerprints through a secondary channel
   - Don't trust keys received only through the internet

2. **Protect Your Session**
   - Log out when done (especially on shared computers)
   - Don't share your username with untrusted parties

3. **Keep Software Updated**
   - Update your browser regularly
   - Keep Python and dependencies updated

### Safe Usage Guidelines

#### Do's ✅
- Use strong, unique usernames
- Verify chat partner fingerprints
- Check the Security Status panel regularly
- Report any suspicious behavior
- Use on trusted networks when possible

#### Don'ts ❌
- Don't share screenshots of fingerprints publicly
- Don't ignore security warnings
- Don't use on untrusted public computers
- Don't leave sessions open unattended
- Don't disable any security features

### Understanding SecureChat's Security

SecureChat implements multiple layers of security:

| Layer | Technology | Protection |
|-------|------------|------------|
| **Message Encryption** | AES-256-GCM | Confidentiality |
| **Key Exchange** | RSA-2048-OAEP | Secure key distribution |
| **Digital Signatures** | RSA-PSS | Authentication & Integrity |
| **Replay Protection** | Timestamp + Nonce | Freshness |
| **DoS Protection** | Rate Limiting | Availability |

### Limitations to Be Aware Of

1. **No Forward Secrecy**: If session keys are compromised, past messages in that session could be decrypted
2. **Trust in Server**: The server handles key distribution; use fingerprint verification
3. **Local Storage**: Keys stored in browser; clear when on shared devices
4. **Metadata**: Server can see who is communicating (but not message content)

---

## Getting Help

If you encounter issues not covered in this guide:

1. Check the [ARCHITECTURE.md](./ARCHITECTURE.md) for technical details
2. Review the [API_REFERENCE.md](./API_REFERENCE.md) for developer information
3. Open an issue on the project repository

---

*Document Version: 1.0*  
*Last Updated: December 2024*  
*Project: SecureChat - ICS344 Security Project*