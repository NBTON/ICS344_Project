/**
 * SecureChat - Key Management Dashboard
 * 
 * Handles:
 * - User registration and public key display
 * - Active session management
 * - Key status visualization
 * - RSA key pair generation
 * - Key rotation and revocation
 * - Real-time updates via WebSocket
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize dashboard
    initDashboard();
    
    // Load initial data
    loadPublicKeys();
    loadSessions();
    updateKeyStatusCounts();
    
    // Setup WebSocket for real-time updates
    setupWebSocket();
});

// DOM Elements
const elements = {
    registerUserBtn: document.getElementById('register-user-btn'),
    newUserIdInput: document.getElementById('new-user-id'),
    registrationStatus: document.getElementById('registration-status'),
    publicKeysList: document.getElementById('public-keys-list'),
    sessionsList: document.getElementById('sessions-list'),
    activeKeysCount: document.getElementById('active-keys-count'),
    expiredKeysCount: document.getElementById('expired-keys-count'),
    revokedKeysCount: document.getElementById('revoked-keys-count'),
    generateKeysBtn: document.getElementById('generate-keys-btn'),
    rotateKeysBtn: document.getElementById('rotate-keys-btn'),
    revokeKeysBtn: document.getElementById('revoke-keys-btn'),
    rotationExpirationInput: document.getElementById('rotation-expiration'),
    rotateSessionBtn: document.getElementById('rotate-session-btn'),
    rotationStatus: document.getElementById('rotation-status'),
    nextRotationTime: document.getElementById('next-rotation-time'),
    confirmationModal: document.getElementById('confirmation-modal'),
    confirmationMessage: document.getElementById('confirmation-message'),
    confirmProceed: document.getElementById('confirm-proceed'),
    confirmCancel: document.getElementById('confirm-cancel')
};

// Dashboard State
const state = {
    currentUserId: localStorage.getItem('securechat_user_id') || null,
    socket: null,
    users: [] // Cache for users data
};

// Initialize Dashboard
function initDashboard() {
    // Event Listeners
    elements.registerUserBtn?.addEventListener('click', handleUserRegistration);
    elements.generateKeysBtn?.addEventListener('click', handleGenerateKeys);
    elements.rotateKeysBtn?.addEventListener('click', handleRotateKeys);
    elements.revokeKeysBtn?.addEventListener('click', handleRevokeKeys);
    elements.rotateSessionBtn?.addEventListener('click', handleRotateSessionKey);
    
    // Modal Handlers
    elements.confirmProceed?.addEventListener('click', () => {
        elements.confirmationModal.style.display = 'none';
        state.pendingAction?.();
    });
    
    elements.confirmCancel?.addEventListener('click', () => {
        elements.confirmationModal.style.display = 'none';
        state.pendingAction = null;
    });
    
    // Close modal when clicking overlay
    elements.confirmationModal?.querySelector('.modal-overlay')?.addEventListener('click', () => {
        elements.confirmationModal.style.display = 'none';
        state.pendingAction = null;
    });
}

// User Registration
async function handleUserRegistration() {
    const userId = elements.newUserIdInput?.value.trim();
    if (!userId) {
        showStatus('Please enter a user ID', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Registration failed');
        
        localStorage.setItem('securechat_user_id', userId);
        state.currentUserId = userId;
        
        showStatus(`User ${userId} registered successfully! Public key fingerprint: ${data.fingerprint}`, 'success');
        loadPublicKeys();
        loadSessions();
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
    }
}

// Public Key Management
async function loadPublicKeys() {
    try {
        const response = await fetch('/api/users');
        const data = await response.json();
        if (!response.ok) throw new Error('Failed to load users');
        
        state.users = data.users;
        elements.publicKeysList.innerHTML = '';
        
        data.users.forEach(user => {
            const userEl = document.createElement('div');
            userEl.className = 'user-key-item';
            userEl.innerHTML = `
                <span class="user-id">${user.user_id}</span>
                <span class="fingerprint">${user.fingerprint.substring(0, 16)}...</span>
                <span class="status-badge badge-${getKeyStatus(user)}">${getKeyStatus(user)}</span>
            `;
            elements.publicKeysList.appendChild(userEl);
        });
        
        updateKeyStatusCounts();
    } catch (error) {
        elements.publicKeysList.innerHTML = '<div class="error">Failed to load public keys</div>';
    }
}

function isExpired(user) {
    if (!user.created_at) return false;
    const now = Date.now();
    const created = user.created_at * 1000; // Convert seconds to milliseconds
    return now - created > 365 * 24 * 60 * 60 * 1000; // 1 year in milliseconds
}

function getKeyStatus(user) {
    if (user.revoked) return 'revoked';
    if (isExpired(user)) return 'expired';
    return 'active';
}

// Session Management
async function loadSessions() {
    if (!state.currentUserId) {
        elements.sessionsList.innerHTML = '<div class="info">Please log in to view sessions</div>';
        return;
    }
    
    try {
        const response = await fetch(`/api/keys/sessions/${state.currentUserId}`);
        const data = await response.json();
        if (!response.ok) throw new Error('Failed to load sessions');
        
        elements.sessionsList.innerHTML = '';
        data.sessions.forEach(session => {
            const sessionEl = document.createElement('div');
            sessionEl.className = 'session-item';
            const expiresAt = new Date(session.expires_at * 1000);
            const isExpired = expiresAt < new Date();
            
            sessionEl.innerHTML = `
                <span class="session-id">${session.session_id.substring(0, 8)}...</span>
                <span class="peer-id">${session.peer_id}</span>
                <span class="expires-at">${expiresAt.toLocaleString()}</span>
                <span class="status-badge badge-${isExpired ? 'expired' : 'active'}">
                    ${isExpired ? 'Expired' : 'Active'}
                </span>
            `;
            elements.sessionsList.appendChild(sessionEl);
        });
    } catch (error) {
        elements.sessionsList.innerHTML = '<div class="error">Failed to load sessions</div>';
    }
}

// Key Generation
async function handleGenerateKeys() {
    if (!state.currentUserId) {
        showStatus('Please register a user first', 'error');
        return;
    }
    
    try {
        // Generate RSA key pair using Web Crypto API
        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        
        // Export public key to PEM format
        const publicKeyPem = await exportPublicKey(keyPair.publicKey);
        
        // Register public key with server
        const response = await fetch('/api/keys/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: state.currentUserId,
                public_key: publicKeyPem
            })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Key registration failed');
        
        showStatus('RSA key pair generated and registered successfully', 'success');
        loadPublicKeys();
    } catch (error) {
        showStatus(`Error generating keys: ${error.message}`, 'error');
    }
}

// Session Key Rotation
async function handleRotateSessionKey() {
    if (!state.currentUserId) {
        showStatus('Please register a user first', 'error');
        return;
    }
    
    const expirationMinutes = parseInt(elements.rotationExpirationInput.value);
    if (isNaN(expirationMinutes) || expirationMinutes <= 0) {
        showStatus('Please enter a valid expiration time in minutes', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/keys/rotate-session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: state.currentUserId,
                expiration_minutes: expirationMinutes
            })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Rotation failed');
        
        // Update UI with rotation status and next rotation time
        elements.rotationStatus.textContent = 'Session key rotated successfully';
        elements.rotationStatus.className = 'status-message success';
        
        // Calculate next rotation time (current time + expiration minutes)
        const now = new Date();
        const nextRotation = new Date(now.getTime() + expirationMinutes * 60 * 1000);
        elements.nextRotationTime.textContent = `Next rotation scheduled for: ${nextRotation.toLocaleString()}`;
        
        // Refresh session list to show updated expiration
        loadSessions();
    } catch (error) {
        elements.rotationStatus.textContent = `Error: ${error.message}`;
        elements.rotationStatus.className = 'status-message error';
        elements.nextRotationTime.textContent = '';
    }
}

// Key Rotation
function handleRotateKeys() {
    if (!state.currentUserId) {
        showStatus('Please register a user first', 'error');
        return;
    }
    
    state.pendingAction = async () => {
        try {
            const response = await fetch(`/api/keys/rotate/${state.currentUserId}`, { method: 'POST' });
            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.message || 'Rotation failed');
            }
            
            showStatus('Keys rotated successfully', 'success');
            loadPublicKeys();
            loadSessions();
        } catch (error) {
            showStatus(`Error rotating keys: ${error.message}`, 'error');
        }
        state.pendingAction = null;
    };
    
    elements.confirmationMessage.textContent = `Are you sure you want to rotate keys for ${state.currentUserId}? This will invalidate all existing sessions.`;
    elements.confirmationModal.style.display = 'flex';
}

// Key Revocation
function handleRevokeKeys() {
    if (!state.currentUserId) {
        showStatus('Please register a user first', 'error');
        return;
    }
    
    state.pendingAction = async () => {
        try {
            const response = await fetch(`/api/keys/revoke/${state.currentUserId}`, { method: 'POST' });
            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.message || 'Revocation failed');
            }
            
            showStatus('Keys revoked successfully', 'success');
            loadPublicKeys();
            loadSessions();
        } catch (error) {
            showStatus(`Error revoking keys: ${error.message}`, 'error');
        }
        state.pendingAction = null;
    };
    
    elements.confirmationMessage.textContent = `Are you sure you want to revoke keys for ${state.currentUserId}? This will prevent all future logins with this user.`;
    elements.confirmationModal.style.display = 'flex';
}

// UI Helpers
function showStatus(message, type) {
    elements.registrationStatus.textContent = message;
    elements.registrationStatus.className = `status-message ${type}`;
}

function updateKeyStatusCounts() {
    if (!state.users.length) return;
    
    const activeCount = state.users.filter(user => !user.revoked).length;
    const revokedCount = state.users.filter(user => user.revoked).length;
    
    elements.activeKeysCount.textContent = activeCount;
    elements.revokedKeysCount.textContent = revokedCount;
    elements.expiredKeysCount.textContent = '0'; // Placeholder for future implementation
}

// WebSocket Integration
function setupWebSocket() {
    if (!state.currentUserId) return;
    
    state.socket = io();
    
    state.socket.on('connect', () => {
        console.log('WebSocket connected for key management updates');
    });
    
    state.socket.on('key_update', (data) => {
        console.log('Received key management update:', data);
        loadPublicKeys();
        loadSessions();
    });
    
    state.socket.on('session_update', (data) => {
        console.log('Received session update:', data);
        loadSessions();
    });
}

// Utility Functions
async function exportPublicKey(publicKey) {
    // Convert CryptoKey to PEM format
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    const pem = bufferToPem(exported, 'PUBLIC KEY');
    return pem;
}

function bufferToPem(buffer, type) {
    const binary = Array.from(new Uint8Array(buffer))
        .map(b => String.fromCharCode(b))
        .join('');
    const base64 = btoa(binary);
    return `-----BEGIN ${type}-----\n${base64}\n-----END ${type}-----`;
}