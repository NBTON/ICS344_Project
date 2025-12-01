/**
 * SecureChat - Main Application Logic
 * 
 * This module handles:
 * - Socket.IO connection management
 * - Global state management
 * - Utility functions
 */

// Global state
const SecureChatState = {
    socket: null,
    userId: null,
    currentSessionId: null,
    currentPeerId: null,
    sessionKeys: new Map(), // sessionId -> CryptoKey
    publicKeys: new Map(),  // peerId -> CryptoKey
    connected: false,
    users: [],
    messages: new Map(), // sessionId -> messages[]
    typingTimeout: null
};

// Configuration
const SecureChatConfig = {
    socketUrl: window.location.origin,
    reconnectAttempts: 5,
    reconnectDelay: 3000,
    typingTimeout: 2000,
    messageMaxLength: 4096,
    timestampWindow: 300000 // 5 minutes in ms
};

/**
 * Socket.IO Connection Manager
 */
const SocketManager = {
    /**
     * Initialize socket connection
     * @param {string} userId - The user's ID
     */
    init(userId) {
        if (SecureChatState.socket) {
            this.disconnect();
        }

        SecureChatState.userId = userId;
        
        // Create socket connection
        SecureChatState.socket = io(SecureChatConfig.socketUrl, {
            reconnection: true,
            reconnectionAttempts: SecureChatConfig.reconnectAttempts,
            reconnectionDelay: SecureChatConfig.reconnectDelay,
            transports: ['websocket', 'polling']
        });

        this._setupEventHandlers();
    },

    /**
     * Set up socket event handlers
     */
    _setupEventHandlers() {
        const socket = SecureChatState.socket;

        // Connection events
        socket.on('connect', () => {
            console.log('[Socket] Connected');
            SecureChatState.connected = true;
            this._updateConnectionStatus('connected');
            
            // Register with server
            socket.emit('register', { user_id: SecureChatState.userId });
        });

        socket.on('disconnect', (reason) => {
            console.log('[Socket] Disconnected:', reason);
            SecureChatState.connected = false;
            this._updateConnectionStatus('disconnected');
        });

        socket.on('connect_error', (error) => {
            console.error('[Socket] Connection error:', error);
            this._updateConnectionStatus('error');
        });

        socket.on('reconnect', (attemptNumber) => {
            console.log('[Socket] Reconnected after', attemptNumber, 'attempts');
            socket.emit('register', { user_id: SecureChatState.userId });
        });

        // Registration
        socket.on('registered', (data) => {
            console.log('[Socket] Registered:', data);
            this._triggerEvent('registered', data);
        });

        socket.on('connected', (data) => {
            console.log('[Socket] Server acknowledged connection:', data);
        });

        // User events
        socket.on('user_online', (data) => {
            console.log('[Socket] User online:', data.user_id);
            this._triggerEvent('userOnline', data);
        });

        socket.on('user_offline', (data) => {
            console.log('[Socket] User offline:', data.user_id);
            this._triggerEvent('userOffline', data);
        });

        // Session events
        socket.on('joined_session', (data) => {
            console.log('[Socket] Joined session:', data.session_id);
            this._triggerEvent('joinedSession', data);
        });

        // Message events
        socket.on('message', (data) => {
            console.log('[Socket] Message received');
            this._triggerEvent('messageReceived', data);
        });

        socket.on('message_sent', (data) => {
            console.log('[Socket] Message sent confirmation');
            this._triggerEvent('messageSent', data);
        });

        // Key exchange events
        socket.on('key_exchange', (data) => {
            console.log('[Socket] Key exchange received from:', data.initiator_id);
            this._triggerEvent('keyExchange', data);
        });

        socket.on('key_exchange_sent', (data) => {
            console.log('[Socket] Key exchange sent to:', data.recipient_id);
            this._triggerEvent('keyExchangeSent', data);
        });

        socket.on('key_exchange_pending', (data) => {
            console.log('[Socket] Key exchange pending:', data.message);
            this._triggerEvent('keyExchangePending', data);
        });

        // Typing indicator
        socket.on('typing', (data) => {
            this._triggerEvent('typing', data);
        });

        // Error handling
        socket.on('error', (data) => {
            console.error('[Socket] Error:', data);
            this._triggerEvent('socketError', data);
        });

        // Ping/pong for latency
        socket.on('pong', (data) => {
            const latency = Date.now() - this._lastPing;
            this._updateLatency(latency);
        });
    },

    /**
     * Disconnect socket
     */
    disconnect() {
        if (SecureChatState.socket) {
            SecureChatState.socket.disconnect();
            SecureChatState.socket = null;
            SecureChatState.connected = false;
        }
    },

    /**
     * Emit socket event
     * @param {string} event - Event name
     * @param {object} data - Event data
     */
    emit(event, data) {
        if (SecureChatState.socket && SecureChatState.connected) {
            SecureChatState.socket.emit(event, data);
        } else {
            console.warn('[Socket] Cannot emit, not connected');
        }
    },

    /**
     * Join a session room
     * @param {string} sessionId - Session ID to join
     */
    joinSession(sessionId) {
        this.emit('join_session', { session_id: sessionId });
    },

    /**
     * Leave a session room
     * @param {string} sessionId - Session ID to leave
     */
    leaveSession(sessionId) {
        this.emit('leave_session', { session_id: sessionId });
    },

    /**
     * Send typing indicator
     * @param {string} sessionId - Session ID
     * @param {boolean} isTyping - Whether user is typing
     */
    sendTyping(sessionId, isTyping) {
        this.emit('typing', { session_id: sessionId, is_typing: isTyping });
    },

    /**
     * Ping server for latency check
     */
    ping() {
        this._lastPing = Date.now();
        if (SecureChatState.socket) {
            SecureChatState.socket.emit('ping');
        }
    },

    /**
     * Update connection status in UI
     * @param {string} status - Status string
     */
    _updateConnectionStatus(status) {
        const statusEl = document.getElementById('status-websocket');
        if (statusEl) {
            const badge = statusEl.querySelector('.status-badge');
            if (badge) {
                badge.className = 'status-badge';
                switch (status) {
                    case 'connected':
                        badge.classList.add('badge-success');
                        badge.textContent = 'Connected';
                        break;
                    case 'disconnected':
                        badge.classList.add('badge-warning');
                        badge.textContent = 'Disconnected';
                        break;
                    case 'error':
                        badge.classList.add('badge-error');
                        badge.textContent = 'Error';
                        break;
                    default:
                        badge.classList.add('badge-warning');
                        badge.textContent = 'Connecting...';
                }
            }
        }
    },

    /**
     * Update latency display
     * @param {number} latency - Latency in ms
     */
    _updateLatency(latency) {
        const latencyEl = document.getElementById('status-latency');
        if (latencyEl) {
            latencyEl.textContent = `${latency}ms`;
        }
    },

    /**
     * Trigger custom event
     * @param {string} eventName - Event name
     * @param {object} data - Event data
     */
    _triggerEvent(eventName, data) {
        document.dispatchEvent(new CustomEvent(`securechat:${eventName}`, { detail: data }));
    },

    _lastPing: 0
};

/**
 * API Client for REST endpoints
 */
const APIClient = {
    /**
     * Make API request
     * @param {string} endpoint - API endpoint
     * @param {object} options - Fetch options
     * @returns {Promise<object>} Response data
     */
    async request(endpoint, options = {}) {
        const url = `/api${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const response = await fetch(url, { ...defaultOptions, ...options });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'API request failed');
        }

        return data;
    },

    /**
     * Register a new user
     * @param {string} userId - User ID
     * @returns {Promise<object>} User data with public key
     */
    async register(userId) {
        return this.request('/register', {
            method: 'POST',
            body: JSON.stringify({ user_id: userId })
        });
    },

    /**
     * Get all users
     * @returns {Promise<object>} List of users
     */
    async getUsers() {
        return this.request('/users');
    },

    /**
     * Get user's public key
     * @param {string} userId - User ID
     * @returns {Promise<object>} Public key data
     */
    async getPublicKey(userId) {
        return this.request(`/keys/public/${encodeURIComponent(userId)}`);
    },

    /**
     * Initiate key exchange
     * @param {string} initiatorId - Initiator user ID
     * @param {string} recipientId - Recipient user ID
     * @returns {Promise<object>} Session data
     */
    async exchangeKeys(initiatorId, recipientId) {
        return this.request('/keys/exchange', {
            method: 'POST',
            body: JSON.stringify({
                initiator_id: initiatorId,
                recipient_id: recipientId
            })
        });
    },

    /**
     * Get session info
     * @param {string} sessionId - Session ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<object>} Session data
     */
    async getSession(sessionId, userId) {
        return this.request(`/keys/session/${sessionId}?user_id=${encodeURIComponent(userId)}`);
    },

    /**
     * Get user's sessions
     * @param {string} userId - User ID
     * @returns {Promise<object>} List of sessions
     */
    async getUserSessions(userId) {
        return this.request(`/keys/sessions/${encodeURIComponent(userId)}`);
    }
};

/**
 * Utility Functions
 */
const Utils = {
    /**
     * Generate a random nonce
     * @param {number} length - Nonce length in bytes
     * @returns {Uint8Array} Random nonce
     */
    generateNonce(length = 16) {
        return crypto.getRandomValues(new Uint8Array(length));
    },

    /**
     * Convert ArrayBuffer to hex string
     * @param {ArrayBuffer} buffer - Buffer to convert
     * @returns {string} Hex string
     */
    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Convert hex string to ArrayBuffer
     * @param {string} hex - Hex string
     * @returns {Uint8Array} Buffer
     */
    hexToBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    },

    /**
     * Convert ArrayBuffer to Base64
     * @param {ArrayBuffer} buffer - Buffer to convert
     * @returns {string} Base64 string
     */
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    /**
     * Convert Base64 to ArrayBuffer
     * @param {string} base64 - Base64 string
     * @returns {Uint8Array} Buffer
     */
    base64ToBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    /**
     * Format timestamp for display
     * @param {number} timestamp - Unix timestamp in ms
     * @returns {string} Formatted time
     */
    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    /**
     * Format date for display
     * @param {number} timestamp - Unix timestamp in ms
     * @returns {string} Formatted date
     */
    formatDate(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleDateString();
    },

    /**
     * Truncate string with ellipsis
     * @param {string} str - String to truncate
     * @param {number} maxLength - Maximum length
     * @returns {string} Truncated string
     */
    truncate(str, maxLength = 20) {
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength - 3) + '...';
    },

    /**
     * Get initials from username
     * @param {string} username - Username
     * @returns {string} Initials
     */
    getInitials(username) {
        return username.substring(0, 2).toUpperCase();
    },

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Debounce function
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function} Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Check if timestamp is within acceptable window
     * @param {number} timestamp - Timestamp to check (ms)
     * @param {number} window - Acceptable window (ms)
     * @returns {boolean} Is valid
     */
    isTimestampValid(timestamp, window = SecureChatConfig.timestampWindow) {
        const now = Date.now();
        return Math.abs(now - timestamp) <= window;
    },

    /**
     * Show notification
     * @param {string} message - Notification message
     * @param {string} type - Notification type (success, error, warning, info)
     */
    showNotification(message, type = 'info') {
        // Simple console notification for now
        // Can be extended with toast notifications
        const styles = {
            success: 'color: green',
            error: 'color: red',
            warning: 'color: orange',
            info: 'color: blue'
        };
        console.log(`%c[${type.toUpperCase()}] ${message}`, styles[type] || styles.info);
        
        // Could add toast notification here
    }
};

/**
 * Storage Manager for persistent data
 */
const StorageManager = {
    prefix: 'securechat_',

    /**
     * Set item in localStorage
     * @param {string} key - Key
     * @param {*} value - Value (will be JSON stringified)
     */
    set(key, value) {
        try {
            localStorage.setItem(this.prefix + key, JSON.stringify(value));
        } catch (e) {
            console.error('Storage error:', e);
        }
    },

    /**
     * Get item from localStorage
     * @param {string} key - Key
     * @returns {*} Parsed value or null
     */
    get(key) {
        try {
            const value = localStorage.getItem(this.prefix + key);
            return value ? JSON.parse(value) : null;
        } catch (e) {
            console.error('Storage error:', e);
            return null;
        }
    },

    /**
     * Remove item from localStorage
     * @param {string} key - Key
     */
    remove(key) {
        localStorage.removeItem(this.prefix + key);
    },

    /**
     * Clear all SecureChat data
     */
    clear() {
        const keys = Object.keys(localStorage).filter(k => k.startsWith(this.prefix));
        keys.forEach(k => localStorage.removeItem(k));
    }
};

// Export for global access
window.SecureChatState = SecureChatState;
window.SecureChatConfig = SecureChatConfig;
window.SocketManager = SocketManager;
window.APIClient = APIClient;
window.Utils = Utils;
window.StorageManager = StorageManager;

// Initialize ping interval for latency monitoring
setInterval(() => {
    if (SecureChatState.connected) {
        SocketManager.ping();
    }
}, 30000); // Every 30 seconds