/**
 * SecureChat - Chat Functionality
 * 
 * Handles:
 * - User registration/login
 * - Fetching and displaying user list
 * - Selecting chat partners
 * - Sending and receiving encrypted messages
 * - Key exchange
 * - UI updates
 */

const SecureChatApp = {
    // Current state
    currentUserId: null,
    currentPeerId: null,
    currentSessionId: null,
    isInitialized: false,

    /**
     * Initialize the chat application
     * @param {string} userId - Current user's ID
     */
    async init(userId) {
        if (this.isInitialized) {
            console.warn('SecureChatApp already initialized');
            return;
        }

        this.currentUserId = userId;
        console.log('[Chat] Initializing for user:', userId);

        // Update UI with user info
        this._updateUserInfo();

        // Initialize socket connection with reconnection logic, message queuing, and status indicators
        SocketManager.init(userId);
        SocketManager.startHeartbeat();
        SocketManager.setupReconnection();
        SocketManager.initializeMessageQueue();
        this._setupWebSocketStatusIndicators();

        // Set up event listeners
        this._setupEventListeners();
        this._setupSocketListeners();

        // Load user list
        await this._loadUsers();

        // Load existing sessions
        await this._loadSessions();

        this.isInitialized = true;
        console.log('[Chat] Initialization complete');
    },

    /**
     * Set up UI event listeners
     */
    _setupEventListeners() {
        // Message form submission
        const messageForm = document.getElementById('message-form');
        if (messageForm) {
            messageForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this._sendMessage();
            });
        }

        // Message input for typing indicator and char count
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.addEventListener('input', (e) => {
                this._handleTyping();
                this._updateCharCount();
            });
        }

        // Refresh users button
        const refreshBtn = document.getElementById('refresh-users-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this._loadUsers());
        }

        // Key exchange button
        const keyExchangeBtn = document.getElementById('key-exchange-btn');
        if (keyExchangeBtn) {
            keyExchangeBtn.addEventListener('click', () => this._initiateKeyExchange());
        }

        // Verify keys button
        const verifyKeysBtn = document.getElementById('verify-keys-btn');
        if (verifyKeysBtn) {
            verifyKeysBtn.addEventListener('click', () => this._showVerifyModal());
        }

        // Rotate session key button
        const rotateBtn = document.getElementById('rotate-session-btn');
        if (rotateBtn) {
            rotateBtn.addEventListener('click', () => this._rotateSessionKey());
        }

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this._logout());
        }

        // Modal close buttons
        document.querySelectorAll('.modal-close, .modal-close-btn').forEach(btn => {
            btn.addEventListener('click', () => this._hideModals());
        });

        // Modal overlay click
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', () => this._hideModals());
        });
    },

    /**
     * Set up socket event listeners
     */
    _setupSocketListeners() {
        // User registered
        document.addEventListener('securechat:registered', (e) => {
            console.log('[Chat] Socket registered');
            this._updateConnectionStatus('connected');
            SocketManager.clearReconnectTimeout();
            SocketManager.sendQueuedMessages();
        });

        // Connection error
        document.addEventListener('securechat:connectionError', (e) => {
            const { type, message } = e.detail;
            this._updateConnectionStatus('error');
            this._updateQueuedMessagesCount(SocketManager.getQueueSize());
            SocketManager.handleConnectionError(type, message);
        });

        // Connection closed
        document.addEventListener('securechat:disconnected', (e) => {
            console.log('[Chat] Socket disconnected');
            this._updateConnectionStatus('disconnected');
            this._updateQueuedMessagesCount(SocketManager.getQueueSize());
            SocketManager.handleDisconnection();
        });

        // Heartbeat response
        document.addEventListener('securechat:pong', (e) => {
            SocketManager.updateHeartbeat();
        });

        // Message received
        document.addEventListener('securechat:messageReceived', (e) => {
            this._handleIncomingMessage(e.detail);
        });

        // Message sent confirmation
        document.addEventListener('securechat:messageSent', (e) => {
            console.log('[Chat] Message sent confirmed');
            this._updateQueuedMessagesCount(SocketManager.getQueueSize());
        });

        // Decryption error
        document.addEventListener('securechat:decryptionError', (e) => {
            const { message } = e.detail;
            Utils.showNotification(`Decryption failed: ${message}`, 'error');
        });

        // User online
        document.addEventListener('securechat:userOnline', (e) => {
            const { user_id } = e.detail;
            this._updateUserOnlineStatus(user_id, true);
        });

        // User offline
        document.addEventListener('securechat:userOffline', (e) => {
            const { user_id } = e.detail;
            this._updateUserOnlineStatus(user_id, false);
        });

        // Message received
        document.addEventListener('securechat:messageReceived', (e) => {
            this._handleIncomingMessage(e.detail);
        });

        // Message sent confirmation
        document.addEventListener('securechat:messageSent', (e) => {
            console.log('[Chat] Message sent confirmed');
        });

        // Key exchange received
        document.addEventListener('securechat:keyExchange', (e) => {
            this._handleKeyExchange(e.detail);
        });

        // Key exchange sent
        document.addEventListener('securechat:keyExchangeSent', (e) => {
            Utils.showNotification('Key exchange sent', 'success');
        });

        // Typing indicator
        document.addEventListener('securechat:typing', (e) => {
            this._handleTypingIndicator(e.detail);
        });

        // Socket error
        document.addEventListener('securechat:socketError', (e) => {
            const { type, message } = e.detail;
            Utils.showNotification(message, 'error');
        });

        // Connection error
        document.addEventListener('securechat:connectionError', (e) => {
            const { type, message } = e.detail;
            Utils.showNotification('Connection lost. Please refresh the page.', 'error');
            this._updateConnectionStatus('error');
        });
    },

    /**
     * Update user info in UI
     */
    _updateUserInfo() {
        const currentUserEl = document.getElementById('current-user');
        if (currentUserEl) {
            currentUserEl.textContent = this.currentUserId;
        }

        const statusUserIdEl = document.getElementById('status-user-id');
        if (statusUserIdEl) {
            statusUserIdEl.textContent = this.currentUserId;
        }

        const fingerprint = localStorage.getItem('securechat_fingerprint');
        const statusFingerprintEl = document.getElementById('status-fingerprint');
        if (statusFingerprintEl && fingerprint) {
            statusFingerprintEl.textContent = fingerprint.substring(0, 16) + '...';
        }
    },

    /**
     * Update connection status in UI
     * @param {string} status - Connection status
     */
    _updateConnectionStatus(status) {
        const wsStatusEl = document.getElementById('status-websocket');
        if (wsStatusEl) {
            const badge = wsStatusEl.querySelector('.status-badge');
            if (badge) {
                badge.className = 'status-badge';
                if (status === 'connected') {
                    badge.classList.add('badge-success');
                    badge.textContent = 'Connected';
                } else {
                    badge.classList.add('badge-warning');
                    badge.textContent = 'Connecting...';
                }
            }
        }
    },

    /**
     * Load and display users
     */
    async _loadUsers() {
        const userListEl = document.getElementById('user-list');
        if (!userListEl) return;

        try {
            // Show loading
            userListEl.innerHTML = `
                <div class="loading-users">
                    <div class="loading-spinner small"></div>
                    <span>Loading users...</span>
                </div>
            `;

            const data = await APIClient.getUsers();
            SecureChatState.users = data.users || [];

            // Clear and populate user list
            userListEl.innerHTML = '';

            if (SecureChatState.users.length === 0) {
                userListEl.innerHTML = '<div class="loading-users">No users found</div>';
                return;
            }

            SecureChatState.users.forEach(user => {
                const userEl = this._createUserElement(user);
                userListEl.appendChild(userEl);
            });

        } catch (error) {
            console.error('[Chat] Error loading users:', error);
            userListEl.innerHTML = '<div class="loading-users">Error loading users</div>';
        }
    },

    /**
     * Create user list item element
     * @param {object} user - User data
     * @returns {HTMLElement} User element
     */
    _createUserElement(user) {
        const div = document.createElement('div');
        div.className = 'user-item';
        div.dataset.userId = user.user_id;

        if (user.user_id === this.currentUserId) {
            div.classList.add('self');
        }

        div.innerHTML = `
            <div class="user-avatar">${Utils.getInitials(user.user_id)}</div>
            <div class="user-info">
                <div class="user-name">${Utils.escapeHtml(user.user_id)}</div>
                <div class="user-fingerprint">${user.fingerprint.substring(0, 16)}...</div>
            </div>
            <span class="user-status ${user.user_id === this.currentUserId ? 'online' : ''}"></span>
        `;

        if (user.user_id !== this.currentUserId) {
            div.addEventListener('click', () => this._selectUser(user.user_id));
        }

        return div;
    },

    /**
     * Update user online status in UI
     * @param {string} userId - User ID
     * @param {boolean} isOnline - Online status
     */
    _updateUserOnlineStatus(userId, isOnline) {
        const userEl = document.querySelector(`.user-item[data-user-id="${userId}"]`);
        if (userEl) {
            const statusEl = userEl.querySelector('.user-status');
            if (statusEl) {
                statusEl.className = `user-status ${isOnline ? 'online' : ''}`;
            }
        }
    },

    /**
     * Select a user to chat with
     * @param {string} userId - User ID to chat with
     */
    async _selectUser(userId) {
        if (userId === this.currentUserId) return;

        console.log('[Chat] Selecting user:', userId);
        this.currentPeerId = userId;

        // Update UI
        this._updateSelectedUser(userId);

        // Check for existing session
        const session = await this._findOrCreateSession(userId);
        
        if (session) {
            this.currentSessionId = session.session_id;
            this._updateSessionStatus(session);
            
            // Join the session room
            SocketManager.joinSession(session.session_id);
            
            // Show message input
            const inputContainer = document.getElementById('message-input-container');
            if (inputContainer) {
                inputContainer.style.display = 'block';
            }

            // Load message history
            this._loadMessages(session.session_id);
        }
    },

    /**
     * Update UI for selected user
     * @param {string} userId - Selected user ID
     */
    _updateSelectedUser(userId) {
        // Update user list selection
        document.querySelectorAll('.user-item').forEach(el => {
            el.classList.remove('active');
            if (el.dataset.userId === userId) {
                el.classList.add('active');
            }
        });

        // Update chat header
        const partnerNameEl = document.getElementById('chat-partner-name');
        if (partnerNameEl) {
            partnerNameEl.textContent = userId;
        }

        const partnerStatusEl = document.getElementById('chat-partner-status');
        if (partnerStatusEl) {
            partnerStatusEl.textContent = 'Encrypted chat';
        }

        // Show key exchange button
        const keyExchangeBtn = document.getElementById('key-exchange-btn');
        if (keyExchangeBtn) {
            keyExchangeBtn.style.display = 'inline-flex';
        }

        // Clear no-chat-selected message
        const messagesContainer = document.getElementById('messages-container');
        if (messagesContainer) {
            const noChat = messagesContainer.querySelector('.no-chat-selected');
            if (noChat) {
                noChat.remove();
            }
        }
    },

    /**
     * Find existing session or create new one
     * @param {string} peerId - Peer user ID
     * @returns {Promise<object>} Session data
     */
    async _findOrCreateSession(peerId) {
        try {
            // Get user's sessions
            const sessionsData = await APIClient.getUserSessions(this.currentUserId);
            
            // Look for existing session with peer
            const existingSession = sessionsData.sessions.find(
                s => s.peer_id === peerId
            );

            if (existingSession) {
                console.log('[Chat] Found existing session:', existingSession.session_id);
                return {
                    session_id: existingSession.session_id,
                    ...existingSession
                };
            }

            // Create new session
            console.log('[Chat] Creating new session with:', peerId);
            const newSession = await APIClient.exchangeKeys(this.currentUserId, peerId);
            
            // Store the session key
            // In a real app, we'd decrypt the encrypted key
            
            return newSession;

        } catch (error) {
            console.error('[Chat] Error finding/creating session:', error);
            Utils.showNotification('Failed to establish secure session', 'error');
            return null;
        }
    },

    /**
     * Update session status in UI
     * @param {object} session - Session data
     */
    _updateSessionStatus(session) {
        const sessionKeyEl = document.getElementById('status-session-key');
        if (sessionKeyEl) {
            const hasKey = SecureChatCrypto.getSessionKey(session.session_id);
            if (hasKey) {
                sessionKeyEl.innerHTML = '<span class="status-badge badge-success">Established</span>';
            } else {
                sessionKeyEl.innerHTML = '<span class="status-badge badge-warning">Pending</span>';
            }
        }

        const sessionIdEl = document.getElementById('status-session-id');
        if (sessionIdEl) {
            sessionIdEl.textContent = session.session_id.substring(0, 8) + '...';
        }

        const expiresEl = document.getElementById('status-session-expires');
        if (expiresEl && session.expires_at) {
            expiresEl.textContent = Utils.formatTime(session.expires_at * 1000);
        }
    },

    /**
     * Load existing sessions
     */
    async _loadSessions() {
        try {
            const data = await APIClient.getUserSessions(this.currentUserId);
            console.log('[Chat] Loaded sessions:', data.sessions.length);
        } catch (error) {
            console.error('[Chat] Error loading sessions:', error);
        }
    },

    /**
     * Load messages for a session
     * @param {string} sessionId - Session ID
     */
    _loadMessages(sessionId) {
        const messagesContainer = document.getElementById('messages-container');
        if (!messagesContainer) return;

        // Clear current messages
        messagesContainer.innerHTML = '';

        // Get stored messages
        const messages = SecureChatState.messages.get(sessionId) || [];
        
        messages.forEach(msg => {
            this._displayMessage(msg);
        });

        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    },

    /**
     * Send encrypted message
     */
    async _sendMessage() {
        const input = document.getElementById('message-input');
        if (!input) return;

        const plaintext = input.value.trim();
        if (!plaintext) return;

        if (!this.currentSessionId || !this.currentPeerId) {
            Utils.showNotification('Please select a user to chat with', 'warning');
            return;
        }

        // Check socket connection before sending
        if (!SocketManager.isConnected()) {
            Utils.showNotification('Not connected to server. Please wait...', 'error');
            return;
        }

        try {
            // Get or generate session key
            let sessionKey = SecureChatCrypto.getSessionKey(this.currentSessionId);
            
            if (!sessionKey) {
                // Generate new session key for demo
                sessionKey = await SecureChatCrypto.generateSessionKey();
                SecureChatCrypto.storeSessionKey(this.currentSessionId, sessionKey);
            }

            // Get signing key
            const keys = await SecureChatCrypto.getKeyPair(this.currentUserId);
            const signingKey = keys.signing?.privateKey || null;

            // Create secure message
            const messagePackage = await SecureChatCrypto.createSecureMessage(
                plaintext,
                sessionKey,
                this.currentUserId,
                signingKey
            );

            // Send via WebSocket
            SocketManager.emit('message', {
                session_id: this.currentSessionId,
                message: messagePackage
            });

            // Display sent message locally
            const sentMessage = {
                text: plaintext,
                senderId: this.currentUserId,
                timestamp: Date.now(),
                sent: true,
                signatureValid: true
            };

            this._displayMessage(sentMessage);
            this._storeMessage(this.currentSessionId, sentMessage);

            // Clear input
            input.value = '';
            this._updateCharCount();

            // Update last verified time
            this._updateLastVerified();

        } catch (error) {
            console.error('[Chat] Error sending message:', error);
            Utils.showNotification('Failed to send message', 'error');
        }
    },

    /**
     * Handle incoming message
     * @param {object} data - Message data from socket
     */
    async _handleIncomingMessage(data) {
        const { session_id, sender_id, message, timestamp } = data;

        console.log('[Chat] Incoming message from:', sender_id);

        // Don't ignore own messages - we want to see what we sent
        // if (sender_id === this.currentUserId) {
        //     return; // Ignore own messages
        // }

        try {
            // Get session key
            let sessionKey = SecureChatCrypto.getSessionKey(session_id);
            
            if (!sessionKey) {
                // For demo, generate matching key
                sessionKey = await SecureChatCrypto.generateSessionKey();
                SecureChatCrypto.storeSessionKey(session_id, sessionKey);
            }

            // Parse and decrypt message
            const decrypted = await SecureChatCrypto.parseSecureMessage(
                message,
                sessionKey,
                null // Would pass sender's public key for signature verification
            );

            const receivedMessage = {
                text: decrypted.plaintext,
                senderId: sender_id,
                timestamp: decrypted.timestamp,
                sent: false,
                signatureValid: decrypted.signatureValid
            };

            // Always store the message
            this._storeMessage(session_id, receivedMessage);

            // Display message if it's in the current chat session
            if (session_id === this.currentSessionId) {
                this._displayMessage(receivedMessage);
            } else {
                // If not current session, show a notification
                console.log(`[Chat] New message from ${sender_id} in session ${session_id}`);
                Utils.showNotification(`New message from ${sender_id}`, 'info');
            }

            // Update last verified time
            this._updateLastVerified();

        } catch (error) {
            console.error('[Chat] Error processing incoming message:', error);
            Utils.showNotification('Failed to decrypt message', 'error');
        }
    },

    /**
     * Display message in chat
     * @param {object} message - Message data
     */
    _displayMessage(message) {
        const container = document.getElementById('messages-container');
        if (!container) return;

        const messageEl = document.createElement('div');
        messageEl.className = `message ${message.sent ? 'sent' : 'received'}`;

        const statusIcon = message.signatureValid ? '✓✓' : '✓';
        const statusClass = message.signatureValid ? 'verified' : '';

        messageEl.innerHTML = `
            <div class="message-content">
                <p class="message-text">${Utils.escapeHtml(message.text)}</p>
                <div class="message-meta">
                    <span class="message-time">${Utils.formatTime(message.timestamp)}</span>
                    <span class="message-status ${statusClass}">${statusIcon}</span>
                </div>
            </div>
        `;

        container.appendChild(messageEl);
        container.scrollTop = container.scrollHeight;
    },

    /**
     * Store message in state
     * @param {string} sessionId - Session ID
     * @param {object} message - Message data
     */
    _storeMessage(sessionId, message) {
        if (!SecureChatState.messages.has(sessionId)) {
            SecureChatState.messages.set(sessionId, []);
        }
        SecureChatState.messages.get(sessionId).push(message);
    },

    /**
     * Handle typing input
     */
    _handleTyping() {
        if (!this.currentSessionId) return;

        // Send typing indicator
        SocketManager.sendTyping(this.currentSessionId, true);

        // Clear existing timeout
        if (SecureChatState.typingTimeout) {
            clearTimeout(SecureChatState.typingTimeout);
        }

        // Set timeout to stop typing indicator
        SecureChatState.typingTimeout = setTimeout(() => {
            SocketManager.sendTyping(this.currentSessionId, false);
        }, SecureChatConfig.typingTimeout);
    },

    /**
     * Handle typing indicator from peer
     * @param {object} data - Typing data
     */
    _handleTypingIndicator(data) {
        const { user_id, is_typing } = data;
        
        if (user_id !== this.currentPeerId) return;

        const container = document.getElementById('messages-container');
        if (!container) return;

        // Remove existing typing indicator
        const existingIndicator = container.querySelector('.typing-indicator-wrapper');
        if (existingIndicator) {
            existingIndicator.remove();
        }

        if (is_typing) {
            const indicator = document.createElement('div');
            indicator.className = 'typing-indicator-wrapper message received';
            indicator.innerHTML = `
                <div class="typing-indicator">
                    <span class="typing-dot"></span>
                    <span class="typing-dot"></span>
                    <span class="typing-dot"></span>
                </div>
            `;
            container.appendChild(indicator);
            container.scrollTop = container.scrollHeight;
        }
    },

    /**
     * Update character count
     */
    _updateCharCount() {
        const input = document.getElementById('message-input');
        const countEl = document.getElementById('char-count');
        
        if (input && countEl) {
            countEl.textContent = `${input.value.length}/${SecureChatConfig.messageMaxLength}`;
        }
    },

    /**
     * Update last verified time
     */
    _updateLastVerified() {
        const el = document.getElementById('status-last-verified');
        if (el) {
            el.textContent = Utils.formatTime(Date.now());
        }
    },

    /**
     * Initiate key exchange with current peer
     */
    async _initiateKeyExchange() {
        if (!this.currentPeerId) {
            Utils.showNotification('Please select a user first', 'warning');
            return;
        }

        try {
            Utils.showNotification('Initiating key exchange...', 'info');

            // Get peer's public key
            const peerKeyData = await APIClient.getPublicKey(this.currentPeerId);
            const peerPublicKey = await SecureChatCrypto.importPublicKey(peerKeyData.public_key);

            // Generate new session key
            const sessionKey = await SecureChatCrypto.generateSessionKey();

            // Encrypt session key with peer's public key
            const encryptedKey = await SecureChatCrypto.encryptSessionKey(sessionKey, peerPublicKey);

            // Get signing key
            const keys = await SecureChatCrypto.getKeyPair(this.currentUserId);
            const signingKey = keys.signing?.privateKey || null;

            // Sign the encrypted key
            let signature = '';
            if (signingKey) {
                signature = await SecureChatCrypto.signMessage(
                    Utils.bufferToHex(encryptedKey),
                    signingKey
                );
            }

            // Store session key locally
            SecureChatCrypto.storeSessionKey(this.currentSessionId, sessionKey);

            // Send key exchange via WebSocket
            SocketManager.emit('key_exchange', {
                session_id: this.currentSessionId,
                recipient_id: this.currentPeerId,
                encrypted_key: Utils.bufferToHex(encryptedKey),
                signature: signature
            });

            this._updateSessionStatus({ session_id: this.currentSessionId });

        } catch (error) {
            console.error('[Chat] Key exchange error:', error);
            Utils.showNotification('Key exchange failed', 'error');
        }
    },

    /**
     * Handle incoming key exchange
     * @param {object} data - Key exchange data
     */
    async _handleKeyExchange(data) {
        const { session_id, initiator_id, encrypted_key, signature } = data;

        console.log('[Chat] Received key exchange from:', initiator_id);

        try {
            // Get our private key
            const keys = await SecureChatCrypto.getKeyPair(this.currentUserId);
            const privateKey = keys.encryption.privateKey;

            // Decrypt session key
            const encryptedKeyBuffer = Utils.hexToBuffer(encrypted_key);
            const sessionKey = await SecureChatCrypto.decryptSessionKey(encryptedKeyBuffer, privateKey);

            // Store session key
            SecureChatCrypto.storeSessionKey(session_id, sessionKey);

            Utils.showNotification(`Secure session established with ${initiator_id}`, 'success');

            // Update UI if this is the current session
            if (session_id === this.currentSessionId) {
                this._updateSessionStatus({ session_id: session_id });
            }

        } catch (error) {
            console.error('[Chat] Error handling key exchange:', error);
            Utils.showNotification('Failed to process key exchange', 'error');
        }
    },

    /**
     * Rotate session key
     */
    async _rotateSessionKey() {
        if (!this.currentSessionId) {
            Utils.showNotification('No active session', 'warning');
            return;
        }

        await this._initiateKeyExchange();
        Utils.showNotification('Session key rotated', 'success');
    },

    /**
     * Show key verification modal
     */
    async _showVerifyModal() {
        const modal = document.getElementById('verify-modal');
        if (!modal) return;

        // Get fingerprints
        const myFingerprint = localStorage.getItem('securechat_fingerprint') || 'Not available';
        
        let partnerFingerprint = 'Not available';
        if (this.currentPeerId) {
            try {
                const peerData = await APIClient.getPublicKey(this.currentPeerId);
                partnerFingerprint = peerData.fingerprint;
            } catch (e) {
                console.error('Error getting partner fingerprint:', e);
            }
        }

        // Generate session verification code
        let sessionCode = 'No active session';
        if (this.currentSessionId) {
            const combinedFingerprints = myFingerprint + partnerFingerprint;
            const encoder = new TextEncoder();
            const data = encoder.encode(combinedFingerprints);
            const hash = await crypto.subtle.digest('SHA-256', data);
            sessionCode = Utils.bufferToHex(hash).substring(0, 32);
        }

        // Update modal content
        document.getElementById('verify-your-fingerprint').textContent = myFingerprint;
        document.getElementById('verify-partner-fingerprint').textContent = partnerFingerprint;
        document.getElementById('verify-session-code').textContent = sessionCode;

        modal.style.display = 'flex';
    },

    /**
     * Hide all modals
     */
    _hideModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    },

    /**
     * Logout user
     */
    _logout() {
        // Disconnect socket
        SocketManager.disconnect();

        // Clear local storage
        localStorage.removeItem('securechat_user_id');
        localStorage.removeItem('securechat_public_key');
        localStorage.removeItem('securechat_fingerprint');

        // Clear state
        SecureChatState.messages.clear();
        this.currentUserId = null;
        this.currentPeerId = null;
        this.currentSessionId = null;
        this.isInitialized = false;

        // Redirect to login
        window.location.href = '/';
    }
};

// Export for global access
window.SecureChatApp = SecureChatApp;