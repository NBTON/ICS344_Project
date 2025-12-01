/**
 * SecureChat - Attack Lab Module
 * 
 * Interactive demonstrations of security attacks and defenses:
 * - Replay Attack
 * - Ciphertext Tampering
 * - Man-in-the-Middle Attack
 * - Denial of Service Attack
 */

const AttackLab = {
    // Current active tab
    activeAttack: 'replay',

    // Attack simulation state
    attackInProgress: false,

    /**
     * Initialize Attack Lab
     */
    init() {
        console.log('[AttackLab] Initializing...');
        this._setupTabNavigation();
        this._setupAttackButtons();
        console.log('[AttackLab] Ready');
    },

    /**
     * Set up tab navigation
     */
    _setupTabNavigation() {
        const tabButtons = document.querySelectorAll('.tab-btn');
        
        tabButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const attack = btn.dataset.attack;
                this._switchTab(attack);
            });
        });
    },

    /**
     * Switch to a different attack tab
     * @param {string} attack - Attack type (replay, tampering, mitm, dos)
     */
    _switchTab(attack) {
        this.activeAttack = attack;

        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.attack === attack);
        });

        // Update panels
        document.querySelectorAll('.attack-panel').forEach(panel => {
            panel.classList.toggle('active', panel.id === `${attack}-panel`);
        });
    },

    /**
     * Set up attack button handlers
     */
    _setupAttackButtons() {
        const attackButtons = document.querySelectorAll('.btn-attack');
        
        attackButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const attack = btn.dataset.attack;
                const mode = btn.dataset.mode;
                this._runAttack(attack, mode);
            });
        });
    },

    /**
     * Run attack demonstration
     * @param {string} attack - Attack type
     * @param {string} mode - 'vulnerable' or 'defended'
     */
    async _runAttack(attack, mode) {
        if (this.attackInProgress) {
            console.warn('[AttackLab] Attack already in progress');
            return;
        }

        this.attackInProgress = true;
        console.log(`[AttackLab] Running ${attack} attack in ${mode} mode`);

        // Reset UI
        this._resetDemo(attack, mode);
        this._setStatus(attack, mode, 'Running...');

        try {
            switch (attack) {
                case 'replay':
                    await this._runReplayAttack(mode);
                    break;
                case 'tampering':
                    await this._runTamperingAttack(mode);
                    break;
                case 'mitm':
                    await this._runMITMAttack(mode);
                    break;
                case 'dos':
                    await this._runDoSAttack(mode);
                    break;
            }
        } catch (error) {
            console.error('[AttackLab] Attack error:', error);
            this._log(attack, mode, `Error: ${error.message}`, 'error');
        } finally {
            this.attackInProgress = false;
        }
    },

    /**
     * Reset demo UI
     * @param {string} attack - Attack type
     * @param {string} mode - Mode
     */
    _resetDemo(attack, mode) {
        const logEl = document.getElementById(`${attack}-${mode}-log`);
        if (logEl) {
            logEl.innerHTML = '';
        }

        const resultEl = document.getElementById(`${attack}-${mode}-result`);
        if (resultEl) {
            resultEl.innerHTML = '';
            resultEl.className = 'demo-result';
        }
    },

    /**
     * Set demo status
     * @param {string} attack - Attack type
     * @param {string} mode - Mode
     * @param {string} status - Status text
     */
    _setStatus(attack, mode, status) {
        const statusEl = document.getElementById(`${attack}-${mode}-status`);
        if (statusEl) {
            statusEl.textContent = status;
        }
    },

    /**
     * Log message to demo
     * @param {string} attack - Attack type
     * @param {string} mode - Mode
     * @param {string} message - Log message
     * @param {string} type - Log type (info, success, error, warning)
     */
    _log(attack, mode, message, type = 'info') {
        const logEl = document.getElementById(`${attack}-${mode}-log`);
        if (logEl) {
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            entry.textContent = `> ${message}`;
            logEl.appendChild(entry);
            logEl.scrollTop = logEl.scrollHeight;
        }
    },

    /**
     * Show demo result
     * @param {string} attack - Attack type
     * @param {string} mode - Mode
     * @param {boolean} attackSucceeded - Whether attack succeeded
     * @param {string} message - Result message
     */
    _showResult(attack, mode, attackSucceeded, message) {
        const resultEl = document.getElementById(`${attack}-${mode}-result`);
        if (resultEl) {
            if (mode === 'vulnerable') {
                // In vulnerable mode, attack succeeding is bad
                resultEl.className = `demo-result ${attackSucceeded ? 'failure' : 'success'}`;
                resultEl.textContent = attackSucceeded ? '⚠️ ATTACK SUCCEEDED' : '✓ Attack Failed';
            } else {
                // In defended mode, attack failing is good
                resultEl.className = `demo-result ${attackSucceeded ? 'failure' : 'success'}`;
                resultEl.textContent = attackSucceeded ? '⚠️ Defense Failed' : '🛡️ ATTACK BLOCKED';
            }
        }
        this._setStatus(attack, mode, message);
    },

    /**
     * Simulate delay
     * @param {number} ms - Milliseconds to wait
     */
    _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    // ==========================================
    // Replay Attack Demonstration
    // ==========================================

    async _runReplayAttack(mode) {
        const attack = 'replay';

        this._log(attack, mode, 'Starting Replay Attack demonstration...', 'info');
        await this._delay(500);

        // Step 1: Capture original message
        this._log(attack, mode, 'Alice sends message to Bob...', 'info');
        await this._delay(300);

        const originalMessage = {
            content: 'Transfer $100 to Bob',
            timestamp: Date.now(),
            nonce: this._generateNonce()
        };

        this._log(attack, mode, `Message: "${originalMessage.content}"`, 'info');
        this._log(attack, mode, `Timestamp: ${new Date(originalMessage.timestamp).toISOString()}`, 'info');
        this._log(attack, mode, `Nonce: ${originalMessage.nonce.substring(0, 16)}...`, 'info');
        await this._delay(500);

        // Step 2: Attacker captures message
        this._log(attack, mode, '🕵️ Attacker intercepts and captures message...', 'warning');
        await this._delay(500);

        const capturedMessage = { ...originalMessage };
        this._log(attack, mode, 'Message captured and stored by attacker', 'warning');
        await this._delay(1000);

        // Step 3: Time passes
        this._log(attack, mode, '⏱️ Time passes (simulating 10 minutes)...', 'info');
        await this._delay(1000);

        // Step 4: Replay attempt
        this._log(attack, mode, '🔄 Attacker replays captured message...', 'warning');
        await this._delay(500);

        if (mode === 'vulnerable') {
            // Vulnerable mode - no replay protection
            this._log(attack, mode, 'Server receives message...', 'info');
            await this._delay(300);
            this._log(attack, mode, 'No timestamp validation ❌', 'warning');
            this._log(attack, mode, 'No nonce tracking ❌', 'warning');
            await this._delay(300);
            this._log(attack, mode, 'Message accepted and processed!', 'error');
            this._log(attack, mode, '$100 transferred again (duplicate transaction)!', 'error');
            await this._delay(300);
            this._showResult(attack, mode, true, 'Attack succeeded - message replayed');

        } else {
            // Defended mode - with replay protection
            this._log(attack, mode, 'Server receives replayed message...', 'info');
            await this._delay(300);

            // Check timestamp
            this._log(attack, mode, 'Checking timestamp...', 'info');
            await this._delay(300);
            const timestampValid = this._isTimestampValid(capturedMessage.timestamp, 300000); // 5 min window
            
            if (!timestampValid) {
                this._log(attack, mode, '⏱️ Timestamp expired (outside 5-minute window) ✓', 'success');
            } else {
                this._log(attack, mode, 'Timestamp still valid...', 'warning');
            }
            await this._delay(300);

            // Check nonce (simulated as already used)
            this._log(attack, mode, 'Checking nonce in cache...', 'info');
            await this._delay(300);
            this._log(attack, mode, '🔢 Nonce already used (found in cache) ✓', 'success');
            await this._delay(300);

            this._log(attack, mode, '🚫 REPLAY DETECTED - Message rejected!', 'success');
            this._showResult(attack, mode, false, 'Attack blocked by replay protection');
        }
    },

    // ==========================================
    // Ciphertext Tampering Attack Demonstration
    // ==========================================

    async _runTamperingAttack(mode) {
        const attack = 'tampering';

        this._log(attack, mode, 'Starting Ciphertext Tampering demonstration...', 'info');
        await this._delay(500);

        // Step 1: Original encryption
        this._log(attack, mode, 'Alice encrypts message for Bob...', 'info');
        await this._delay(300);

        const plaintext = 'Send $500 to Bob';
        this._log(attack, mode, `Plaintext: "${plaintext}"`, 'info');
        await this._delay(300);

        // Simulate encryption
        const iv = this._generateNonce(12);
        this._log(attack, mode, `IV: ${iv.substring(0, 16)}...`, 'info');
        
        const ciphertext = this._simulateEncrypt(plaintext);
        this._log(attack, mode, `Ciphertext: ${ciphertext.substring(0, 32)}...`, 'info');
        
        const authTag = this._generateNonce(16);
        this._log(attack, mode, `Auth Tag: ${authTag.substring(0, 16)}...`, 'info');
        await this._delay(500);

        // Step 2: Attacker intercepts
        this._log(attack, mode, '🕵️ Attacker intercepts encrypted message...', 'warning');
        await this._delay(500);

        // Step 3: Attacker modifies ciphertext
        this._log(attack, mode, '✏️ Attacker modifies ciphertext bytes...', 'warning');
        await this._delay(300);

        const tamperedCiphertext = this._tamperCiphertext(ciphertext);
        this._log(attack, mode, `Tampered: ${tamperedCiphertext.substring(0, 32)}... (bytes modified)`, 'warning');
        await this._delay(500);

        // Step 4: Decryption attempt
        this._log(attack, mode, '📨 Tampered message sent to Bob...', 'info');
        await this._delay(500);

        if (mode === 'vulnerable') {
            // Vulnerable mode - simulated unauthenticated encryption (like AES-CBC)
            this._log(attack, mode, 'Using AES-CBC (no authentication)...', 'warning');
            await this._delay(300);
            this._log(attack, mode, 'Decrypting tampered ciphertext...', 'info');
            await this._delay(300);
            
            // Simulated corrupted decryption
            const corruptedPlaintext = 'Send $999 to Eve';
            this._log(attack, mode, `Decrypted: "${corruptedPlaintext}"`, 'error');
            this._log(attack, mode, 'No integrity check performed ❌', 'error');
            await this._delay(300);
            this._log(attack, mode, 'Corrupted message processed!', 'error');
            this._showResult(attack, mode, true, 'Attack succeeded - message tampered');

        } else {
            // Defended mode - AES-GCM with authentication
            this._log(attack, mode, 'Using AES-256-GCM (authenticated encryption)...', 'info');
            await this._delay(300);
            this._log(attack, mode, 'Decrypting and verifying auth tag...', 'info');
            await this._delay(500);
            
            this._log(attack, mode, '🔐 Authentication tag verification FAILED ✓', 'success');
            this._log(attack, mode, 'Ciphertext was modified - integrity check failed', 'success');
            await this._delay(300);
            this._log(attack, mode, '🚫 TAMPERING DETECTED - Message rejected!', 'success');
            this._showResult(attack, mode, false, 'Attack blocked by AES-GCM authentication');
        }
    },

    // ==========================================
    // Man-in-the-Middle Attack Demonstration
    // ==========================================

    async _runMITMAttack(mode) {
        const attack = 'mitm';

        this._log(attack, mode, 'Starting Man-in-the-Middle Attack demonstration...', 'info');
        await this._delay(500);

        // Step 1: Key exchange begins
        this._log(attack, mode, 'Alice initiates key exchange with Bob...', 'info');
        await this._delay(300);

        const aliceKeyPair = {
            public: 'Alice_PubKey_' + this._generateNonce(8),
            private: 'Alice_PrivKey_xxx'
        };

        const bobKeyPair = {
            public: 'Bob_PubKey_' + this._generateNonce(8),
            private: 'Bob_PrivKey_xxx'
        };

        this._log(attack, mode, `Alice's Public Key: ${aliceKeyPair.public}`, 'info');
        await this._delay(300);

        // Step 2: Attacker intercepts
        this._log(attack, mode, '🕵️ Eve (attacker) intercepts key exchange...', 'warning');
        await this._delay(500);

        const eveKeyPair = {
            public: 'Eve_PubKey_' + this._generateNonce(8),
            private: 'Eve_PrivKey_xxx'
        };

        this._log(attack, mode, `Eve generates fake key: ${eveKeyPair.public}`, 'warning');
        await this._delay(500);

        if (mode === 'vulnerable') {
            // Vulnerable mode - no signature verification
            this._log(attack, mode, 'No signature verification enabled ❌', 'warning');
            await this._delay(300);

            // Eve substitutes keys
            this._log(attack, mode, 'Eve sends her key to Alice (as "Bob")...', 'warning');
            this._log(attack, mode, 'Eve sends her key to Bob (as "Alice")...', 'warning');
            await this._delay(500);

            this._log(attack, mode, 'Alice accepts Eve\'s key as Bob\'s key', 'error');
            this._log(attack, mode, 'Bob accepts Eve\'s key as Alice\'s key', 'error');
            await this._delay(500);

            // Interception
            this._log(attack, mode, '💬 Alice sends message: "Secret plans"', 'info');
            await this._delay(300);
            this._log(attack, mode, 'Eve decrypts, reads, re-encrypts message', 'error');
            this._log(attack, mode, 'Eve can modify: "Modified plans"', 'error');
            await this._delay(300);
            this._log(attack, mode, 'Bob receives modified message, unaware', 'error');
            this._showResult(attack, mode, true, 'Attack succeeded - communications intercepted');

        } else {
            // Defended mode - with signatures
            this._log(attack, mode, 'RSA-PSS signature verification enabled ✓', 'info');
            await this._delay(300);

            // Bob's key comes with signature
            this._log(attack, mode, 'Alice requests Bob\'s key from server...', 'info');
            await this._delay(300);
            this._log(attack, mode, 'Server returns Bob\'s key with certificate', 'info');
            await this._delay(300);

            // Eve tries to substitute
            this._log(attack, mode, '🕵️ Eve tries to substitute her key...', 'warning');
            await this._delay(500);

            this._log(attack, mode, 'Alice verifies key signature...', 'info');
            await this._delay(300);
            this._log(attack, mode, '✍️ Signature does NOT match Eve\'s key ✓', 'success');
            this._log(attack, mode, 'Key fingerprint mismatch detected', 'success');
            await this._delay(300);
            this._log(attack, mode, '🚫 MITM DETECTED - Key exchange aborted!', 'success');
            this._showResult(attack, mode, false, 'Attack blocked by signature verification');
        }
    },

    // ==========================================
    // Denial of Service Attack Demonstration
    // ==========================================

    async _runDoSAttack(mode) {
        const attack = 'dos';

        this._log(attack, mode, 'Starting Denial of Service Attack demonstration...', 'info');
        await this._delay(500);

        // Configuration
        const totalRequests = 50;
        const requestsPerSecond = mode === 'vulnerable' ? 50 : 50;
        
        this._log(attack, mode, `Attacker sends ${totalRequests} rapid requests...`, 'warning');
        await this._delay(300);

        let successCount = 0;
        let blockedCount = 0;
        let serverLoad = 0;

        // Rate limit configuration (for defended mode)
        const rateLimit = 10; // max requests per "window"
        let requestsInWindow = 0;

        // Simulate requests
        for (let i = 1; i <= totalRequests; i++) {
            if (mode === 'vulnerable') {
                // All requests processed
                successCount++;
                serverLoad += 2;
                
                if (i % 10 === 0) {
                    this._log(attack, mode, `Processed ${i}/${totalRequests} requests... Server load: ${serverLoad}%`, 'warning');
                    await this._delay(100);
                }

                // Server overwhelmed
                if (serverLoad > 80 && i === 40) {
                    this._log(attack, mode, '⚠️ Server resources critical!', 'error');
                }

            } else {
                // Rate limiting applied
                requestsInWindow++;

                if (requestsInWindow <= rateLimit) {
                    successCount++;
                    serverLoad += 1;
                    
                    if (i <= 10 || i % 10 === 0) {
                        this._log(attack, mode, `Request ${i}: Allowed (${requestsInWindow}/${rateLimit} in window)`, 'info');
                    }
                } else {
                    blockedCount++;
                    
                    if (blockedCount === 1) {
                        this._log(attack, mode, `Request ${i}: RATE LIMITED (429 Too Many Requests)`, 'success');
                    } else if (blockedCount % 10 === 0) {
                        this._log(attack, mode, `${blockedCount} requests blocked...`, 'success');
                    }
                }

                // Reset window periodically
                if (i % 15 === 0) {
                    requestsInWindow = 0;
                    this._log(attack, mode, '⏱️ Rate limit window reset', 'info');
                }

                if (i % 10 === 0) {
                    await this._delay(50);
                }
            }
        }

        await this._delay(500);

        // Summary
        this._log(attack, mode, '--- Attack Summary ---', 'info');
        this._log(attack, mode, `Total requests: ${totalRequests}`, 'info');
        this._log(attack, mode, `Processed: ${successCount}`, mode === 'vulnerable' ? 'error' : 'info');
        
        if (mode === 'vulnerable') {
            this._log(attack, mode, `Server load: ${serverLoad}% (OVERLOADED)`, 'error');
            await this._delay(300);
            this._log(attack, mode, '❌ Legitimate users experiencing timeouts!', 'error');
            this._log(attack, mode, 'Service degraded or unavailable', 'error');
            this._showResult(attack, mode, true, 'Attack succeeded - service disrupted');

        } else {
            this._log(attack, mode, `Blocked: ${blockedCount}`, 'success');
            this._log(attack, mode, `Server load: ${serverLoad}% (Healthy)`, 'success');
            await this._delay(300);
            this._log(attack, mode, '✓ Legitimate users unaffected', 'success');
            this._log(attack, mode, '✓ Attacker rate limited', 'success');
            this._showResult(attack, mode, false, 'Attack blocked by rate limiting');
        }
    },

    // ==========================================
    // Helper Functions
    // ==========================================

    /**
     * Generate random nonce
     * @param {number} length - Length in bytes
     * @returns {string} Hex-encoded nonce
     */
    _generateNonce(length = 16) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Check if timestamp is within valid window
     * @param {number} timestamp - Timestamp to check
     * @param {number} window - Valid window in ms
     * @returns {boolean} Is valid
     */
    _isTimestampValid(timestamp, window) {
        // For demo, always return false to simulate expired timestamp
        return false;
    },

    /**
     * Simulate encryption (for demo purposes)
     * @param {string} plaintext - Text to "encrypt"
     * @returns {string} Simulated ciphertext
     */
    _simulateEncrypt(plaintext) {
        // Generate random-looking hex string
        const bytes = new TextEncoder().encode(plaintext);
        const result = [];
        for (let i = 0; i < bytes.length; i++) {
            result.push((bytes[i] ^ 0x42).toString(16).padStart(2, '0'));
        }
        return result.join('') + this._generateNonce(8);
    },

    /**
     * Tamper with ciphertext (for demo purposes)
     * @param {string} ciphertext - Original ciphertext
     * @returns {string} Tampered ciphertext
     */
    _tamperCiphertext(ciphertext) {
        // Flip some bits in the middle
        const chars = ciphertext.split('');
        const midpoint = Math.floor(chars.length / 2);
        for (let i = midpoint; i < midpoint + 4 && i < chars.length; i++) {
            const val = parseInt(chars[i], 16);
            chars[i] = ((val + 7) % 16).toString(16);
        }
        return chars.join('');
    }
};

// Export for global access
window.AttackLab = AttackLab;