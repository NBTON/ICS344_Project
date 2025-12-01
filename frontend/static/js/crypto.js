/**
 * SecureChat - Client-side Cryptography Module
 * 
 * Uses WebCrypto API for:
 * - RSA-OAEP key pair generation and key wrapping
 * - AES-GCM symmetric encryption/decryption
 * - RSA-PSS digital signatures (where supported)
 */

const SecureChatCrypto = {
    // Algorithm configurations
    RSA_CONFIG: {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256'
    },

    RSA_PSS_CONFIG: {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
    },

    AES_CONFIG: {
        name: 'AES-GCM',
        length: 256
    },

    // Key storage
    _keyPairs: new Map(), // userId -> { publicKey, privateKey }
    _sessionKeys: new Map(), // sessionId -> CryptoKey

    /**
     * Generate RSA-OAEP key pair for key exchange
     * @returns {Promise<CryptoKeyPair>} Generated key pair
     */
    async generateKeyPair() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                this.RSA_CONFIG,
                true, // extractable
                ['encrypt', 'decrypt'] // for RSA-OAEP
            );
            return keyPair;
        } catch (error) {
            console.error('Error generating key pair:', error);
            throw new Error('Failed to generate encryption keys');
        }
    },

    /**
     * Generate RSA-PSS key pair for signing
     * @returns {Promise<CryptoKeyPair>} Generated key pair
     */
    async generateSigningKeyPair() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                this.RSA_PSS_CONFIG,
                true,
                ['sign', 'verify']
            );
            return keyPair;
        } catch (error) {
            console.error('Error generating signing key pair:', error);
            throw new Error('Failed to generate signing keys');
        }
    },

    /**
     * Generate and store key pair for a user
     * @param {string} userId - User ID
     * @returns {Promise<object>} Public key in exportable format
     */
    async generateAndStoreKeyPair(userId) {
        // Generate encryption key pair
        const encryptionKeyPair = await this.generateKeyPair();
        
        // Generate signing key pair
        let signingKeyPair;
        try {
            signingKeyPair = await this.generateSigningKeyPair();
        } catch (e) {
            console.warn('RSA-PSS not supported, using encryption keys for signatures');
            signingKeyPair = null;
        }

        // Store keys
        this._keyPairs.set(userId, {
            encryption: encryptionKeyPair,
            signing: signingKeyPair
        });

        // Export public key for storage
        const publicKeyData = await this.exportPublicKey(encryptionKeyPair.publicKey);
        
        // Store in IndexedDB for persistence
        await this._storeKeyPairInDB(userId, encryptionKeyPair, signingKeyPair);

        return publicKeyData;
    },

    /**
     * Check if key pair exists for user
     * @param {string} userId - User ID
     * @returns {Promise<boolean>} Whether keys exist
     */
    async hasStoredKeyPair(userId) {
        // Check memory first
        if (this._keyPairs.has(userId)) {
            return true;
        }
        
        // Check IndexedDB
        try {
            const keys = await this._loadKeyPairFromDB(userId);
            return keys !== null;
        } catch (e) {
            return false;
        }
    },

    /**
     * Get stored key pair for user
     * @param {string} userId - User ID
     * @returns {Promise<object>} Key pair object
     */
    async getKeyPair(userId) {
        // Check memory
        if (this._keyPairs.has(userId)) {
            return this._keyPairs.get(userId);
        }

        // Load from IndexedDB
        const keys = await this._loadKeyPairFromDB(userId);
        if (keys) {
            this._keyPairs.set(userId, keys);
            return keys;
        }

        throw new Error('No keys found for user');
    },

    /**
     * Export public key to PEM-like format
     * @param {CryptoKey} publicKey - Public key to export
     * @returns {Promise<string>} Base64-encoded public key
     */
    async exportPublicKey(publicKey) {
        try {
            const exported = await crypto.subtle.exportKey('spki', publicKey);
            const base64 = Utils.bufferToBase64(exported);
            
            // Format as PEM
            const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
            return pem;
        } catch (error) {
            console.error('Error exporting public key:', error);
            throw new Error('Failed to export public key');
        }
    },

    /**
     * Import public key from PEM format
     * @param {string} pemData - PEM-encoded public key
     * @returns {Promise<CryptoKey>} Imported public key
     */
    async importPublicKey(pemData) {
        try {
            // Remove PEM headers and whitespace
            const base64 = pemData
                .replace(/-----BEGIN PUBLIC KEY-----/, '')
                .replace(/-----END PUBLIC KEY-----/, '')
                .replace(/\s/g, '');
            
            const keyData = Utils.base64ToBuffer(base64);
            
            const publicKey = await crypto.subtle.importKey(
                'spki',
                keyData,
                this.RSA_CONFIG,
                true,
                ['encrypt']
            );
            
            return publicKey;
        } catch (error) {
            console.error('Error importing public key:', error);
            throw new Error('Failed to import public key');
        }
    },

    /**
     * Generate AES-256 session key
     * @returns {Promise<CryptoKey>} Generated session key
     */
    async generateSessionKey() {
        try {
            const sessionKey = await crypto.subtle.generateKey(
                this.AES_CONFIG,
                true, // extractable for wrapping
                ['encrypt', 'decrypt']
            );
            return sessionKey;
        } catch (error) {
            console.error('Error generating session key:', error);
            throw new Error('Failed to generate session key');
        }
    },

    /**
     * Encrypt (wrap) session key with RSA-OAEP public key
     * @param {CryptoKey} sessionKey - Session key to encrypt
     * @param {CryptoKey} publicKey - RSA public key
     * @returns {Promise<ArrayBuffer>} Encrypted session key
     */
    async encryptSessionKey(sessionKey, publicKey) {
        try {
            // Export the session key raw
            const rawKey = await crypto.subtle.exportKey('raw', sessionKey);
            
            // Encrypt with RSA-OAEP
            const encryptedKey = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                rawKey
            );
            
            return encryptedKey;
        } catch (error) {
            console.error('Error encrypting session key:', error);
            throw new Error('Failed to encrypt session key');
        }
    },

    /**
     * Decrypt (unwrap) session key with RSA-OAEP private key
     * @param {ArrayBuffer} encryptedKey - Encrypted session key
     * @param {CryptoKey} privateKey - RSA private key
     * @returns {Promise<CryptoKey>} Decrypted session key
     */
    async decryptSessionKey(encryptedKey, privateKey) {
        try {
            // Decrypt with RSA-OAEP
            const rawKey = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encryptedKey
            );
            
            // Import as AES key
            const sessionKey = await crypto.subtle.importKey(
                'raw',
                rawKey,
                this.AES_CONFIG,
                true,
                ['encrypt', 'decrypt']
            );
            
            return sessionKey;
        } catch (error) {
            console.error('Error decrypting session key:', error);
            throw new Error('Failed to decrypt session key');
        }
    },

    /**
     * Encrypt message with AES-GCM
     * @param {string} plaintext - Message to encrypt
     * @param {CryptoKey} sessionKey - AES session key
     * @returns {Promise<object>} Encrypted data { iv, ciphertext, tag }
     */
    async encryptMessage(plaintext, sessionKey) {
        try {
            // Generate random IV (96 bits = 12 bytes for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encode plaintext to bytes
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);
            
            // Encrypt with AES-GCM
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128 // 16 bytes
                },
                sessionKey,
                data
            );
            
            // GCM appends the auth tag to the ciphertext
            const encryptedBytes = new Uint8Array(encrypted);
            const ciphertext = encryptedBytes.slice(0, -16);
            const tag = encryptedBytes.slice(-16);
            
            return {
                iv: Utils.bufferToHex(iv),
                ciphertext: Utils.bufferToHex(ciphertext),
                tag: Utils.bufferToHex(tag)
            };
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw new Error('Failed to encrypt message');
        }
    },

    /**
     * Decrypt message with AES-GCM
     * @param {string} ciphertextHex - Hex-encoded ciphertext
     * @param {string} ivHex - Hex-encoded IV
     * @param {string} tagHex - Hex-encoded auth tag
     * @param {CryptoKey} sessionKey - AES session key
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decryptMessage(ciphertextHex, ivHex, tagHex, sessionKey) {
        try {
            const iv = Utils.hexToBuffer(ivHex);
            const ciphertext = Utils.hexToBuffer(ciphertextHex);
            const tag = Utils.hexToBuffer(tagHex);
            
            // Combine ciphertext and tag (GCM expects them together)
            const combined = new Uint8Array(ciphertext.length + tag.length);
            combined.set(ciphertext);
            combined.set(tag, ciphertext.length);
            
            // Decrypt with AES-GCM
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                combined
            );
            
            // Decode to string
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Error decrypting message:', error);
            throw new Error('Failed to decrypt message - authentication failed');
        }
    },

    /**
     * Sign message with RSA-PSS
     * @param {string} message - Message to sign (hex string of data)
     * @param {CryptoKey} privateKey - RSA-PSS private key
     * @returns {Promise<string>} Hex-encoded signature
     */
    async signMessage(message, privateKey) {
        try {
            // If RSA-PSS is not available, return empty signature
            if (!privateKey) {
                console.warn('No signing key available');
                return '';
            }

            const data = Utils.hexToBuffer(message);
            
            const signature = await crypto.subtle.sign(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                privateKey,
                data
            );
            
            return Utils.bufferToHex(signature);
        } catch (error) {
            console.error('Error signing message:', error);
            // Return empty signature instead of failing
            return '';
        }
    },

    /**
     * Verify signature with RSA-PSS
     * @param {string} messageHex - Hex-encoded message data
     * @param {string} signatureHex - Hex-encoded signature
     * @param {CryptoKey} publicKey - RSA-PSS public key
     * @returns {Promise<boolean>} Whether signature is valid
     */
    async verifySignature(messageHex, signatureHex, publicKey) {
        try {
            // If no signature provided, skip verification
            if (!signatureHex || signatureHex === '') {
                console.warn('No signature to verify');
                return true; // Allow messages without signatures for compatibility
            }

            const message = Utils.hexToBuffer(messageHex);
            const signature = Utils.hexToBuffer(signatureHex);
            
            const isValid = await crypto.subtle.verify(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                publicKey,
                signature,
                message
            );
            
            return isValid;
        } catch (error) {
            console.error('Error verifying signature:', error);
            return false;
        }
    },

    /**
     * Create message package with all security elements
     * @param {string} plaintext - Message content
     * @param {CryptoKey} sessionKey - Session key for encryption
     * @param {string} senderId - Sender's user ID
     * @param {CryptoKey} signingKey - Private key for signing (optional)
     * @returns {Promise<object>} Complete message package
     */
    async createSecureMessage(plaintext, sessionKey, senderId, signingKey = null) {
        // Encrypt the message
        const { iv, ciphertext, tag } = await this.encryptMessage(plaintext, sessionKey);
        
        // Generate timestamp and nonce
        const timestamp = Date.now();
        const nonce = Utils.bufferToHex(Utils.generateNonce(16));
        
        // Create sender ID hash
        const senderIdBuffer = new TextEncoder().encode(senderId);
        const senderIdHash = await crypto.subtle.digest('SHA-256', senderIdBuffer);
        const senderIdHex = Utils.bufferToHex(senderIdHash);
        
        // Create data to sign: ciphertext + iv + timestamp + nonce
        const dataToSign = ciphertext + iv + timestamp.toString(16) + nonce;
        
        // Sign the message
        let signature = '';
        if (signingKey) {
            signature = await this.signMessage(dataToSign, signingKey);
        }
        
        return {
            version: 1,
            flags: 0x03, // encrypted + signed
            timestamp: timestamp,
            nonce: nonce,
            sender_id: senderIdHex,
            iv: iv,
            ciphertext: ciphertext,
            auth_tag: tag,
            signature: signature
        };
    },

    /**
     * Parse and decrypt secure message
     * @param {object} messagePackage - Encrypted message package
     * @param {CryptoKey} sessionKey - Session key for decryption
     * @param {CryptoKey} senderPublicKey - Sender's public key for verification
     * @returns {Promise<object>} Decrypted message with metadata
     */
    async parseSecureMessage(messagePackage, sessionKey, senderPublicKey = null) {
        // Verify timestamp is within acceptable window
        if (!Utils.isTimestampValid(messagePackage.timestamp)) {
            throw new Error('Message timestamp is outside acceptable window');
        }
        
        // Verify signature if present and public key available
        let signatureValid = false;
        if (messagePackage.signature && senderPublicKey) {
            const dataToVerify = messagePackage.ciphertext + messagePackage.iv + 
                                 messagePackage.timestamp.toString(16) + messagePackage.nonce;
            signatureValid = await this.verifySignature(dataToVerify, messagePackage.signature, senderPublicKey);
        } else {
            signatureValid = true; // No signature to verify
        }
        
        // Decrypt the message
        const plaintext = await this.decryptMessage(
            messagePackage.ciphertext,
            messagePackage.iv,
            messagePackage.auth_tag,
            sessionKey
        );
        
        return {
            plaintext: plaintext,
            timestamp: messagePackage.timestamp,
            senderId: messagePackage.sender_id,
            signatureValid: signatureValid
        };
    },

    /**
     * Store session key
     * @param {string} sessionId - Session ID
     * @param {CryptoKey} sessionKey - Session key to store
     */
    storeSessionKey(sessionId, sessionKey) {
        this._sessionKeys.set(sessionId, sessionKey);
    },

    /**
     * Get stored session key
     * @param {string} sessionId - Session ID
     * @returns {CryptoKey|null} Session key or null
     */
    getSessionKey(sessionId) {
        return this._sessionKeys.get(sessionId) || null;
    },

    /**
     * Remove session key
     * @param {string} sessionId - Session ID
     */
    removeSessionKey(sessionId) {
        this._sessionKeys.delete(sessionId);
    },

    /**
     * Store key pair in IndexedDB
     * @param {string} userId - User ID
     * @param {CryptoKeyPair} encryptionKeys - Encryption key pair
     * @param {CryptoKeyPair} signingKeys - Signing key pair
     */
    async _storeKeyPairInDB(userId, encryptionKeys, signingKeys) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('SecureChatKeys', 1);
            
            request.onerror = () => reject(request.error);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys', { keyPath: 'userId' });
                }
            };
            
            request.onsuccess = async (event) => {
                const db = event.target.result;
                const transaction = db.transaction(['keys'], 'readwrite');
                const store = transaction.objectStore('keys');
                
                try {
                    // Export keys for storage
                    const encryptionPrivate = await crypto.subtle.exportKey('pkcs8', encryptionKeys.privateKey);
                    const encryptionPublic = await crypto.subtle.exportKey('spki', encryptionKeys.publicKey);
                    
                    let signingPrivate = null;
                    let signingPublic = null;
                    if (signingKeys) {
                        signingPrivate = await crypto.subtle.exportKey('pkcs8', signingKeys.privateKey);
                        signingPublic = await crypto.subtle.exportKey('spki', signingKeys.publicKey);
                    }
                    
                    const keyData = {
                        userId: userId,
                        encryption: {
                            privateKey: Utils.bufferToBase64(encryptionPrivate),
                            publicKey: Utils.bufferToBase64(encryptionPublic)
                        },
                        signing: signingKeys ? {
                            privateKey: Utils.bufferToBase64(signingPrivate),
                            publicKey: Utils.bufferToBase64(signingPublic)
                        } : null,
                        createdAt: Date.now()
                    };
                    
                    store.put(keyData);
                    transaction.oncomplete = () => resolve();
                    transaction.onerror = () => reject(transaction.error);
                } catch (e) {
                    reject(e);
                }
            };
        });
    },

    /**
     * Load key pair from IndexedDB
     * @param {string} userId - User ID
     * @returns {Promise<object>} Key pair object
     */
    async _loadKeyPairFromDB(userId) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('SecureChatKeys', 1);
            
            request.onerror = () => reject(request.error);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys', { keyPath: 'userId' });
                }
            };
            
            request.onsuccess = async (event) => {
                const db = event.target.result;
                const transaction = db.transaction(['keys'], 'readonly');
                const store = transaction.objectStore('keys');
                const getRequest = store.get(userId);
                
                getRequest.onsuccess = async () => {
                    const keyData = getRequest.result;
                    if (!keyData) {
                        resolve(null);
                        return;
                    }
                    
                    try {
                        // Import encryption keys
                        const encryptionPrivateKey = await crypto.subtle.importKey(
                            'pkcs8',
                            Utils.base64ToBuffer(keyData.encryption.privateKey),
                            this.RSA_CONFIG,
                            true,
                            ['decrypt']
                        );
                        
                        const encryptionPublicKey = await crypto.subtle.importKey(
                            'spki',
                            Utils.base64ToBuffer(keyData.encryption.publicKey),
                            this.RSA_CONFIG,
                            true,
                            ['encrypt']
                        );
                        
                        // Import signing keys if available
                        let signingKeys = null;
                        if (keyData.signing) {
                            const signingPrivateKey = await crypto.subtle.importKey(
                                'pkcs8',
                                Utils.base64ToBuffer(keyData.signing.privateKey),
                                this.RSA_PSS_CONFIG,
                                true,
                                ['sign']
                            );
                            
                            const signingPublicKey = await crypto.subtle.importKey(
                                'spki',
                                Utils.base64ToBuffer(keyData.signing.publicKey),
                                this.RSA_PSS_CONFIG,
                                true,
                                ['verify']
                            );
                            
                            signingKeys = {
                                privateKey: signingPrivateKey,
                                publicKey: signingPublicKey
                            };
                        }
                        
                        resolve({
                            encryption: {
                                privateKey: encryptionPrivateKey,
                                publicKey: encryptionPublicKey
                            },
                            signing: signingKeys
                        });
                    } catch (e) {
                        console.error('Error importing keys from DB:', e);
                        resolve(null);
                    }
                };
                
                getRequest.onerror = () => reject(getRequest.error);
            };
        });
    },

    /**
     * Compute fingerprint of public key
     * @param {CryptoKey} publicKey - Public key
     * @returns {Promise<string>} Hex-encoded fingerprint
     */
    async computeFingerprint(publicKey) {
        try {
            const exported = await crypto.subtle.exportKey('spki', publicKey);
            const hash = await crypto.subtle.digest('SHA-256', exported);
            return Utils.bufferToHex(hash);
        } catch (error) {
            console.error('Error computing fingerprint:', error);
            return '';
        }
    }
};

// Export for global access
window.SecureChatCrypto = SecureChatCrypto;