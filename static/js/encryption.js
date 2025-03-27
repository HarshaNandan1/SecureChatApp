// Encryption Service for handling client-side encryption operations
class EncryptionService {
    constructor() {
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    // Check if private key exists in localStorage
    static hasPrivateKey() {
        return !!localStorage.getItem('privateKey');
    }

    // Get private key from localStorage
    static getPrivateKey() {
        return localStorage.getItem('privateKey');
    }

    // Store private key in localStorage
    static storePrivateKey(privateKey) {
        localStorage.setItem('privateKey', privateKey);
    }

    // Request new keys from server and store private key
    async generateAndStoreKeys() {
        try {
            const response = await fetch('/encryption/generate-keys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to generate keys');
            }

            const data = await response.json();
            if (data.success && data.privateKey) {
                EncryptionService.storePrivateKey(data.privateKey);
                return true;
            }
            throw new Error('Invalid server response');
        } catch (error) {
            console.error('Error generating keys:', error);
            throw error;
        }
    }
    
}

// Add global availability
if (typeof window !== 'undefined') {
    window.EncryptionService = EncryptionService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = EncryptionService;
}