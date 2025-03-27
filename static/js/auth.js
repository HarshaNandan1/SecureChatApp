/**
 * Auth Manager
 * Handles Firebase authentication and key management
 */
class AuthManager {
    constructor(firebaseConfig) {
        // Initialize Firebase
        if (!firebase.apps.length) {
            firebase.initializeApp(firebaseConfig);
        }
        
        this.auth = firebase.auth();
        this.googleProvider = new firebase.auth.GoogleAuthProvider();
        this.encryption = new EncryptionService();
    }

    /**
     * Sign in with email and password
     */
    async signInWithEmailPassword(email, password) {
        try {
            const userCredential = await this.auth.signInWithEmailAndPassword(email, password);
            const idToken = await userCredential.user.getIdToken();
            return await this._authenticateWithServer(idToken);
        } catch (error) {
            console.error('Email/password sign in error:', error);
            throw error;
        }
    }

    /**
     * Sign in with Google
     */
    async signInWithGoogle() {
        try {
            const result = await this.auth.signInWithPopup(this.googleProvider);
            const idToken = await result.user.getIdToken();
            return await this._authenticateWithServer(idToken);
        } catch (error) {
            console.error('Google sign in error:', error);
            throw error;
        }
    }

    /**
     * Sign up with email and password
     */
    async signUpWithEmailPassword(email, password, name) {
        try {
            const userCredential = await this.auth.createUserWithEmailAndPassword(email, password);
            
            // Update display name if provided
            if (name) {
                await userCredential.user.updateProfile({
                    displayName: name
                });
            }
            
            const idToken = await userCredential.user.getIdToken();
            const authResult = await this._authenticateWithServer(idToken);
            
            // Generate encryption keys for new user
            await this.encryption.generateAndStoreKeys();
            
            return authResult;
        } catch (error) {
            console.error('Email/password sign up error:', error);
            throw error;
        }
    }

    /**
     * Sign out
     */
    async signOut() {
        try {
            await this.auth.signOut();
            
            // Clear session on server
            await fetch('/logout', { method: 'POST' });
            
            // Clear private key from local storage
            localStorage.removeItem('privateKey');
            
            return true;
        } catch (error) {
            console.error('Sign out error:', error);
            throw error;
        }
    }

    /**
     * Get current user
     */
    async getCurrentUser() {
        try {
            const response = await fetch('/auth/user');
            return await response.json();
        } catch (error) {
            console.error('Get current user error:', error);
            throw error;
        }
    }

    /**
     * Authenticate with server using Firebase ID token
     */
    async _authenticateWithServer(idToken) {
        try {
            const response = await fetch('/auth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token: idToken })
            });
            
            return await response.json();
        } catch (error) {
            console.error('Server authentication error:', error);
            throw error;
        }
    }
}
