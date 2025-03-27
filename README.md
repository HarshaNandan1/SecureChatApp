## Overview

The Secure Chat Application is a real-time encrypted messaging platform that allows users to communicate securely using end-to-end encryption. Built with Flask, Firebase Authentication, and WebSocket technology, it ensures that messages are encrypted before they leave the sender and can only be decrypted by the intended recipient.

## Technical Stack

- *Backend*: Flask, Flask-SocketIO
- *Frontend*: JavaScript, HTML, Bootstrap
- *Database*: SQLite via SQLAlchemy
- *Authentication*: Firebase Auth
- *Encryption*: PyCryptodome
- *Real-time Communication*: eventlet via Socket.IO

## Directory Structure

a breakdown of the directory structure which helps in understanding the organization of the application:

├── routes/ # Route handlers for the application
├── encryption/ # Encryption logic and key management
├── firebase/ # Configuration related to Firebase
├── static/ # Static files (CSS, JS)
├── templates/ # HTML templates for the frontend
└── database/ # Database models and session management


## Core Functionalities

The application includes several important features:

1. *User Authentication*: Users can register and authenticate using Firebase.
2. *Key Management*: Each user generates RSA keys for message encryption.
3. *Messaging*: Real-time messaging through WebSocket ensuring end-to-end encryption.
4. *Profile Management*: Users can manage their profiles and view chatting history.

## Key Code Components

This section will explain key parts of the codebase, starting with the Chat class used in static/js/chat.js.

### Chat Class (chat.js)

The Chat class manages all interactions related to messaging, including:

- Loading recipient's public key
- Sending and loading messages
- Displaying messages in the UI
- Handle WebSocket connections for real-time messaging

Here's a detailed breakdown:

```javascript
class Chat {
    constructor(socket, userId, recipientId) {
        this.socket = socket;
        this.userId = userId;
        this.recipientId = recipientId;
        this.privateKey = localStorage.getItem('privateKey');
        this.messagesContainer = document.getElementById('messages-list');
        this.messageCache = new Map();
        this.messageForm = document.getElementById('message-form');
        this.recipientPublicKey = null;

        // Load recipient's key and setup listeners
        if (!this.privateKey) {
            console.error('Private key not found in localStorage');
            this.showError('Missing encryption key - please regenerate your keys');
            return;
        }

        this.loadRecipientPublicKey().then(() => {
            this.setupEventListeners();
            this.setupSocketHandlers();
            this.loadMessages();
        }).catch(error => {
            console.error('Failed to load recipient public key:', error);
            this.showError('Failed to load recipient\'s public key');
        });
    }

    // Load Recipient's Public Key
    async loadRecipientPublicKey() {
        try {
            const response = await fetch(/api/public-key/${this.recipientId});
            if (!response.ok) throw new Error('Failed to fetch public key');
            const data = await response.json();
            this.recipientPublicKey = data.public_key;
        } catch (error) {
            throw new Error('Could not load recipient public key');
        }
    }

    // Handle Send Message event
    async sendMessage(text) {
        // Implementation for sending encrypted messages
    }

    // Load previous messages for the chat
    async loadMessages() {
        // Implementation for loading messages from the server
    }

    // Other methods like showError(), displayMessage(), etc.
}


Encryption Routes (routes/encryption_routes.py)
This file contains the endpoints for message encryption and decryption:

@encryption_bp.route('/encryption/encrypt-message', methods=['POST'])
def encrypt_message():
    """Encrypt a message for a recipient"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.get_json()
    message = data.get('message')
    recipient_id = data.get('recipient_id')

    if not message or not recipient_id:
        return jsonify({'error': 'Message and recipient_id are required'}), 400

    try:
        recipient = User.query.filter_by(id=recipient_id).first()
        if not recipient or not recipient.encrypted_public_key:
            return jsonify({'error': 'Recipient has no public key registered'}), 404

        # Encrypt the message
        ...
        
        return jsonify({
            'success': True,
            'encrypted_message': encrypted_message,
            'encrypted_aes_key': encrypted_aes_key
        })
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return jsonify({'error': 'Failed to encrypt message'}), 500

## Security Features
The application implements several security features to ensure secure communication:

End-to-End Encryption (E2EE): Using RSA for key exchanges and AES for encrypting message contents guarantees that only intended users can read the messages.
Firebase Authentication: Secures user management and session handling.
Public/Private Key Management: Users generate RSA keys to keep their communications encrypted.
User Guidelines
Follow these steps to use the Secure Chat Application:

Visit the Application: Go to the designated URL where the application is hosted.
User Registration: Sign up or log in using Firebase authentication.
Generating Keys: Ensure you generate your encryption keys from your profile settings to start chatting securely.
Chatting: Select a contact from your user list to start sending messages.

## Conclusion
This report captures the essential components and features of the Secure Chat Application, its architecture, and how the encryption framework is implemented. Understanding these components allows for better usage and potential improvements to enhance user experience and security.
