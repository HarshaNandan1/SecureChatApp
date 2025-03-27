// Socket.IO instance
const socket = io();

class Chat {
    constructor(socket, userId, recipientId) {
        this.socket = socket;
        this.userId = userId;
        this.recipientId = recipientId;
        this.privateKey = localStorage.getItem('privateKey');

        this.setupSocketHandlers();
        this.loadMessages();
    }

    setupSocketHandlers() {
        this.socket.on('receive_message', async (data) => {
            try {
                const response = await fetch('/encryption/decrypt-message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        encryptedMessage: data.encrypted_message,
                        encryptedAesKey: data.encrypted_aes_key,
                        privateKey: this.privateKey
                    })
                });

                const decryptedData = await response.json();
                if (decryptedData.success) {
                    this.displayMessage({
                        sender_id: data.sender_id,
                        text: decryptedData.decrypted_message,
                        timestamp: new Date().toISOString()
                    });
                }
            } catch (error) {
                console.error('Failed to decrypt message:', error);
            }
        });
    }

    async loadMessages() {
        try {
            const response = await fetch(`/api/messages/${this.recipientId}`);
            const data = await response.json();
            if (data.messages) {
                // Decrypt each message individually
                const decryptedMessages = await Promise.all(data.messages.map(async (msg) => {
                    const decryptResponse = await fetch('/encryption/decrypt-message', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            encryptedMessage: msg.encrypted_message,
                            encryptedAesKey: msg.encrypted_aes_key,
                            privateKey: this.privateKey
                        })
                    });
                    const decryptedData = await decryptResponse.json();
                    return {
                        ...msg,
                        text: decryptedData.decrypted_message
                    };
                }));
                decryptedMessages.forEach(msg => this.displayMessage(msg));
            }
        } catch (error) {
            console.error('Failed to load messages:', error);
        }
    }

    async sendMessage(text) {
        try {
            const response = await fetch('/encryption/encrypt-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: text,
                    recipient_id: this.recipientId
                })
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Failed to encrypt message');
            }

            // Store message in local cache before sending
            const messageData = {
                sender_id: this.userId,
                text: text,
                timestamp: new Date().toISOString(),
                encrypted_message: data.encrypted_message,
                encrypted_aes_key: data.encrypted_aes_key
            };

            // Add to message cache
            if (!sessionStorage.getItem('messages')) {
                sessionStorage.setItem('messages', JSON.stringify([]));
            }
            const messages = JSON.parse(sessionStorage.getItem('messages'));
            messages.push(messageData);
            sessionStorage.setItem('messages', JSON.stringify(messages));

            this.socket.emit('send_message', {
                recipient_id: this.recipientId,
                encrypted_message: data.encrypted_message,
                encrypted_aes_key: data.encrypted_aes_key
            });

            // Display sent message immediately
            this.displayMessage(messageData);

        } catch (error) {
            console.error('Failed to send message:', error);
            alert('Failed to send message. Please try again.');
        }
    }

    async decryptMessage(message) {
        const response = await fetch('/encryption/decrypt-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encryptedMessage: message.encrypted_message,
                encryptedAesKey: message.encrypted_aes_key,
                privateKey: this.privateKey
            })
        });
        const decryptedData = await response.json();
        return decryptedData.decrypted_message;
    }


    displayMessage(message) {
        const messagesContainer = document.querySelector('.messages-container');
        if (!messagesContainer) return;

        // Prevent undefined messages
        if (!message.text && message.encrypted_message) {
            this.decryptMessage(message).then(decryptedText => {
                message.text = decryptedText;
                this.renderMessage(message);
            }).catch(err => {
                console.error('Failed to decrypt message:', err);
                message.text = 'Message encryption error';
                this.renderMessage(message);
            });
        } else {
            this.renderMessage(message);
        }
    }

    renderMessage(message) {
        const messagesContainer = document.querySelector('.messages-container');
        if (!messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.sender_id === this.userId ? 'message-outgoing' : 'message-incoming'}`;
        messageDiv.innerHTML = `
            <div class="message-content">${message.text}</div>
            <div class="message-time">${new Date(message.timestamp).toLocaleTimeString()}</div>
        `;
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

// Initialize chat when document is ready
document.addEventListener('DOMContentLoaded', () => {
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-text');
    const currentUserId = document.getElementById('current-user-id')?.textContent;
    const recipientId = document.getElementById('recipient-id')?.textContent;

    if (!currentUserId || !recipientId || !messageForm || !messageInput) {
        console.error('Required elements not found');
        return;
    }

    const chat = new Chat(socket, currentUserId, recipientId);

    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            chat.sendMessage(message);
            messageInput.value = '';
        }
    });
});