import logging
from flask import Blueprint, request, jsonify, session
from encryption.encryption import EncryptionService
from database.db import User, db

encryption_bp = Blueprint('encryption', __name__)
logger = logging.getLogger(__name__)

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
        # Get recipient's public key
        recipient = User.query.filter_by(id=recipient_id).first()
        if not recipient or not recipient.encrypted_public_key:
            return jsonify({'error': 'Recipient has no public key registered'}), 404

        # Decrypt the recipient's public key
        recipient_public_key = EncryptionService.decrypt_public_key(recipient.encrypted_public_key)

        # Generate a random AES key
        aes_key = EncryptionService.generate_aes_key()

        # Encrypt the message with AES
        encrypted_message = EncryptionService.encrypt_message_with_aes(message, aes_key)

        # Encrypt the AES key with recipient's RSA public key
        encrypted_aes_key = EncryptionService.encrypt_aes_key_with_rsa(aes_key, recipient_public_key)

        return jsonify({
            'success': True,
            'encrypted_message': encrypted_message,
            'encrypted_aes_key': encrypted_aes_key
        })
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return jsonify({'error': 'Failed to encrypt message'}), 500

@encryption_bp.route('/encryption/decrypt-message', methods=['POST'])
def decrypt_message():
    """Decrypt a message using user's private key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.get_json()
    encrypted_message = data.get('encryptedMessage')
    encrypted_aes_key = data.get('encryptedAesKey')
    private_key = data.get('privateKey')

    if not encrypted_message or not encrypted_aes_key or not private_key:
        return jsonify({'error': 'Encrypted message, AES key, and private key are required'}), 400

    # Verify the private key matches the user's public key
    try:
        user = User.query.filter_by(id=session['user_id']).first()
        if not user or not user.encrypted_public_key:
            return jsonify({'error': 'User has no registered keys'}), 404

        # Verify key pair match before decryption
        if not EncryptionService.verify_key_pair(private_key, user.encrypted_public_key):
            return jsonify({'error': 'Invalid private key'}), 400

        # Decrypt the AES key using the private key
        aes_key = EncryptionService.decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

        # Decrypt the message using the AES key
        decrypted_message = EncryptionService.decrypt_message_with_aes(encrypted_message, aes_key)

        return jsonify({
            'success': True,
            'decrypted_message': decrypted_message
        })
    except Exception as e:
        logger.error(f"Error decrypting message: {e}")
        return jsonify({'error': 'Failed to decrypt message'}), 500

@encryption_bp.route('/encryption/generate-keys', methods=['POST'])
def generate_keys():
    """Generate a new RSA key pair for the user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Generate a new RSA key pair for message encryption
        private_key, public_key = EncryptionService.generate_rsa_key_pair()
        if not private_key or not public_key:
            raise ValueError("Failed to generate key pair")

        # Store only the public key in database after encryption
        encrypted_public_key = EncryptionService.encrypt_public_key(public_key)
        if not encrypted_public_key:
            raise ValueError("Failed to encrypt public key")

        # Store the encrypted public key in the database
        user = User.query.filter_by(id=session['user_id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user.encrypted_public_key = encrypted_public_key  
        db.session.commit()

        # Return both keys - private key should be stored only on client side
        return jsonify({
            'success': True,
            'privateKey': private_key, # Client must store this securely
            'publicKey': public_key
        })
    except ValueError as ve:
        db.session.rollback()
        logger.error(f"Validation error generating keys: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating keys: {e}")
        return jsonify({'error': 'Failed to generate encryption keys. Please try again.'}), 500

@encryption_bp.route('/encryption/get-public-key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    """Get a user's public key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.encrypted_public_key:
            return jsonify({'error': 'User has no public key registered'}), 404

        # Decrypt the public key for use
        public_key = EncryptionService.decrypt_public_key(user.encrypted_public_key)

        return jsonify({
            'success': True,
            'publicKey': public_key
        })
    except Exception as e:
        logger.error(f"Error getting public key: {e}")
        return jsonify({'error': str(e)}), 500
import logging
from flask import Blueprint, request, jsonify, session
from encryption.encryption import EncryptionService
from database.db import User, db

encryption_bp = Blueprint('encryption', __name__)
logger = logging.getLogger(__name__)

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
        # Get recipient's public key
        recipient = User.query.filter_by(id=recipient_id).first()
        if not recipient or not recipient.encrypted_public_key:
            return jsonify({'error': 'Recipient has no public key registered'}), 404

        # Decrypt the recipient's public key
        recipient_public_key = EncryptionService.decrypt_public_key(recipient.encrypted_public_key)

        # Generate a random AES key
        aes_key = EncryptionService.generate_aes_key()

        # Encrypt the message with AES
        encrypted_message = EncryptionService.encrypt_message_with_aes(message, aes_key)

        # Encrypt the AES key with recipient's RSA public key
        encrypted_aes_key = EncryptionService.encrypt_aes_key_with_rsa(aes_key, recipient_public_key)

        return jsonify({
            'success': True,
            'encrypted_message': encrypted_message,
            'encrypted_aes_key': encrypted_aes_key
        })
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return jsonify({'error': 'Failed to encrypt message'}), 500

@encryption_bp.route('/encryption/decrypt-message', methods=['POST'])
def decrypt_message():
    """Decrypt a message using user's private key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.get_json()
    encrypted_message = data.get('encryptedMessage')
    encrypted_aes_key = data.get('encryptedAesKey')
    private_key = data.get('privateKey')

    if not encrypted_message or not encrypted_aes_key or not private_key:
        return jsonify({'error': 'Encrypted message, AES key, and private key are required'}), 400

    try:
        user = User.query.filter_by(id=session['user_id']).first()
        if not user or not user.encrypted_public_key:
            return jsonify({'error': 'User has no registered keys'}), 404

        # Verify key pair match before decryption
        if not EncryptionService.verify_key_pair(private_key, user.encrypted_public_key):
            return jsonify({'error': 'Invalid private key'}), 400

        # Decrypt the AES key using the private key
        aes_key = EncryptionService.decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

        # Decrypt the message using the AES key
        decrypted_message = EncryptionService.decrypt_message_with_aes(encrypted_message, aes_key)

        return jsonify({
            'success': True,
            'decrypted_message': decrypted_message
        })
    except Exception as e:
        logger.error(f"Error decrypting message: {e}")
        return jsonify({'error': 'Failed to decrypt message'}), 500

@encryption_bp.route('/encryption/generate-keys', methods=['POST'])
def generate_keys():
    """Generate a new RSA key pair for the user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Generate a new RSA key pair for message encryption
        private_key, public_key = EncryptionService.generate_rsa_key_pair()
        if not private_key or not public_key:
            raise ValueError("Failed to generate key pair")

        # Store only the public key in database after encryption
        encrypted_public_key = EncryptionService.encrypt_public_key(public_key)
        if not encrypted_public_key:
            raise ValueError("Failed to encrypt public key")

        # Store the encrypted public key in the database
        user = User.query.filter_by(id=session['user_id']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user.encrypted_public_key = encrypted_public_key
        db.session.commit()

        # Return both keys - private key should be stored only on client side
        return jsonify({
            'success': True,
            'privateKey': private_key,
            'publicKey': public_key
        })
    except ValueError as ve:
        db.session.rollback()
        logger.error(f"Validation error generating keys: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating keys: {e}")
        return jsonify({'error': 'Failed to generate encryption keys. Please try again.'}), 500

@encryption_bp.route('/encryption/get-public-key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    """Get a user's public key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.encrypted_public_key:
            return jsonify({'error': 'User has no public key registered'}), 404

        # Decrypt the public key for use
        public_key = EncryptionService.decrypt_public_key(user.encrypted_public_key)

        return jsonify({
            'success': True,
            'publicKey': public_key
        })
    except Exception as e:
        logger.error(f"Error getting public key: {e}")
        return jsonify({'error': str(e)}), 500
