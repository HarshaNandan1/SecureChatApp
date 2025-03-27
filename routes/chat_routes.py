import logging
import datetime
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from flask_socketio import emit, join_room, leave_room
from app import db
from database.db import User, Message
from encryption.encryption import EncryptionService

chat_bp = Blueprint('chat', __name__)
logger = logging.getLogger(__name__)

@chat_bp.route('/')
def index():
    """Render home page"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('auth.login_page'))
    
    # Get all users except current user
    users = User.query.filter(User.id != session['user_id']).all()
    
    return render_template('index.html', current_user=user, users=users)

@chat_bp.route('/chat/<user_id>')
def chat(user_id):
    """Render chat page with a specific user"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    
    if not current_user:
        session.pop('user_id', None)
        return redirect(url_for('auth.login_page'))
    
    # Get the recipient user
    recipient = User.query.filter_by(id=user_id).first()
    
    if not recipient:
        return redirect(url_for('chat.index'))
    
    # Check if both users have registered their public keys
    if not current_user.encrypted_public_key or not recipient.encrypted_public_key:
        return render_template('chat.html', 
                              current_user=current_user, 
                              recipient=recipient, 
                              messages=[], 
                              error="One or both users have not set up encryption keys")
    
    # Get messages between the two users
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    unread_messages = Message.query.filter_by(
        sender_id=recipient.id, 
        recipient_id=current_user.id, 
        read=False
    ).all()
    
    for msg in unread_messages:
        msg.read = True
    
    db.session.commit()
    
    return render_template('chat.html', current_user=current_user, recipient=recipient, messages=messages)

@chat_bp.route('/api/messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    """Get messages between current user and another user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    current_user_id = session['user_id']
    
    # Get messages between the two users
    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user_id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    unread_messages = Message.query.filter_by(
        sender_id=user_id, 
        recipient_id=current_user_id, 
        read=False
    ).all()
    
    for msg in unread_messages:
        msg.read = True
    
    db.session.commit()
    
    # Format messages
    messages_list = []
    for msg in messages:
        messages_list.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'recipient_id': msg.recipient_id,
            'encrypted_message': msg.encrypted_message,
            'encrypted_aes_key': msg.encrypted_aes_key,
            'timestamp': msg.timestamp.isoformat(),
            'read': msg.read
        })
    
    return jsonify({'messages': messages_list})

@chat_bp.route('/api/users', methods=['GET'])
def get_users():
    """Get all users except current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    current_user_id = session['user_id']
    
    # Get all users except current user
    users = User.query.filter(User.id != current_user_id).all()
    
    # Format users
    users_list = []
    for user in users:
        # Check if user has a public key
        has_public_key = user.encrypted_public_key is not None
        
        users_list.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'profile_picture': user.profile_picture,
            'has_public_key': has_public_key
        })
    
    return jsonify({'users': users_list})

@chat_bp.route('/api/public-key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    """Get a user's public key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.filter_by(id=user_id).first()
    
    if not user or not user.encrypted_public_key:
        return jsonify({'error': 'Public key not found'}), 404
    
    try:
        # Decrypt the public key
        public_key = EncryptionService.decrypt_public_key(user.encrypted_public_key)
        return jsonify({'public_key': public_key})
    except Exception as e:
        logger.error(f"Error decrypting public key: {e}")
        return jsonify({'error': 'Failed to decrypt public key'}), 500

def register_socket_events(socketio):
    """Register Socket.IO event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        if 'user_id' not in session:
            return False
        
        # Join a room with the user's ID
        join_room(session['user_id'])
        logger.debug(f"User {session['user_id']} connected")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        if 'user_id' in session:
            leave_room(session['user_id'])
            logger.debug(f"User {session['user_id']} disconnected")
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """Handle sending a message"""
        if 'user_id' not in session:
            emit('error', {'message': 'Not authenticated'})
            return
        
        sender_id = session['user_id']
        recipient_id = data.get('recipient_id')
        encrypted_message = data.get('encrypted_message')
        encrypted_aes_key = data.get('encrypted_aes_key')
        
        if not recipient_id or not encrypted_message or not encrypted_aes_key:
            emit('error', {'message': 'Invalid message data'})
            return
        
        try:
            # Store message in database
            message = Message(
                sender_id=sender_id,
                recipient_id=recipient_id,
                encrypted_message=encrypted_message,
                encrypted_aes_key=encrypted_aes_key,
                timestamp=datetime.datetime.utcnow(),
                read=False
            )
            db.session.add(message)
            db.session.commit()
            
            # Send message to recipient
            message_data = {
                'id': message.id,
                'sender_id': sender_id,
                'encrypted_message': encrypted_message,
                'encrypted_aes_key': encrypted_aes_key,
                'timestamp': message.timestamp.isoformat(),
                'read': False
            }
            
            emit('new_message', message_data, room=recipient_id)
            emit('message_sent', {'message_id': message.id}, room=sender_id)
            
            logger.debug(f"Message sent from {sender_id} to {recipient_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error sending message: {e}")
            emit('error', {'message': 'Failed to send message'}, room=sender_id)
