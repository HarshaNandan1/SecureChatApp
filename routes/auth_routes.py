import logging
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from app import db
from database.db import User
from firebase.auth import FirebaseAuthService
from firebase.firebase_config import firebase_config
from encryption.encryption import EncryptionService

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['GET'])
def login_page():
    """Render login page"""
    if 'user_id' in session:
        return redirect(url_for('chat.index'))
    
    return render_template('login.html', 
                          firebase_api_key=firebase_config['apiKey'],
                          firebase_auth_domain=firebase_config['authDomain'],
                          firebase_project_id=firebase_config['projectId'],
                          firebase_app_id=firebase_config['appId'])

@auth_bp.route('/signup', methods=['GET'])
def signup_page():
    """Render signup page"""
    if 'user_id' in session:
        return redirect(url_for('chat.index'))
    
    return render_template('signup.html', 
                          firebase_api_key=firebase_config['apiKey'],
                          firebase_auth_domain=firebase_config['authDomain'],
                          firebase_project_id=firebase_config['projectId'],
                          firebase_app_id=firebase_config['appId'])

@auth_bp.route('/auth/token', methods=['POST'])
def authenticate_token():
    """Verify Firebase token and authenticate user"""
    data = request.get_json()
    id_token = data.get('token')
    
    if not id_token:
        return jsonify({'error': 'No token provided'}), 400
    
    # Verify token and get user info
    user_data = FirebaseAuthService.verify_firebase_token(id_token)
    
    if not user_data:
        logger.error("Failed to verify token")
        return jsonify({'error': 'Invalid token'}), 401
        
    logger.debug(f"Successfully verified token for user: {user_data.get('email')}")
    
    # Create or update user in database
    user = FirebaseAuthService.create_or_update_user(user_data)
    
    if not user:
        logger.error("Failed to create or update user")
        return jsonify({'error': 'Failed to authenticate user'}), 500
    
    # Store user ID in session
    session['user_id'] = user.id
    logger.debug(f"Successfully authenticated user: {user.email}")
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name
        }
    })

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    """Login with email and password"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    try:
        # Use Firebase Auth service to authenticate
        user_data = FirebaseAuthService.login_with_email_password(email, password)
        
        if not user_data:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Create or update user in database
        user = FirebaseAuthService.create_or_update_user(user_data)
        
        if not user:
            return jsonify({'error': 'Failed to authenticate user'}), 500
        
        # Store user ID in session
        session['user_id'] = user.id
        logger.debug(f"Successfully authenticated user: {user.email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        })
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': str(e)}), 401

@auth_bp.route('/auth/signup', methods=['POST'])
def signup():
    """Sign up with email and password"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    try:
        # Use Firebase Auth service to create a new user
        user_data = FirebaseAuthService.signup_with_email_password(email, password, name)
        
        if not user_data:
            return jsonify({'error': 'Failed to create user'}), 500
        
        # Create or update user in database
        user = FirebaseAuthService.create_or_update_user(user_data)
        
        if not user:
            return jsonify({'error': 'Failed to create user record'}), 500
        
        # Store user ID in session
        session['user_id'] = user.id
        logger.debug(f"Successfully created user: {user.email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        })
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/auth/google', methods=['POST'])
def google_auth():
    """Handle Google authentication"""
    data = request.get_json()
    id_token = data.get('token')
    
    if not id_token:
        return jsonify({'error': 'No token provided'}), 400
    
    try:
        # Verify the Google ID token
        user_data = FirebaseAuthService.verify_google_token(id_token)
        
        if not user_data:
            return jsonify({'error': 'Invalid Google token'}), 401
        
        # Create or update user in database
        user = FirebaseAuthService.create_or_update_user(user_data)
        
        if not user:
            return jsonify({'error': 'Failed to authenticate with Google'}), 500
        
        # Store user ID in session
        session['user_id'] = user.id
        logger.debug(f"Successfully authenticated with Google: {user.email}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        })
    except Exception as e:
        logger.error(f"Google authentication error: {e}")
        return jsonify({'error': str(e)}), 401

@auth_bp.route('/auth/register-keys', methods=['POST'])
def register_keys():
    """Register user's public key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    public_key = data.get('public_key')
    
    if not public_key:
        return jsonify({'error': 'No public key provided'}), 400
    
    try:
        # Encrypt the public key before storing it
        encrypted_public_key = EncryptionService.encrypt_public_key(public_key)
        
        # Update user with encrypted public key
        user = User.query.filter_by(id=session['user_id']).first()
        user.encrypted_public_key = encrypted_public_key
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error registering keys: {e}")
        return jsonify({'error': 'Failed to register keys'}), 500

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Log out user"""
    # Clear session
    session.pop('user_id', None)
    
    return jsonify({'success': True})

@auth_bp.route('/auth/user', methods=['GET'])
def get_current_user():
    """Get current authenticated user"""
    if 'user_id' not in session:
        return jsonify({'authenticated': False}), 401
    
    user = User.query.filter_by(id=session['user_id']).first()
    
    if not user:
        session.pop('user_id', None)
        return jsonify({'authenticated': False}), 401
    
    return jsonify({
        'authenticated': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'has_keys': user.encrypted_public_key is not None
        }
    })

@auth_bp.route('/profile', methods=['GET'])
def profile():
    """Render user profile page"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login_page'))
    
    user = User.query.filter_by(id=session['user_id']).first()
    
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('auth.login_page'))
    
    return render_template('profile.html', user=user)
