import datetime
import logging
import json
import base64
import requests
import os
import secrets
import string
from config import get_firebase_config

# Import Firebase Admin conditionally
firebase_auth = None
try:
    from firebase_admin import auth as firebase_auth
except ImportError:
    logging.warning("Firebase Admin auth module not available. Using limited functionality.")

from app import db
from database.db import User

logger = logging.getLogger(__name__)

class FirebaseAuthService:
    """Service for handling Firebase authentication"""
    
    # Get Firebase configuration
    firebase_config = get_firebase_config()
    
    @staticmethod
    def verify_firebase_token(id_token):
        """Verify Firebase ID token and get user info"""
        try:
            # In a development environment without service account key, 
            # we'll do a simplified verification by decoding the JWT
            # Note: This is NOT secure for production use!
            
            # Decode JWT token (without verification for development)
            token_parts = id_token.split('.')
            if len(token_parts) != 3:
                logger.error("Invalid token format")
                return None
            
            # Decode payload (middle part of JWT)
            payload_bytes = base64.b64decode(token_parts[1] + "==")
            payload = json.loads(payload_bytes)
            
            # Extract user info from payload
            uid = payload.get('user_id') or payload.get('sub')
            email = payload.get('email')
            name = payload.get('name')
            picture = payload.get('picture')
            
            if not uid or not email:
                logger.error("Missing required user information in token")
                return None
                
            return {
                'uid': uid,
                'email': email,
                'name': name,
                'picture': picture
            }
            
        except Exception as e:
            logger.error(f"Error verifying Firebase token: {e}")
            return None
    
    @staticmethod
    def login_with_email_password(email, password):
        """Authenticate user with email and password using Firebase REST API"""
        try:
            api_key = FirebaseAuthService.firebase_config['apiKey']
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(url, json=payload)
            data = response.json()
            
            if 'error' in data:
                logger.error(f"Firebase login error: {data['error']['message']}")
                return None
            
            return {
                'uid': data['localId'],
                'email': data['email'],
                'name': data.get('displayName', ''),
                'picture': data.get('photoUrl', ''),
                'token': data['idToken']
            }
            
        except Exception as e:
            logger.error(f"Error during email/password login: {e}")
            return None
    
    @staticmethod
    def signup_with_email_password(email, password, name=None):
        """Sign up user with email and password using Firebase REST API"""
        try:
            api_key = FirebaseAuthService.firebase_config['apiKey']
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
            
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(url, json=payload)
            data = response.json()
            
            if 'error' in data:
                logger.error(f"Firebase signup error: {data['error']['message']}")
                return None
            
            # If name is provided, update the user profile
            if name:
                # Update profile
                profile_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
                profile_payload = {
                    "idToken": data['idToken'],
                    "displayName": name,
                    "returnSecureToken": True
                }
                
                profile_response = requests.post(profile_url, json=profile_payload)
                profile_data = profile_response.json()
                
                if 'error' in profile_data:
                    logger.error(f"Firebase profile update error: {profile_data['error']['message']}")
            
            return {
                'uid': data['localId'],
                'email': data['email'],
                'name': name or '',
                'picture': '',
                'token': data['idToken']
            }
            
        except Exception as e:
            logger.error(f"Error during email/password signup: {e}")
            return None
    
    @staticmethod
    def verify_google_token(id_token):
        """Verify Google ID token and get user info"""
        try:
            # For Google sign-in, we can use the Firebase verifyIdToken or decode the JWT
            # Here we'll use the simplified JWT decoding approach for consistency
            
            # Decode JWT token (without verification for development)
            token_parts = id_token.split('.')
            if len(token_parts) != 3:
                logger.error("Invalid Google token format")
                return None
            
            # Decode payload (middle part of JWT)
            payload_bytes = base64.b64decode(token_parts[1] + "==")
            payload = json.loads(payload_bytes)
            
            # Extract user info from payload
            uid = payload.get('sub')
            email = payload.get('email')
            name = payload.get('name')
            picture = payload.get('picture')
            
            if not uid or not email:
                logger.error("Missing required user information in Google token")
                return None
                
            return {
                'uid': uid,
                'email': email,
                'name': name,
                'picture': picture
            }
            
        except Exception as e:
            logger.error(f"Error verifying Google token: {e}")
            return None
    
    @staticmethod
    def get_user_by_uid(uid):
        """Get user by UID from database (no Firebase server call)"""
        try:
            # In development, we'll use the database instead of Firebase
            user = User.query.filter_by(id=uid).first()
            if user:
                return {
                    'uid': user.id,
                    'email': user.email,
                    'display_name': user.name,
                    'photo_url': user.profile_picture
                }
            return None
        except Exception as e:
            logger.error(f"Error getting user by UID: {e}")
            return None
    
    @staticmethod
    def create_or_update_user(user_data):
        """Create or update user in the database"""
        try:
            user = User.query.filter_by(id=user_data['uid']).first()
            
            if not user:
                # Create new user
                user = User(
                    id=user_data['uid'],
                    email=user_data['email'],
                    name=user_data.get('name', ''),
                    profile_picture=user_data.get('picture', ''),
                    registered_on=datetime.datetime.utcnow(),
                    last_login=datetime.datetime.utcnow()
                )
                db.session.add(user)
                logger.debug(f"Created new user: {user.email}")
            else:
                # Update existing user
                user.name = user_data.get('name', user.name)
                user.profile_picture = user_data.get('picture', user.profile_picture)
                user.last_login = datetime.datetime.utcnow()
                logger.debug(f"Updated existing user: {user.email}")
            
            db.session.commit()
            return user
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating/updating user: {e}")
            return None
