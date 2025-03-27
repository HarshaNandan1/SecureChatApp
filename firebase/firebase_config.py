import os
import logging

# Import Firebase dependencies in a way that won't block initialization
# if the module is not fully available
firebase_admin = None
firebase_auth = None
try:
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import auth as firebase_auth
except ImportError:
    logging.warning("Firebase Admin SDK not fully available. Some functions may not work.")

from config import (
    FIREBASE_API_KEY, 
    FIREBASE_AUTH_DOMAIN, 
    FIREBASE_PROJECT_ID, 
    FIREBASE_STORAGE_BUCKET, 
    FIREBASE_MESSAGING_SENDER_ID, 
    FIREBASE_APP_ID
)

logger = logging.getLogger(__name__)

# Firebase configuration for client-side
firebase_config = {
    "apiKey": FIREBASE_API_KEY,
    "authDomain": FIREBASE_AUTH_DOMAIN,
    "projectId": FIREBASE_PROJECT_ID,
    "storageBucket": FIREBASE_STORAGE_BUCKET,
    "messagingSenderId": FIREBASE_MESSAGING_SENDER_ID,
    "appId": FIREBASE_APP_ID
}

# Initialize Firebase Admin SDK if available
if firebase_admin:
    try:
        # Initialize Firebase Admin with service account
        cred = credentials.Certificate('firebase/service_account.json')
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully with service account")
    except Exception as e:
        logger.error(f"Error initializing Firebase Admin SDK: {e}")
        # As a fallback, try initializing with default configuration
        try:
            firebase_admin.initialize_app()
            logger.info("Firebase Admin SDK initialized with default configuration")
        except Exception as e:
            logger.error(f"Failed to initialize Firebase Admin SDK with default configuration: {e}")
else:
    logger.warning("Firebase Admin SDK import failed. Running in limited mode.")
