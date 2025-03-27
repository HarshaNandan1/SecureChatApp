import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Firebase Configuration
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID")
FIREBASE_APP_ID = os.environ.get("FIREBASE_APP_ID")

# Construct derived Firebase values
FIREBASE_AUTH_DOMAIN = f"{FIREBASE_PROJECT_ID}.firebaseapp.com" if FIREBASE_PROJECT_ID else None
FIREBASE_STORAGE_BUCKET = f"{FIREBASE_PROJECT_ID}.appspot.com" if FIREBASE_PROJECT_ID else None
FIREBASE_MESSAGING_SENDER_ID = os.environ.get("FIREBASE_MESSAGING_SENDER_ID")

# Log Firebase configuration status
if FIREBASE_API_KEY and FIREBASE_PROJECT_ID and FIREBASE_APP_ID:
    logger.debug("Firebase configuration loaded from environment variables")
else:
    logger.warning("Some Firebase configuration values are missing. Using fallback values for development only.")
    # Fallback values for development only (not secure for production)
    FIREBASE_API_KEY = FIREBASE_API_KEY or "dev-api-key"
    FIREBASE_PROJECT_ID = FIREBASE_PROJECT_ID or "dev-project"
    FIREBASE_APP_ID = FIREBASE_APP_ID or "dev-app-id"
    FIREBASE_AUTH_DOMAIN = FIREBASE_AUTH_DOMAIN or f"{FIREBASE_PROJECT_ID}.firebaseapp.com"
    FIREBASE_STORAGE_BUCKET = FIREBASE_STORAGE_BUCKET or f"{FIREBASE_PROJECT_ID}.appspot.com"
    FIREBASE_MESSAGING_SENDER_ID = FIREBASE_MESSAGING_SENDER_ID or "000000000000"

# Flask Configuration
SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = os.urandom(32).hex()
    logger.warning("Generated temporary SESSION_SECRET. Please set a permanent one in environment variables.")

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///chat.db")
logger.debug(f"Using database: {DATABASE_URL}")

# Encryption Configuration
SERVER_KEY = os.environ.get("SERVER_KEY", "dev_server_key_not_for_production")
if not os.environ.get("SERVER_KEY"):
    logger.warning("SERVER_KEY not found in environment variables. Using insecure default for development only.")

def get_firebase_config():
    """
    Return Firebase configuration as a dictionary
    This is used by the Firebase auth service and client-side code
    """
    return {
        'apiKey': FIREBASE_API_KEY,
        'authDomain': FIREBASE_AUTH_DOMAIN,
        'projectId': FIREBASE_PROJECT_ID,
        'storageBucket': FIREBASE_STORAGE_BUCKET,
        'messagingSenderId': FIREBASE_MESSAGING_SENDER_ID,
        'appId': FIREBASE_APP_ID
    }
