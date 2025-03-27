import os
import logging
from flask import Flask
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Load configuration
from config import SESSION_SECRET, DATABASE_URL
app.secret_key = os.environ.get("SESSION_SECRET", SESSION_SECRET)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Initialize SocketIO with eventlet mode for better performance with Gunicorn
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', manage_session=False)

# Import database models (after db is defined)
from database.db import User, Message

# Create database tables
with app.app_context():
    db.create_all()
    logger.debug("Database tables created")

# Import and register routes
from routes.auth_routes import auth_bp
from routes.chat_routes import chat_bp
from routes.encryption_routes import encryption_bp

app.register_blueprint(auth_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(encryption_bp)

# Import socket handlers
from routes.chat_routes import register_socket_events
register_socket_events(socketio)

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return {"error": "Resource not found"}, 404

# Error handler for 500
@app.errorhandler(500)
def internal_server_error(e):
    return {"error": "Internal server error"}, 500

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=True, log_output=True)
