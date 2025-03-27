import datetime
from app import db

class User(db.Model):
    """User model for storing user-related data"""
    __tablename__ = 'users'

    id = db.Column(db.String(128), primary_key=True)  # Firebase UID
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)
    encrypted_public_key = db.Column(db.Text, nullable=True)  # Encrypted RSA public key
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    profile_picture = db.Column(db.String(512), nullable=True)
    
    # Relationship with messages
    sent_messages = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')
    
    def __repr__(self):
        return f'<User {self.email}>'

class Message(db.Model):
    """Message model for storing chat messages"""
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.String(128), db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.String(128), db.ForeignKey('users.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)  # AES encrypted message
    encrypted_aes_key = db.Column(db.Text, nullable=False)  # RSA encrypted AES key
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.recipient_id}>'
