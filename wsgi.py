"""
WSGI entry point for Gunicorn
"""
from app import app, socketio

# Make the application instance available for Gunicorn 
application = app  # For gunicorn wsgi.py:application

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)