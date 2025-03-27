from app import app, socketio

# Make the application instance available for Gunicorn
# When running with gunicorn main:app
application = app  # For Gunicorn to pick up

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=True, log_output=True)
