"""
Application entrypoint for Blockchain-Based Secure Cloud Audit Logging.
"""
import os
from app import create_app
from app.extensions import db
import app.models  # Ensure models are loaded

# Create Flask application instance using environment configuration
app = create_app(os.getenv("FLASK_ENV", "development"))

if __name__ == "__main__":
    # Ensure database tables exist in development
    with app.app_context():
        db.create_all()
    
    # Run development server
    port = int(os.getenv("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=app.config.get("DEBUG", True))
