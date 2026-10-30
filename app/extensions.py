"""
Flask extension instances initialized without binding to a specific app.
They are attached to the application within the create_app factory.
"""
from flask_sqlalchemy import SQLAlchemy

# Relational Database extension
db = SQLAlchemy()
