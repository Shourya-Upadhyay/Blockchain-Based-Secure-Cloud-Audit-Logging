"""
Cloud File Storage Blueprint initialization.
"""
from flask import Blueprint

cloud_bp = Blueprint("cloud", __name__, url_prefix="/cloud")

from app.cloud import routes  # noqa: F401, E402
