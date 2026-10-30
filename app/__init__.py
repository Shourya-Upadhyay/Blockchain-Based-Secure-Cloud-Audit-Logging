"""
Flask Application Factory for Blockchain-Based Secure Cloud Audit Logging.
"""
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import click
from flask import Flask, jsonify, render_template, request, abort
from sqlalchemy import text, inspect

from config import config, BASE_DIR
from app.extensions import db


def create_app(config_name=None):
    """
    Factory function to create and configure the Flask application.
    """
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    # Ensure instance directory exists before database configuration or connections
    instance_dir = BASE_DIR / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__, instance_path=str(instance_dir))

    # Load configuration
    if isinstance(config_name, str):
        config_class = config.get(config_name, config["default"])
        app.config.from_object(config_class)
    else:
        # If an explicit config object/class is passed
        app.config.from_object(config_name)

    # Normalize SQLite database URI to reliable absolute path based on instance directory
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if db_uri.startswith("sqlite:///") and db_uri != "sqlite:///:memory:":
        raw_path = db_uri[len("sqlite:///"):]
        path_obj = Path(raw_path)
        if not path_obj.is_absolute():
            if raw_path.startswith("instance/") or raw_path.startswith("instance\\"):
                rel_file = raw_path[len("instance/"):]
                abs_path = Path(app.instance_path) / rel_file
            else:
                abs_path = Path(app.instance_path) / raw_path
            app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{abs_path.as_posix()}"

    # Secure Session Settings
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", app.config.get("SESSION_COOKIE_SECURE", False))
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(days=7))

    # Ensure instance directory and upload directory exist
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    upload_folder = Path(app.config.get("UPLOAD_FOLDER", BASE_DIR / "uploads"))
    upload_folder.mkdir(parents=True, exist_ok=True)

    # Initialize extensions AFTER instance directory exists and URI is normalized
    db.init_app(app)

    # Register blueprints
    register_blueprints(app)

    # Configure CSRF protection and template helpers
    configure_security_and_helpers(app)

    # Register CLI commands
    register_commands(app)

    # Register core routes & health check
    register_core_routes(app)

    # Register error handlers
    register_error_handlers(app)

    return app


def register_blueprints(app: Flask):
    """Register application blueprints."""
    from app.auth import auth_bp
    from app.cloud import cloud_bp
    from app.audit import audit_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(cloud_bp)
    app.register_blueprint(audit_bp)


def configure_security_and_helpers(app: Flask):
    """Configure CSRF protection, template context processors, and session helpers."""
    from app.services.auth_service import generate_csrf_token, validate_csrf_token
    from app.auth.decorators import get_current_user

    # Template globals
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    # Context processors
    @app.context_processor
    def inject_auth_context():
        return {
            "current_user": get_current_user(),
        }

    # Global CSRF protection on mutating HTTP requests
    @app.before_request
    def enforce_csrf_protection():
        # Exempt if CSRF is explicitly disabled (e.g. testing mode)
        if app.config.get("WTF_CSRF_ENABLED") is False or app.config.get("ENABLE_CSRF") is False:
            return

        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            if not validate_csrf_token(token):
                abort(400, description="CSRF validation failed. Form submission missing or invalid token.")


def register_commands(app: Flask):
    """Register custom CLI commands with the Flask application."""
    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables and verify schema."""
        from flask import current_app
        import app.models  # noqa: F401
        Path(current_app.instance_path).mkdir(parents=True, exist_ok=True)
        db.create_all()
        print("Database initialized successfully at:", current_app.config.get("SQLALCHEMY_DATABASE_URI"))

    @app.cli.command("create-auditor")
    @click.option("--username", prompt=True, help="Auditor account username")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Auditor account password")
    def create_auditor_command(username, password):
        """
        Create or update an auditor account with secure PBKDF2 password hashing.
        Allows interactive or scripted provisioning without hardcoded credentials.
        """
        import app.models  # noqa: F401
        from app.services.auth_service import create_auditor_account
        db.create_all()
        user, msg = create_auditor_account(username=username, password=password)
        if user:
            print(f"[SUCCESS] {msg}")
        else:
            print(f"[ERROR] {msg}")


def register_core_routes(app: Flask):
    """Register health check and landing routes."""
    @app.route("/")
    def index():
        """Cybersecurity SOC Overview Dashboard."""
        from app.blockchain.anchoring import get_anchoring_stats
        from app.blockchain.client import get_blockchain_client
        from app.models.audit_log import AuditLog
        from app.models import FileMetadata
        from flask import session

        stats = get_anchoring_stats()
        blockchain_status = get_blockchain_client().get_status()

        # Cloud storage metrics
        total_files = FileMetadata.query.count()
        total_bytes = db.session.query(db.func.sum(FileMetadata.filesize)).scalar() or 0

        if total_bytes < 1024:
            formatted_storage = f"{total_bytes} B"
        elif total_bytes < 1024 * 1024:
            formatted_storage = f"{total_bytes / 1024:.1f} KB"
        else:
            formatted_storage = f"{total_bytes / (1024 * 1024):.2f} MB"

        # Integrity verification status
        latest_verification = session.get("latest_verification_report")
        if latest_verification:
            if latest_verification.get("blockchain_status") == "OFFLINE":
                integrity_status = "UNAVAILABLE"
            else:
                summary = latest_verification.get("summary", {})
                tampered = (summary.get("tampered") or 0) + (summary.get("missing_sql") or 0)
                integrity_status = "FAILED" if tampered > 0 else "VERIFIED"
            verification_timestamp = latest_verification.get("timestamp")
        else:
            integrity_status = "NOT_VERIFIED"
            verification_timestamp = None

        # Recent activity (real records)
        recent_logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(6).all()

        # Real action breakdown for chart
        action_counts_raw = db.session.query(
            AuditLog.action_type, db.func.count(AuditLog.id)
        ).group_by(AuditLog.action_type).all()
        action_breakdown = {act: count for act, count in action_counts_raw}

        return render_template(
            "index.html",
            stats=stats,
            blockchain_status=blockchain_status,
            total_files=total_files,
            formatted_storage=formatted_storage,
            integrity_status=integrity_status,
            verification_timestamp=verification_timestamp,
            recent_logs=recent_logs,
            action_breakdown=action_breakdown,
        )

    @app.route("/health")
    @app.route("/api/health")
    def health_check():
        """
        System health check endpoint verifying database connectivity and table schema.
        """
        db_status = "disconnected"
        table_list = []
        try:
            # Test direct connection
            db.session.execute(text("SELECT 1"))
            db_status = "connected"

            # Inspect available tables
            inspector = inspect(db.engine)
            table_list = inspector.get_table_names()
        except Exception as e:
            db_status = f"error: {str(e)}"

        status_code = 200 if db_status == "connected" else 503
        return jsonify({
            "status": "healthy" if db_status == "connected" else "degraded",
            "database": db_status,
            "tables": table_list,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "environment": app.config.get("ENV", "development"),
        }), status_code


def register_error_handlers(app: Flask):
    """Register custom HTTP error handlers."""
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html", error=error), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html", error=error), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html", error=error), 500
