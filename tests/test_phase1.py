"""
Phase 1 automated tests:
- Application factory and configuration validation
- Database initialization and table schema verification
- User model password hashing and role-based checks
- AuditLog model CRUD, canonical field separation, and unique constraints
- FileMetadata model and relationship
- Health check route JSON response and database connectivity
- Error handlers and landing page rendering
- CLI init-db command execution
"""
import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from app import create_app
from app.extensions import db
from app.models import User, AuditLog, FileMetadata
from config import DevelopmentConfig, TestingConfig, ProductionConfig


def test_config_environments():
    """Verify configuration classes load appropriate settings."""
    dev_app = create_app("development")
    assert dev_app.config["DEBUG"] is True
    assert "cloud_audit.db" in dev_app.config["SQLALCHEMY_DATABASE_URI"]

    test_app = create_app(TestingConfig)
    assert test_app.config["TESTING"] is True
    assert test_app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"

    prod_app = create_app("production")
    assert prod_app.config["DEBUG"] is False
    assert prod_app.config["ALLOW_TAMPER_SIMULATION"] is False


def test_database_table_creation(app):
    """Verify that all required tables are properly created in SQLite."""
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        assert "users" in tables
        assert "audit_logs" in tables
        assert "files" in tables


def test_user_model_crud(app):
    """Test User creation, Werkzeug PBKDF2 hashing, and role checks."""
    with app.app_context():
        user = User(username="test_auditor", role="auditor")
        user.set_password("AuditPass2026!")
        db.session.add(user)
        db.session.commit()

        queried = User.query.filter_by(username="test_auditor").first()
        assert queried is not None
        assert queried.is_auditor is True
        assert queried.check_password("AuditPass2026!") is True
        assert queried.check_password("WrongPassword") is False
        assert "password_hash" not in queried.to_dict()


def test_audit_log_model_crud(app):
    """
    Test AuditLog creation, separate anchoring status, and canonical field isolation.
    """
    with app.app_context():
        log = AuditLog(
            log_id="LOG-20261029-A1B2C3D4",
            user_id="shourya",
            action_type="UPLOAD",
            file_name="research_paper.pdf",
            timestamp="2026-10-29T18:30:00Z",
            log_hash="0x" + "a" * 64,
            anchored_status="PENDING",
            retry_count=0
        )
        db.session.add(log)
        db.session.commit()

        retrieved = AuditLog.query.filter_by(log_id="LOG-20261029-A1B2C3D4").first()
        assert retrieved is not None
        assert retrieved.anchored_status == "PENDING"
        assert retrieved.tx_hash is None
        assert retrieved.block_number is None

        # Verify canonical dictionary strictly contains only the 5 hashed fields
        canonical = retrieved.canonical_dict()
        assert set(canonical.keys()) == {"log_id", "user_id", "action_type", "file_name", "timestamp"}
        assert "anchored_status" not in canonical
        assert "log_hash" not in canonical
        assert "tx_hash" not in canonical

        # Simulate successful on-chain anchoring update
        retrieved.anchored_status = "ANCHORED"
        retrieved.tx_hash = "0x" + "b" * 64
        retrieved.block_number = 101
        db.session.commit()

        updated = AuditLog.query.filter_by(log_id="LOG-20261029-A1B2C3D4").first()
        assert updated.anchored_status == "ANCHORED"
        assert updated.block_number == 101
        assert updated.tx_hash == "0x" + "b" * 64


def test_audit_log_unique_constraint(app):
    """Verify that duplicate log_id insertions are rejected by database constraints."""
    with app.app_context():
        log1 = AuditLog(
            log_id="LOG-DUP-001",
            user_id="user1",
            action_type="LOGIN",
            file_name="SESSION",
            timestamp="2026-10-29T18:30:00Z",
            log_hash="0x" + "1" * 64,
            anchored_status="PENDING"
        )
        db.session.add(log1)
        db.session.commit()

        log2 = AuditLog(
            log_id="LOG-DUP-001",  # Same log_id
            user_id="user2",
            action_type="LOGIN",
            file_name="SESSION",
            timestamp="2026-10-29T18:35:00Z",
            log_hash="0x" + "2" * 64,
            anchored_status="PENDING"
        )
        db.session.add(log2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_file_metadata_and_relationship(app):
    """Test FileMetadata model and relationship with User."""
    with app.app_context():
        owner = User(username="cloud_user", role="user")
        owner.set_password("Secret123!")
        db.session.add(owner)
        db.session.commit()

        file_meta = FileMetadata(
            filename="dataset.csv",
            stored_filename="dataset_uuid123.csv",
            filesize=1048576,
            owner_id=owner.id
        )
        db.session.add(file_meta)
        db.session.commit()

        assert len(owner.files) == 1
        assert owner.files[0].filename == "dataset.csv"


def test_health_check_endpoint(client):
    """Test /health and /api/health endpoints."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert "users" in data["tables"]
    assert "audit_logs" in data["tables"]
    assert "files" in data["tables"]
    assert "timestamp" in data
    assert data["version"] == "1.0.0"

    # Also test /api/health alias
    api_response = client.get("/api/health")
    assert api_response.status_code == 200
    assert api_response.get_json()["status"] == "healthy"


def test_index_landing_page(client):
    """Test that the overview landing page loads with HTTP 200."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Blockchain-Based Secure Cloud Audit Logging" in html
    assert "CloudAudit" in html
    assert "health-badge" in html


def test_404_error_page(client):
    """Test custom 404 error handler."""
    response = client.get("/invalid-nonexistent-path")
    assert response.status_code == 404
    html = response.get_data(as_text=True)
    assert "404" in html
    assert "Resource Not Found" in html


def test_init_db_cli_command(runner):
    """Test custom flask init-db CLI command."""
    result = runner.invoke(args=["init-db"])
    assert result.exit_code == 0
    assert "Database initialized successfully" in result.output
