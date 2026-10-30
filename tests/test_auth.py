"""
Phase 2 Authentication & Authorization Tests:
- User registration with validation and duplicate prevention
- Password hashing security (Werkzeug PBKDF2)
- Session management, login, and logout
- Automatic LOGIN audit event generation in SQLite
- Server-side role-based access control (RBAC):
  * Anonymous users blocked from protected routes
  * Ordinary users blocked from auditor routes (HTTP 403 Forbidden)
  * Auditors granted access to auditor routes
- CLI create-auditor command testing
- CSRF protection validation
"""
import pytest
from flask import session
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app import create_app
from config import TestingConfig


def test_registration_success(client, app):
    """Test successful user registration."""
    response = client.post(
        "/auth/register",
        data={
            "username": "alice_user",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Account created successfully" in html

    with app.app_context():
        user = User.query.filter_by(username="alice_user").first()
        assert user is not None
        assert user.role == "user"
        assert user.is_auditor is False
        assert user.check_password("Password123!") is True


def test_registration_validation(client):
    """Test registration input validation rules."""
    # 1. Short username
    res = client.post(
        "/auth/register",
        data={"username": "al", "password": "Password123!", "confirm_password": "Password123!"},
    )
    assert "Username must be between 3 and 30 characters" in res.get_data(as_text=True)

    # 2. Invalid characters in username
    res = client.post(
        "/auth/register",
        data={"username": "bad user!", "password": "Password123!", "confirm_password": "Password123!"},
    )
    assert "Username may only contain letters, numbers, underscores, and hyphens" in res.get_data(as_text=True)

    # 3. Weak password (<8 chars)
    res = client.post(
        "/auth/register",
        data={"username": "valid_user", "password": "P1!", "confirm_password": "P1!"},
    )
    assert "Password must be at least 8 characters long" in res.get_data(as_text=True)

    # 4. Password without digit or symbol
    res = client.post(
        "/auth/register",
        data={"username": "valid_user", "password": "PasswordOnly", "confirm_password": "PasswordOnly"},
    )
    assert "Password must contain at least one digit or special character" in res.get_data(as_text=True)

    # 5. Mismatched passwords
    res = client.post(
        "/auth/register",
        data={"username": "valid_user", "password": "Password123!", "confirm_password": "DifferentPass123!"},
    )
    assert "Passwords do not match" in res.get_data(as_text=True)


def test_duplicate_registration_rejected(client):
    """Test duplicate usernames are rejected."""
    # First registration
    client.post(
        "/auth/register",
        data={"username": "bob_user", "password": "Password123!", "confirm_password": "Password123!"},
    )

    # Duplicate registration
    res = client.post(
        "/auth/register",
        data={"username": "bob_user", "password": "NewPassword123!", "confirm_password": "NewPassword123!"},
    )
    assert "Username is already registered" in res.get_data(as_text=True)


def test_login_success_and_session(client):
    """Test successful login, session population, and profile access."""
    # Register user
    client.post(
        "/auth/register",
        data={"username": "carol_user", "password": "Password123!", "confirm_password": "Password123!"},
    )

    # Perform login
    response = client.post(
        "/auth/login",
        data={"username": "carol_user", "password": "Password123!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Welcome back, carol_user!" in html
    assert "carol_user" in html
    assert "Standard Cloud User" in html

    # Profile route accessible directly
    profile_res = client.get("/auth/profile")
    assert profile_res.status_code == 200
    assert "carol_user" in profile_res.get_data(as_text=True)


def test_login_incorrect_password(client):
    """Test login with incorrect password."""
    client.post(
        "/auth/register",
        data={"username": "dave_user", "password": "Password123!", "confirm_password": "Password123!"},
    )

    response = client.post(
        "/auth/login",
        data={"username": "dave_user", "password": "WrongPassword999!"},
    )
    assert response.status_code == 200
    assert "Invalid username or password" in response.get_data(as_text=True)


def test_login_nonexistent_user(client):
    """Test login with non-existent user."""
    response = client.post(
        "/auth/login",
        data={"username": "ghost_user", "password": "Password123!"},
    )
    assert "Invalid username or password" in response.get_data(as_text=True)


def test_login_audit_event_recorded(client, app):
    """Verify that successful login automatically records a LOGIN audit event."""
    client.post(
        "/auth/register",
        data={"username": "audit_test_user", "password": "Password123!", "confirm_password": "Password123!"},
    )

    # Log in
    client.post(
        "/auth/login",
        data={"username": "audit_test_user", "password": "Password123!"},
    )

    with app.app_context():
        login_log = AuditLog.query.filter_by(user_id="audit_test_user", action_type="LOGIN").first()
        assert login_log is not None
        assert login_log.file_name == "SESSION"
        assert login_log.anchored_status in ("PENDING", "ANCHORED")
        assert login_log.log_hash.startswith("0x")
        assert len(login_log.log_hash) == 66  # 0x + 64 hex characters


def test_logout_clears_session(client):
    """Test logout terminates session and redirects."""
    # Register and login
    client.post(
        "/auth/register",
        data={"username": "eve_user", "password": "Password123!", "confirm_password": "Password123!"},
    )
    client.post(
        "/auth/login",
        data={"username": "eve_user", "password": "Password123!"},
    )

    # Logout via POST
    response = client.post("/auth/logout", follow_redirects=True)
    assert response.status_code == 200
    assert "logged out" in response.get_data(as_text=True).lower()

    # Accessing profile now redirects to login
    prof_res = client.get("/auth/profile")
    assert prof_res.status_code == 302
    assert "/auth/login" in prof_res.headers["Location"]


def test_login_required_protection(client):
    """Test unauthenticated users cannot access protected profile route."""
    response = client.get("/auth/profile")
    assert response.status_code == 302
    assert "/auth/login?next=/auth/profile" in response.headers["Location"]


def test_auditor_access_control_ordinary_user_blocked(client):
    """
    Test RBAC server-side enforcement:
    Ordinary users navigating directly to an auditor route receive HTTP 403 Forbidden.
    """
    # Register and log in as standard user
    client.post(
        "/auth/register",
        data={"username": "standard_frank", "password": "Password123!", "confirm_password": "Password123!"},
    )
    client.post(
        "/auth/login",
        data={"username": "standard_frank", "password": "Password123!"},
    )

    # Attempt to open auditor route directly
    response = client.get("/auth/auditor-only-test")
    assert response.status_code == 403
    html = response.get_data(as_text=True)
    assert "403" in html
    assert "Forbidden" in html or "Access Forbidden" in html


def test_auditor_access_control_auditor_granted(client, app):
    """
    Test RBAC server-side enforcement:
    Auditors are authorized and receive HTTP 200 on auditor routes.
    """
    with app.app_context():
        auditor = User(username="official_auditor", role="auditor")
        auditor.set_password("AuditorPass2026!")
        db.session.add(auditor)
        db.session.commit()

    # Log in as auditor
    client.post(
        "/auth/login",
        data={"username": "official_auditor", "password": "AuditorPass2026!"},
    )

    # Access auditor route
    response = client.get("/auth/auditor-only-test")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "RBAC Verification Succeeded" in html
    assert "Auditor" in html


def test_create_auditor_cli_command(runner, app):
    """Test safe development CLI command to create an auditor account without hardcoding secrets."""
    result = runner.invoke(args=["create-auditor", "--username", "sec_officer", "--password", "StrongPass2026!"])
    assert result.exit_code == 0
    assert "[SUCCESS]" in result.output
    assert "created successfully" in result.output

    with app.app_context():
        user = User.query.filter_by(username="sec_officer").first()
        assert user is not None
        assert user.role == "auditor"
        assert user.is_auditor is True
        assert user.check_password("StrongPass2026!") is True


def test_csrf_protection_enforced():
    """
    Test that CSRF protection rejects mutating POST requests when token is missing,
    and accepts them when a valid token is provided.
    """
    # Create app instance with CSRF explicitly enabled
    class CsrfEnabledTestingConfig(TestingConfig):
        WTF_CSRF_ENABLED = True
        ENABLE_CSRF = True

    csrf_app = create_app(CsrfEnabledTestingConfig)
    with csrf_app.app_context():
        db.create_all()

    csrf_client = csrf_app.test_client()

    # 1. Missing CSRF token -> Rejected with 400 Bad Request
    rejected_res = csrf_client.post(
        "/auth/register",
        data={"username": "csrf_target", "password": "Password123!", "confirm_password": "Password123!"},
    )
    assert rejected_res.status_code == 400
    assert "CSRF" in rejected_res.get_data(as_text=True)

    # 2. Extract valid CSRF token from registration page
    get_res = csrf_client.get("/auth/register")
    html = get_res.get_data(as_text=True)
    import re
    match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', html)
    assert match is not None
    token = match.group(1)

    # 3. Submit with valid token -> Accepted with 302 redirect to login
    allowed_res = csrf_client.post(
        "/auth/register",
        data={
            "csrf_token": token,
            "username": "csrf_success",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    assert allowed_res.status_code == 302
