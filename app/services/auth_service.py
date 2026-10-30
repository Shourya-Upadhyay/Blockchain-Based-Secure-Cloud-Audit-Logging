"""
Authentication Service.
Handles registration validation, password hashing, session authentication,
login audit event dispatching, and CSRF token management.
"""
import re
import hmac
import secrets
from flask import session
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.hashing_service import (
    canonical_serialize,
    compute_sha256_hash,
    generate_log_id,
    get_current_utc_iso,
)


def generate_csrf_token() -> str:
    """Generate or retrieve a CSRF token stored in the user's session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token: str) -> bool:
    """Validate a submitted CSRF token using constant-time comparison."""
    session_token = session.get("_csrf_token")
    if not session_token or not token:
        return False
    return hmac.compare_digest(session_token, str(token))


def validate_registration_input(username: str, password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Validate username and password format and strength.
    """
    if not username or not password or not confirm_password:
        return False, "All fields are required."

    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."

    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return False, "Username may only contain letters, numbers, underscores, and hyphens."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"\d", password) and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one digit or special character."

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, ""


def register_user(username: str, password: str, role: str = "user") -> tuple[User | None, str]:
    """
    Register a new user account with hashed password.
    Enforces uniqueness and valid role.
    """
    username = username.strip()
    if role not in ("user", "auditor"):
        return None, f"Invalid role '{role}' specified."

    existing = User.query.filter_by(username=username).first()
    if existing:
        return None, "Username is already registered. Please choose another."

    user = User(username=username, role=role)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()
    return user, ""


def authenticate_user(username: str, password: str) -> tuple[User | None, str]:
    """
    Authenticate user credentials.
    On successful login, writes a LOGIN event to the off-chain SQLite audit log
    via the unified audit_service interface.
    """
    from app.services.audit_service import record_audit_event

    username = (username or "").strip()
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return None, "Invalid username or password."

    # Dispatch LOGIN audit event through single unified audit service
    record_audit_event(
        user_id=user.username,
        action_type="LOGIN",
        file_name="SESSION",
    )

    return user, ""


def create_auditor_account(username: str, password: str) -> tuple[User | None, str]:
    """
    Helper for CLI command to provision an auditor account securely.
    """
    username = username.strip()
    if len(username) < 3:
        return None, "Auditor username must be at least 3 characters."
    if len(password) < 8:
        return None, "Auditor password must be at least 8 characters."

    existing = User.query.filter_by(username=username).first()
    if existing:
        if existing.role == "auditor":
            # Update password safely if already auditor
            existing.set_password(password)
            db.session.commit()
            return existing, "Updated existing auditor account password."
        else:
            return None, f"User '{username}' already exists as a regular user."

    user = User(username=username, role="auditor")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user, f"Auditor account '{username}' created successfully."
