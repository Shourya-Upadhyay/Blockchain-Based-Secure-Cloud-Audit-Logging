"""
Authentication and Role-Based Access Control (RBAC) Decorators.
Enforces server-side permissions on protected routes.
"""
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort
from app.models.user import User


def get_current_user() -> User | None:
    """Return the User entity for the current session, or None if anonymous."""
    from app.extensions import db
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_required(f):
    """
    Decorator requiring an active authenticated user session.
    Redirects unauthenticated visitors to the login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    """
    Decorator requiring the logged-in user to have one of the specified roles.
    Aborts with 403 Forbidden if the user lacks the required role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth.login", next=request.path))

            user_role = session.get("role", "user")
            if user_role not in allowed_roles:
                # Server-side denial: HTTP 403 Forbidden
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def auditor_required(f):
    """Convenience decorator restricting route access exclusively to auditors."""
    return role_required("auditor")(f)
