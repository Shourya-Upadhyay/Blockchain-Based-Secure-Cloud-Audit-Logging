"""
Authentication routes: registration, login, logout, and profile management.
"""
from flask import render_template, redirect, url_for, flash, request, session
from app.auth import auth_bp
from app.auth.decorators import login_required, auditor_required, get_current_user
from app.services.auth_service import (
    validate_registration_input,
    register_user,
    authenticate_user,
)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User account registration."""
    if "user_id" in session:
        return redirect(url_for("auth.profile"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        is_valid, validation_msg = validate_registration_input(username, password, confirm_password)
        if not is_valid:
            flash(validation_msg, "danger")
            return render_template("auth/register.html", username=username)

        user, err_msg = register_user(username=username, password=password, role="user")
        if err_msg:
            flash(err_msg, "danger")
            return render_template("auth/register.html", username=username)

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User account login."""
    if "user_id" in session:
        return redirect(url_for("auth.profile"))

    next_url = request.args.get("next") or request.form.get("next") or url_for("auth.profile")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, err_msg = authenticate_user(username=username, password=password)
        if err_msg or not user:
            flash(err_msg or "Invalid credentials.", "danger")
            return render_template("auth/login.html", username=username, next=next_url)

        # Set authenticated session data
        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        session.permanent = True

        flash(f"Welcome back, {user.username}!", "success")
        # Ensure next_url is a relative path to prevent open redirect vulnerabilities
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("auth.profile"))

    return render_template("auth/login.html", next=next_url)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Terminate current user session."""
    username = session.get("username")
    session.clear()
    if username:
        flash(f"Goodbye, {username}. You have been logged out safely.", "info")
    else:
        flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile")
@login_required
def profile():
    """Protected user profile and session overview."""
    user = get_current_user()
    return render_template("auth/profile.html", user=user)


@auth_bp.route("/auditor-only-test")
@auditor_required
def auditor_only_test():
    """
    Protected audit verification route used to verify RBAC enforcement.
    Ordinary users navigating directly here receive a 403 Forbidden error.
    """
    user = get_current_user()
    return render_template("auth/profile.html", user=user, auditor_access_granted=True)
