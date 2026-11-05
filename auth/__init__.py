from datetime import timedelta
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from audit import log_event
from extensions import db
from models import AuditLog, User, utcnow

bp = Blueprint("auth", __name__)

# Roles a person may pick for themselves. "admin" is deliberately NOT here.
SELF_SERVICE_ROLES = ("owner", "viewer")

WINDOW = timedelta(minutes=15)
MAX_FAILS_PER_EMAIL_AND_IP = 5
MAX_FAILS_PER_IP = 20


def is_safe_next(target):
    """Only allow redirects to a path on our own site (prevents open redirects)."""
    if not target:
        return False
    parts = urlparse(target)
    return (
        not parts.scheme
        and not parts.netloc
        and target.startswith("/")
        and not target.startswith("//")
        and "\\" not in target
    )


def too_many_failures(email):
    """Counts failed logins in the audit log (so it survives restarts)."""
    cutoff = (utcnow() - WINDOW).isoformat()
    from_this_ip = AuditLog.query.filter(
        AuditLog.action == "login", AuditLog.outcome == "denied",
        AuditLog.ip == request.remote_addr, AuditLog.ts >= cutoff)
    if from_this_ip.count() >= MAX_FAILS_PER_IP:
        return True
    same_email = from_this_ip.filter(AuditLog.detail == f"bad credentials: {email}")
    return same_email.count() >= MAX_FAILS_PER_EMAIL_AND_IP


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        errors = []
        if not name or len(name) > 120:
            errors.append("Please enter your name (max 120 characters).")
        if "@" not in email or len(email) > 255:
            errors.append("Please enter a valid email address.")
        if len(password) < 10:
            errors.append("Password must be at least 10 characters.")
        if role not in SELF_SERVICE_ROLES:
            errors.append("Please choose a valid account type.")
            log_event("register", "denied", detail=f"bad role requested: {role}"[:100])

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html"), 400

        user = User(name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            log_event("register", "denied", detail="duplicate email")
            flash("That email cannot be registered. Try logging in.", "danger")
            return render_template("register.html"), 400

        log_event("register", "allowed", actor=user, detail=f"role {role}")
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:255]
        password = request.form.get("password", "")

        if too_many_failures(email):
            log_event("login_blocked", "denied", detail=f"too many failures: {email}")
            flash("Too many failed attempts. Please wait 15 minutes and try again.", "danger")
            return render_template("login.html"), 429

        user = User.query.filter_by(email=email).first()

        # One generic message for every failure, so attackers learn nothing.
        if user is None or not user.active or not user.check_password(password):
            log_event("login", "denied", detail=f"bad credentials: {email}")
            flash("Invalid email or password.", "danger")
            return render_template("login.html"), 401

        login_user(user)
        log_event("login", "allowed", actor=user, detail="login ok")
        next_url = request.args.get("next")
        if is_safe_next(next_url):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("logout", "allowed", actor=current_user)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))