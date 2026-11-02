from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import User

bp = Blueprint("auth", __name__)

# Users can register only as owners or viewers.
SELF_SERVICE_ROLES = ("owner", "viewer")


def is_safe_next(target):
    """Prevent redirects to external websites."""
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

        if errors:
            for error in errors:
                flash(error, "danger")

            return render_template("register.html"), 400

        user = User(name=name, email=email, role=role)

        user.set_password(password)

        db.session.add(user)

        try:
            db.session.commit()

        except IntegrityError:
            db.session.rollback()

            flash("That email cannot be registered. Try logging in.", "danger")

            return render_template("register.html"), 400

        flash("Account created. Please log in.", "success")

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user is None or not user.active or not user.check_password(password):
            flash("Invalid email or password.", "danger")

            return render_template("login.html"), 401

        login_user(user)

        next_url = request.args.get("next")

        if is_safe_next(next_url):
            return redirect(next_url)

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash("You have been logged out.", "success")

    return redirect(url_for("auth.login"))