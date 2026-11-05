from datetime import datetime

from flask import Flask, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from config import Config
from extensions import csrf, db, login_manager


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    if app.config.get("IS_PRODUCTION"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"

    import models
    from admin import bp as admin_bp
    from auth import bp as auth_bp
    from documents import CATEGORIES, bp as documents_bp
    from permissions import authorize

    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)

    @login_manager.user_loader
    def load_user(user_id):
        # A disabled account is treated as logged out on its very next request.
        user = db.session.get(models.User, user_id)
        return user if user is not None and user.active else None

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        if app.config.get("IS_PRODUCTION"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("auth.login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if current_user.role == "admin":
            return redirect(url_for("admin.home"))

        # Step 1: collect only documents this person may read.
        # authorize() has the final say, so search can never show more.
        items = []
        own = models.Document.query.filter_by(owner_id=current_user.id,
                                              deleted_at=None).all()
        for d in own:
            if authorize(current_user, d, "read"):
                items.append((d, "owner"))
        grants = models.Grant.query.filter_by(user_id=current_user.id,
                                              revoked_at=None).all()
        for g in grants:
            if authorize(current_user, g.document, "read"):
                items.append((g.document, g.permission))

        # Step 2: apply the search filters to that list only.
        filters = {
            "q": request.args.get("q", "").strip()[:100],
            "category": request.args.get("category", "")[:50],
            "owner": request.args.get("owner", "").strip()[:100],
            "date_from": request.args.get("from", "")[:10],
            "date_to": request.args.get("to", "")[:10],
        }
        date_from = parse_date(filters["date_from"])
        date_to = parse_date(filters["date_to"])

        def keep(d):
            if filters["q"] and filters["q"].lower() not in d.original_name.lower():
                return False
            if filters["category"] and d.category != filters["category"]:
                return False
            if filters["owner"]:
                who = (d.owner.name + " " + d.owner.email).lower()
                if filters["owner"].lower() not in who:
                    return False
            day = d.created_at.date()
            if date_from and day < date_from:
                return False
            if date_to and day > date_to:
                return False
            return True

        items = [(d, p) for d, p in items if keep(d)]
        items.sort(key=lambda pair: pair[0].created_at, reverse=True)
        return render_template("dashboard.html", items=items,
                               categories=CATEGORIES, filters=filters)

    @app.errorhandler(413)
    def too_large(e):
        return "File too large. The maximum is 10 MB.", 413

    with app.app_context():
        db.create_all()
        try:
            from audit import install_guards
            install_guards()
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not install audit guards")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)