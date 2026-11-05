from datetime import timedelta
from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from audit import chain_head, log_event, verify_chain
from extensions import db
from models import AuditLog, Document, Grant, User, utcnow

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_only(view):
    """Admins only. Everyone else gets 404 and the attempt is recorded."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user.role != "admin" or not current_user.active:
            log_event("admin_access", "denied", actor=current_user,
                      detail=request.path[:200])
            abort(404)
        return view(*args, **kwargs)
    return wrapped


@bp.route("/")
@login_required
@admin_only
def home():
    day_ago = (utcnow() - timedelta(hours=24)).isoformat()
    hour_ago = (utcnow() - timedelta(hours=1)).isoformat()
    recent = AuditLog.query.filter(AuditLog.ts >= day_ago).all()

    refused, failed_logins, downloads = {}, {}, {}
    for r in recent:
        if r.outcome == "denied" and r.action not in ("login", "login_blocked"):
            who = r.actor_email or "(not logged in)"
            refused[who] = refused.get(who, 0) + 1
        if r.action == "login" and r.outcome == "denied":
            ip = r.ip or "unknown"
            failed_logins[ip] = failed_logins.get(ip, 0) + 1
        if r.action == "download" and r.outcome == "allowed" and r.ts >= hour_ago:
            downloads[r.actor_email] = downloads.get(r.actor_email, 0) + 1

    alerts = []
    alerts += [f"{w} was refused {n} times in 24 hours" for w, n in refused.items() if n >= 5]
    alerts += [f"{ip} had {n} failed logins in 24 hours" for ip, n in failed_logins.items() if n >= 5]
    alerts += [f"{w} downloaded {n} files in the last hour" for w, n in downloads.items() if n >= 10]

    shared_count = {}
    for g in Grant.query.filter_by(revoked_at=None).all():
        shared_count[g.document_id] = shared_count.get(g.document_id, 0) + 1

    head_id, head_hash = chain_head()
    stats = {
        "users": User.query.count(),
        "documents": Document.query.filter_by(deleted_at=None).count(),
        "grants": sum(shared_count.values()),
        "refused": sum(refused.values()),
    }
    return render_template(
        "admin.html", stats=stats, alerts=alerts, head_id=head_id,
        head_hash=head_hash, shared_count=shared_count,
        users=User.query.order_by(User.created_at).all(),
        docs=Document.query.order_by(Document.created_at.desc()).all())


@bp.route("/audit")
@login_required
@admin_only
def audit():
    q = AuditLog.query
    action = request.args.get("action", "").strip()[:50]
    outcome = request.args.get("outcome", "")[:10]
    who = request.args.get("who", "").strip().lower()[:255]
    doc = request.args.get("doc", "").strip()[:36]
    if action:
        q = q.filter(AuditLog.action == action)
    if outcome in ("allowed", "denied"):
        q = q.filter(AuditLog.outcome == outcome)
    if who:
        q = q.filter(AuditLog.actor_email.ilike(f"%{who}%"))
    if doc:
        q = q.filter(AuditLog.document_id == doc)
    rows = q.order_by(AuditLog.id.desc()).limit(200).all()
    actions = sorted({a for (a,) in db.session.query(AuditLog.action).distinct()})
    return render_template("admin_audit.html", rows=rows, actions=actions,
                           f={"action": action, "outcome": outcome, "who": who, "doc": doc})


@bp.route("/verify", methods=["POST"])
@login_required
@admin_only
def verify():
    ok, bad_id = verify_chain()
    if ok:
        flash("Audit chain verified: no row has been altered.", "success")
    else:
        flash(f"TAMPERING DETECTED: the chain breaks at row {bad_id}.", "danger")
    log_event("audit_verify", "allowed" if ok else "denied", actor=current_user,
              detail="ok" if ok else f"broken at row {bad_id}")
    return redirect(url_for("admin.home"))


@bp.route("/users/<user_id>/toggle", methods=["POST"])
@login_required
@admin_only
def toggle_user(user_id):
    target = db.session.get(User, user_id)
    if target is None or target.id == current_user.id or target.role == "admin":
        log_event("user_change", "denied", actor=current_user,
                  detail=f"refused for {user_id}"[:200])
        flash("That account cannot be changed.", "danger")
        return redirect(url_for("admin.home"))
    target.active = not target.active
    db.session.commit()
    log_event("user_enable" if target.active else "user_disable", "allowed",
              actor=current_user, detail=target.email)
    flash(f"{target.email} is now {'active' if target.active else 'disabled'}.", "success")
    return redirect(url_for("admin.home"))