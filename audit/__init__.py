import hashlib
import json

from flask import has_request_context, request
from sqlalchemy import text

from extensions import db
from models import AuditLog, utcnow

GENESIS = "0" * 64

# PostgreSQL only: the database itself refuses to change or remove audit rows.
GUARD_SQL = [
    """CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log",
    """CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_append_only()""",
    "DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log",
    """CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only()""",
]


def _compute_hash(prev_hash, ts, actor_id, actor_email, action, outcome,
                  document_id, detail, ip):
    payload = json.dumps(
        [prev_hash, ts, actor_id, actor_email, action, outcome,
         document_id, detail, ip],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(action, outcome, actor=None, document_id=None, detail=""):
    """Write one audit row, chained to the previous row. Call this for
    every action, including refused ones."""
    if db.engine.dialect.name == "postgresql":
        # One writer at a time, so two requests can never fork the chain.
        db.session.execute(text("SELECT pg_advisory_xact_lock(7305)"))
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last.entry_hash if last else GENESIS

    ts = utcnow().isoformat()
    actor_id = actor.id if actor is not None and actor.is_authenticated else None
    actor_email = actor.email if actor_id else None
    ip = request.remote_addr if has_request_context() else None
    detail = (detail or "")[:500]

    entry_hash = _compute_hash(prev_hash, ts, actor_id, actor_email, action,
                               outcome, document_id, detail, ip)
    db.session.add(AuditLog(
        ts=ts, actor_id=actor_id, actor_email=actor_email, action=action,
        outcome=outcome, document_id=document_id, detail=detail, ip=ip,
        prev_hash=prev_hash, entry_hash=entry_hash,
    ))
    db.session.commit()


def chain_head():
    """(id, hash) of the newest row. Keep a copy outside the system."""
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    return (last.id, last.entry_hash) if last else (0, GENESIS)


def verify_chain():
    """Return (True, None) if the log is intact, else (False, id_of_first_bad_row)."""
    expected_prev = GENESIS
    for row in AuditLog.query.order_by(AuditLog.id.asc()).all():
        recomputed = _compute_hash(row.prev_hash, row.ts, row.actor_id,
                                   row.actor_email, row.action, row.outcome,
                                   row.document_id, row.detail, row.ip)
        if row.prev_hash != expected_prev or row.entry_hash != recomputed:
            return False, row.id
        expected_prev = row.entry_hash
    return True, None


def install_guards():
    """PostgreSQL only: refuse UPDATE, DELETE and TRUNCATE on audit_log."""
    if db.engine.dialect.name != "postgresql":
        return
    for statement in GUARD_SQL:
        db.session.execute(text(statement))
    db.session.commit()