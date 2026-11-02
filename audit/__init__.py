import hashlib
import json

from flask import has_request_context, request

from extensions import db
from models import AuditLog, utcnow

GENESIS = "0" * 64


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