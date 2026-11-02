"""The ONE place that decides who may do what to a document.
Every route must call authorize(). The default answer is False (deny).

Rules:
  - The owner of a document may do everything to it.
  - Anyone else needs an active grant (not revoked, not expired).
  - A "read" grant allows reading only. An "edit" grant allows reading and editing.
  - Deleting and sharing are for the owner only, never through a grant.
"""
from datetime import timezone

from models import Grant, utcnow

ACTIONS = ("read", "edit", "delete", "share")


def _active_grant(user, doc):
    """Looked up in the database EVERY time, so revoking works at once."""
    g = Grant.query.filter_by(document_id=doc.id, user_id=user.id,
                              revoked_at=None).first()
    if g is None:
        return None
    if g.expires_at is not None:
        expires = g.expires_at
        if expires.tzinfo is None:           # SQLite drops the timezone
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= utcnow():
            return None
    return g


def authorize(user, doc, action):
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if not user.active:
        return False
    if doc is None or doc.deleted_at is not None:
        return False
    if action not in ACTIONS:
        return False

    # The owner of the document may do everything.
    if user.role == "owner" and doc.owner_id == user.id:
        return True

    # Everyone else needs an active grant.
    g = _active_grant(user, doc)
    if g is None:
        return False
    if action == "read":
        return g.permission in ("read", "edit")
    if action == "edit":
        return g.permission == "edit"
    return False        # delete and share are owner-only