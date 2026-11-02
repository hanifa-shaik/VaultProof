"""The ONE place that decides who may do what to a document.
Every route must call authorize(). The default answer is False (deny)."""

ACTIONS = ("read", "edit", "delete", "share")


def authorize(user, doc, action):
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if not user.active:
        return False
    if doc is None or doc.deleted_at is not None:
        return False
    if action not in ACTIONS:
        return False

    # For now only the owner of the document is allowed.
    # Grants to other people are added in the next part.
    if user.role == "owner" and doc.owner_id == user.id:
        return True

    return False