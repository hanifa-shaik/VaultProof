"""Creates demo accounts and sample documents. Safe to run more than once."""
import hashlib
import os

from app import app
from audit import log_event
from extensions import db
from models import Document, FileBlob, Grant, User, new_id

PASSWORD = os.environ.get("SEED_PASSWORD", "TestPass12345")

ACCOUNTS = [
    ("Demo Admin", "admin@trustvault.test", "admin"),
    ("Demo Owner", "owner@trustvault.test", "owner"),
    ("Demo Viewer", "viewer@trustvault.test", "viewer"),
]


def get_or_create_user(name, email, role):
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(name=name, email=email, role=role)
        db.session.add(user)
    user.role = role
    user.active = True
    user.set_password(PASSWORD)
    db.session.commit()
    return user


def seed_document(owner, viewer, name, text, share_with_viewer):
    if Document.query.filter_by(owner_id=owner.id, original_name=name).first():
        return
    data = text.encode("utf-8")
    storage_name = new_id()
    doc = Document(owner_id=owner.id, original_name=name, category="general",
                   content_type="text/plain", size_bytes=len(data),
                   sha256=hashlib.sha256(data).hexdigest(),
                   storage_name=storage_name)
    db.session.add(doc)
    db.session.add(FileBlob(storage_name=storage_name, data=data))
    db.session.commit()
    log_event("upload", "allowed", actor=owner, document_id=doc.id,
              detail=f"{name} (seed data)")
    if share_with_viewer:
        db.session.add(Grant(document_id=doc.id, user_id=viewer.id,
                             permission="read", granted_by=owner.id))
        db.session.commit()
        log_event("grant", "allowed", actor=owner, document_id=doc.id,
                  detail=f"read to {viewer.email} (seed data)")


if __name__ == "__main__":
    with app.app_context():
        admin, owner, viewer = [get_or_create_user(*a) for a in ACCOUNTS]
        seed_document(owner, viewer, "welcome.txt",
                      "Welcome to TrustVault. The demo viewer was given read access to this file.\n",
                      True)
        seed_document(owner, viewer, "private-notes.txt",
                      "This file was NOT shared. Only the demo owner may open it.\n",
                      False)
        print("Seed complete:", [a[1] for a in ACCOUNTS])