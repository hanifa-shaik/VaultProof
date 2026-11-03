import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db

ROLES = ("admin", "owner", "viewer")


def new_id():
    return str(uuid.uuid4())


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.active


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.String(36), primary_key=True, default=new_id)
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False, default="general")
    content_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    storage_name = db.Column(db.String(64), unique=True, nullable=False, default=new_id)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)

    owner = db.relationship("User", backref="documents")


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ts = db.Column(db.String(40), nullable=False)
    actor_id = db.Column(db.String(36), nullable=True)
    actor_email = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    outcome = db.Column(db.String(10), nullable=False)
    document_id = db.Column(db.String(36), nullable=True, index=True)
    detail = db.Column(db.String(500), nullable=False, default="")
    ip = db.Column(db.String(64), nullable=True)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)


class Grant(db.Model):
    """One person's access to one document. Revoking sets revoked_at."""
    __tablename__ = "grants"
    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="uq_grant_doc_user"),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    document_id = db.Column(db.String(36), db.ForeignKey("documents.id"),
                            nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"),
                        nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)  # "read" or "edit"
    granted_by = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    document = db.relationship("Document", backref="grants")
    user = db.relationship("User", foreign_keys=[user_id])
class FileBlob(db.Model):
    """The bytes of an uploaded file. Only code that has passed authorize()
    ever reads this table."""
    __tablename__ = "file_blobs"

    storage_name = db.Column(db.String(64), primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
