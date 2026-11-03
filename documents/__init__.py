import hashlib
import io
import zipfile

from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, send_file, url_for)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from audit import log_event
from extensions import db
from models import Document, FileBlob, Grant, User, new_id, utcnow
from permissions import authorize

bp = Blueprint("documents", __name__)

# Allow-list: extension -> content type WE decide (never trust the browser's).
ALLOWED = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
CATEGORIES = ("general", "contract", "hr", "finance", "legal", "drawing", "audit")


def content_matches(ext, data):
    """Check the REAL bytes of the file, not just its name."""
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == "txt":
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    if ext in ("docx", "xlsx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
        except zipfile.BadZipFile:
            return False
        prefix = "word/" if ext == "docx" else "xl/"
        return "[Content_Types].xml" in names and any(n.startswith(prefix) for n in names)
    return False


def refuse(message, reason, filename=""):
    """Record the refused upload in the audit log, then show the message."""
    log_event("upload", "denied", actor=current_user,
              detail=f"{reason}: {filename}"[:200])
    flash(message, "danger")
    return render_template("upload.html", categories=CATEGORIES), 400


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # Only owners may upload. Everyone else is refused AND logged.
    if current_user.role != "owner":
        log_event("upload", "denied", actor=current_user, detail="role is not owner")
        abort(403)

    if request.method == "GET":
        return render_template("upload.html", categories=CATEGORIES)

    f = request.files.get("file")
    category = request.form.get("category", "")

    if f is None or not f.filename:
        return refuse("Please choose a file.", "no file")
    if category not in CATEGORIES:
        return refuse("Please choose a valid category.", "bad category", f.filename)

    name = secure_filename(f.filename)
    if "." not in name:
        return refuse("The file needs a name with an extension, like report.pdf.",
                      "no extension", f.filename)
    ext = name.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED:
        return refuse("That file type is not allowed. Allowed: "
                      + ", ".join(sorted(ALLOWED)) + ".", "type not allowed", name)

    data = f.read()
    if len(data) == 0:
        return refuse("The file is empty.", "empty file", name)
    if not content_matches(ext, data):
        return refuse("The file contents do not match its type.",
                      "content mismatch", name)

    storage_name = new_id()          # random name for the stored bytes
    doc = Document(
        owner_id=current_user.id,
        original_name=name[:255],
        category=category,
        content_type=ALLOWED[ext],
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        storage_name=storage_name,
    )
    db.session.add(doc)
    db.session.add(FileBlob(storage_name=storage_name, data=data))
    try:
        db.session.commit()          # document row and bytes saved together
    except Exception:
        db.session.rollback()
        raise

    log_event("upload", "allowed", actor=current_user, document_id=doc.id,
              detail=f"{name} ({len(data)} bytes)")
    flash("Document uploaded.", "success")
    return redirect(url_for("dashboard"))


def load_or_404(doc_id, permission, event):
    """Fetch a document only if the current user is authorised.
    'Not yours' and 'does not exist' give the SAME 404 answer."""
    doc = db.session.get(Document, doc_id)
    if not authorize(current_user, doc, permission):
        log_event(event, "denied", actor=current_user,
                  document_id=doc_id[:36],
                  detail="not authorised or not found")
        abort(404)
    return doc


@bp.route("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    doc = load_or_404(doc_id, "read", "download")

    blob = db.session.get(FileBlob, doc.storage_name)
    if blob is None:
        log_event("download", "denied", actor=current_user,
                  document_id=doc.id, detail="stored file missing")
        abort(404)
    data = bytes(blob.data)

    # The file must still match the fingerprint stored at upload.
    if hashlib.sha256(data).hexdigest() != doc.sha256:
        log_event("download", "denied", actor=current_user,
                  document_id=doc.id, detail="integrity check failed")
        abort(500)

    log_event("download", "allowed", actor=current_user,
              document_id=doc.id, detail=doc.original_name)

    resp = send_file(io.BytesIO(data), mimetype=doc.content_type,
                     as_attachment=True, download_name=doc.original_name)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/documents/<doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    doc = load_or_404(doc_id, "delete", "delete")
    doc.deleted_at = utcnow()          # soft delete: the row and bytes are kept
    db.session.commit()
    log_event("delete", "allowed", actor=current_user,
              document_id=doc.id, detail=doc.original_name)
    flash("Document deleted.", "success")
    return redirect(url_for("dashboard"))


@bp.route("/documents/<doc_id>/share")
@login_required
def share(doc_id):
    doc = load_or_404(doc_id, "share", "share_view")
    grants = Grant.query.filter_by(document_id=doc.id, revoked_at=None).all()
    return render_template("share.html", doc=doc, grants=grants)


@bp.route("/documents/<doc_id>/grant", methods=["POST"])
@login_required
def grant(doc_id):
    doc = load_or_404(doc_id, "share", "grant")
    email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission", "")

    if permission not in ("read", "edit"):
        flash("Please choose read or edit.", "danger")
        return redirect(url_for("documents.share", doc_id=doc.id))

    target = User.query.filter_by(email=email).first()
    if target is None or not target.active or target.id == current_user.id:
        log_event("grant", "denied", actor=current_user, document_id=doc.id,
                  detail=f"invalid target: {email}"[:200])
        flash("Could not share with that person. Check the email address.", "danger")
        return redirect(url_for("documents.share", doc_id=doc.id))

    existing = Grant.query.filter_by(document_id=doc.id, user_id=target.id).first()
    if existing is None:
        db.session.add(Grant(document_id=doc.id, user_id=target.id,
                             permission=permission, granted_by=current_user.id))
    else:                                    # re-grant or change level
        existing.permission = permission
        existing.revoked_at = None
        existing.granted_by = current_user.id
        existing.created_at = utcnow()
    db.session.commit()

    log_event("grant", "allowed", actor=current_user, document_id=doc.id,
              detail=f"{permission} to {target.email}")
    flash(f"Shared with {target.email} ({permission}).", "success")
    return redirect(url_for("documents.share", doc_id=doc.id))


@bp.route("/documents/<doc_id>/revoke/<int:grant_id>", methods=["POST"])
@login_required
def revoke(doc_id, grant_id):
    doc = load_or_404(doc_id, "share", "revoke")
    g = db.session.get(Grant, grant_id)
    if g is None or g.document_id != doc.id or g.revoked_at is not None:
        log_event("revoke", "denied", actor=current_user, document_id=doc.id,
                  detail="grant not found for this document")
        flash("That access could not be found.", "danger")
        return redirect(url_for("documents.share", doc_id=doc.id))

    g.revoked_at = utcnow()
    db.session.commit()
    log_event("revoke", "allowed", actor=current_user, document_id=doc.id,
              detail=f"{g.permission} removed from {g.user.email}")
    flash("Access removed.", "success")
    return redirect(url_for("documents.share", doc_id=doc.id))


@bp.route("/documents/<doc_id>/edit", methods=["GET", "POST"])
@login_required
def edit(doc_id):
    # "edit" permission: the owner, or someone with an edit grant.
    doc = load_or_404(doc_id, "edit", "edit")
    old_ext = doc.original_name.rsplit(".", 1)[-1].lower()

    if request.method == "GET":
        return render_template("edit.html", doc=doc, old_ext=old_ext)

    def refuse_edit(message, reason):
        log_event("edit", "denied", actor=current_user, document_id=doc.id,
                  detail=reason[:200])
        flash(message, "danger")
        return render_template("edit.html", doc=doc, old_ext=old_ext), 400

    f = request.files.get("file")
    if f is None or not f.filename:
        return refuse_edit("Please choose a file.", "no file")

    name = secure_filename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext != old_ext:
        return refuse_edit(f"The new file must be a .{old_ext} file, like the original.",
                           "different type: " + (ext or "none"))

    data = f.read()
    if len(data) == 0:
        return refuse_edit("The file is empty.", "empty file")
    if not content_matches(ext, data):
        return refuse_edit("The file contents do not match its type.", "content mismatch")

    # Save the new bytes under a new random name and drop the old bytes,
    # all in ONE database transaction.
    old_storage = doc.storage_name
    old_hash = doc.sha256
    new_storage = new_id()
    db.session.add(FileBlob(storage_name=new_storage, data=data))
    old_blob = db.session.get(FileBlob, old_storage)
    if old_blob is not None:
        db.session.delete(old_blob)
    doc.storage_name = new_storage
    doc.size_bytes = len(data)
    doc.sha256 = hashlib.sha256(data).hexdigest()
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    log_event("edit", "allowed", actor=current_user, document_id=doc.id,
              detail=f"{doc.original_name}: {old_hash[:12]} -> {doc.sha256[:12]}")
    flash("Document updated.", "success")
    return redirect(url_for("dashboard"))