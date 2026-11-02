import hashlib
import io
import os
import zipfile

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from audit import log_event
from extensions import db
from models import Document, new_id

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


def vault_dir():
    """Private folder. It is inside instance/, which Flask never serves."""
    path = os.path.join(current_app.instance_path, "vault")
    os.makedirs(path, exist_ok=True)
    return path


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

    storage_name = new_id()          # random name on disk
    path = os.path.join(vault_dir(), storage_name)
    with open(path, "wb") as out:
        out.write(data)

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
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        os.remove(path)              # do not leave an orphan file behind
        raise

    log_event("upload", "allowed", actor=current_user, document_id=doc.id,
              detail=f"{name} ({len(data)} bytes)")
    flash("Document uploaded.", "success")
    return redirect(url_for("dashboard"))