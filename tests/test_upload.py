from conftest import file_data
from models import AuditLog, Document


def post_file(client, name, content):
    return client.post("/upload", data=file_data(content, name),
                       content_type="multipart/form-data")


def test_valid_text_file_is_accepted(world):
    assert post_file(world.owner1, "notes.txt", b"hello").status_code == 302


def test_zip_is_refused(world):
    r = post_file(world.owner1, "hello.zip", b"PK\x03\x04 data")
    assert r.status_code == 400
    assert b"not allowed" in r.data


def test_exe_is_refused(world):
    r = post_file(world.owner1, "fake.exe", b"MZ program")
    assert r.status_code == 400
    assert b"not allowed" in r.data


def test_text_renamed_to_pdf_is_refused(world):
    r = post_file(world.owner1, "fake.pdf", b"hello")
    assert r.status_code == 400
    assert b"do not match" in r.data


def test_text_renamed_to_png_is_refused(world):
    r = post_file(world.owner1, "fake.png", b"hello")
    assert r.status_code == 400
    assert b"do not match" in r.data


def test_empty_file_is_refused(world):
    r = post_file(world.owner1, "empty.txt", b"")
    assert r.status_code == 400
    assert b"empty" in r.data


def test_refused_upload_creates_no_document_and_is_recorded(world):
    with world.app.app_context():
        before = Document.query.count()
    post_file(world.owner1, "fake.pdf", b"hello")
    with world.app.app_context():
        assert Document.query.count() == before
        assert AuditLog.query.filter_by(action="upload", outcome="denied").count() >= 1


def test_viewer_cannot_upload(world):
    assert post_file(world.viewer, "notes.txt", b"hello").status_code == 403


def test_path_in_file_name_is_removed_and_storage_name_is_random(world):
    assert post_file(world.owner1, "../../evil.txt", b"hi").status_code == 302
    with world.app.app_context():
        doc = Document.query.filter_by(original_name="evil.txt").one()
        assert doc.storage_name != "evil.txt"
        assert len(doc.storage_name) == 36