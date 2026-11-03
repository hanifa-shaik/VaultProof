import io

from conftest import SECRET
from extensions import db
from models import Document, Grant


def put(client, url, content=b"hacked"):
    return client.post(url, data={"file": (io.BytesIO(content), "x.txt")},
                       content_type="multipart/form-data")


# ---------- Sanity: the owner can use their own document ----------

def test_owner_can_download_own_document(world):
    r = world.owner1.get(world.url("download"))
    assert r.status_code == 200
    assert r.data == SECRET


# ---------- People who were NOT granted access ----------

def test_anonymous_is_sent_to_login(world):
    anon = world.app.test_client()
    r = anon.get(world.url("download"))
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_other_owner_cannot_download(world):
    r = world.owner2.get(world.url("download"))
    assert r.status_code == 404
    assert SECRET not in r.data


def test_viewer_without_grant_cannot_download(world):
    r = world.viewer.get(world.url("download"))
    assert r.status_code == 404
    assert SECRET not in r.data


def test_other_owner_cannot_delete(world):
    r = world.owner2.post(world.url("delete"))
    assert r.status_code == 404
    with world.app.app_context():
        assert db.session.get(Document, world.doc_id).deleted_at is None


def test_other_owner_cannot_edit(world):
    assert world.owner2.get(world.url("edit")).status_code == 404
    assert put(world.owner2, world.url("edit")).status_code == 404
    assert world.owner1.get(world.url("download")).data == SECRET


def test_other_owner_cannot_share(world):
    assert world.owner2.get(world.url("share")).status_code == 404
    r = world.owner2.post(world.url("grant"),
                          data={"email": "viewer1@test.com", "permission": "read"})
    assert r.status_code == 404
    with world.app.app_context():
        assert Grant.query.count() == 0


def test_other_owner_cannot_see_document_on_dashboard(world):
    assert b"secret.txt" in world.owner1.get("/dashboard").data   # sanity check
    assert b"secret.txt" not in world.owner2.get("/dashboard").data


def test_search_never_shows_documents_not_given(world):
    r = world.owner2.get("/dashboard?q=secret")
    assert b"secret.txt" not in r.data
    r = world.owner2.get("/dashboard?owner=owner1")
    assert b"secret.txt" not in r.data


def test_not_yours_looks_the_same_as_does_not_exist(world):
    real = world.owner2.get(world.url("download"))
    fake = world.owner2.get("/documents/00000000-0000-0000-0000-000000000000/download")
    assert real.status_code == fake.status_code == 404
    assert real.data == fake.data


# ---------- Read and edit grants ----------

def test_read_grant_allows_download_but_nothing_else(world):
    world.grant("viewer1@test.com", "read")
    r = world.viewer.get(world.url("download"))
    assert r.status_code == 200 and r.data == SECRET
    assert world.viewer.get(world.url("edit")).status_code == 404
    assert put(world.viewer, world.url("edit")).status_code == 404
    assert world.viewer.post(world.url("delete")).status_code == 404
    assert world.viewer.get(world.url("share")).status_code == 404


def test_edit_grant_allows_edit_but_not_delete_or_share(world):
    world.grant("viewer1@test.com", "edit")
    assert put(world.viewer, world.url("edit"), b"new text").status_code == 302
    assert world.owner1.get(world.url("download")).data == b"new text"
    assert world.viewer.post(world.url("delete")).status_code == 404
    assert world.viewer.get(world.url("share")).status_code == 404
    r = world.viewer.post(world.url("grant"),
                          data={"email": "owner2@test.com", "permission": "read"})
    assert r.status_code == 404


def test_a_grant_to_one_person_does_not_help_another(world):
    world.grant("viewer1@test.com", "edit")
    assert world.owner2.get(world.url("download")).status_code == 404


# ---------- Taking access away ----------

def test_revoke_takes_effect_immediately(world):
    world.grant("viewer1@test.com", "read")
    assert world.viewer.get(world.url("download")).status_code == 200
    world.revoke("viewer1@test.com")
    assert world.viewer.get(world.url("download")).status_code == 404
    assert b"secret.txt" not in world.viewer.get("/dashboard").data


def test_expired_grant_stops_working(world):
    world.grant("viewer1@test.com", "read")
    assert world.viewer.get(world.url("download")).status_code == 200
    world.expire_grant("viewer1@test.com")
    assert world.viewer.get(world.url("download")).status_code == 404


def test_disabled_user_loses_access(world):
    world.grant("viewer1@test.com", "read")
    world.set_active("viewer1@test.com", False)
    r = world.viewer.get(world.url("download"))
    assert r.status_code in (302, 404)
    assert SECRET not in r.data


def test_deleted_document_is_unreachable(world):
    assert world.owner1.post(world.url("delete")).status_code == 302
    assert world.owner1.get(world.url("download")).status_code == 404