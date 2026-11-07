import io

from conftest import file_data
from models import Document


def put(client, url, content=b"hacked"):
    return client.post(url, data={"file": (io.BytesIO(content), "x.txt")},
                       content_type="multipart/form-data")


def test_revoking_an_edit_grant_removes_edit_and_read(world):
    world.grant("viewer1@test.com", "edit")
    assert put(world.viewer, world.url("edit"), b"v1").status_code == 302
    world.revoke("viewer1@test.com")
    assert world.viewer.get(world.url("download")).status_code == 404
    assert world.viewer.get(world.url("edit")).status_code == 404
    assert put(world.viewer, world.url("edit"), b"v2").status_code == 404
    assert world.owner1.get(world.url("download")).data == b"v1"


def test_revoking_one_person_does_not_affect_another(world):
    world.grant("viewer1@test.com", "read")
    world.grant("owner2@test.com", "read")
    world.revoke("viewer1@test.com")
    assert world.viewer.get(world.url("download")).status_code == 404
    assert world.owner2.get(world.url("download")).status_code == 200


def test_regrant_after_revoke_restores_access(world):
    world.grant("viewer1@test.com", "read")
    world.revoke("viewer1@test.com")
    assert world.viewer.get(world.url("download")).status_code == 404
    world.grant("viewer1@test.com", "read")
    assert world.viewer.get(world.url("download")).status_code == 200


def test_only_the_owner_can_revoke(world):
    world.grant("viewer1@test.com", "read")
    gid = world._grant_id("viewer1@test.com")
    assert world.viewer.post(world.url(f"revoke/{gid}")).status_code == 404
    assert world.owner2.post(world.url(f"revoke/{gid}")).status_code == 404
    assert world.viewer.get(world.url("download")).status_code == 200


def test_revoke_cannot_be_pointed_at_another_documents_grant(world):
    world.grant("viewer1@test.com", "read")
    gid = world._grant_id("viewer1@test.com")
    r = world.owner1.post("/upload", data=file_data(b"second", "second.txt"),
                          content_type="multipart/form-data")
    assert r.status_code == 302
    with world.app.app_context():
        other_id = Document.query.filter_by(original_name="second.txt").one().id
    r = world.owner1.post(f"/documents/{other_id}/revoke/{gid}")
    assert r.status_code == 302
    assert world.viewer.get(world.url("download")).status_code == 200