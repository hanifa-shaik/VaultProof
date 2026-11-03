from audit import verify_chain
from extensions import db
from models import AuditLog


def rows(action, outcome):
    return AuditLog.query.filter_by(action=action, outcome=outcome).all()


def test_refused_download_is_recorded(world):
    world.owner2.get(world.url("download"))
    with world.app.app_context():
        found = rows("download", "denied")
        assert len(found) == 1
        assert found[0].actor_email == "owner2@test.com"
        assert found[0].document_id == world.doc_id


def test_allowed_download_is_recorded(world):
    world.owner1.get(world.url("download"))
    with world.app.app_context():
        found = rows("download", "allowed")
        assert len(found) == 1
        assert found[0].actor_email == "owner1@test.com"


def test_grant_and_revoke_are_recorded(world):
    world.grant("viewer1@test.com", "read")
    world.revoke("viewer1@test.com")
    with world.app.app_context():
        assert len(rows("grant", "allowed")) == 1
        assert len(rows("revoke", "allowed")) == 1


def test_refused_edit_and_delete_are_recorded(world):
    world.owner2.post(world.url("delete"))
    world.owner2.get(world.url("edit"))
    with world.app.app_context():
        assert len(rows("delete", "denied")) == 1
        assert len(rows("edit", "denied")) == 1


def test_untouched_chain_verifies(world):
    world.owner2.get(world.url("download"))
    with world.app.app_context():
        assert verify_chain() == (True, None)


def test_edited_audit_row_is_detected(world):
    world.owner2.get(world.url("download"))
    with world.app.app_context():
        row = AuditLog.query.order_by(AuditLog.id).first()
        row.detail = "EDITED"
        db.session.commit()
        ok, bad_id = verify_chain()
        assert ok is False
        assert bad_id == row.id


def test_deleted_audit_row_is_detected(world):
    world.owner2.get(world.url("download"))
    world.owner2.get(world.url("download"))
    with world.app.app_context():
        all_rows = AuditLog.query.order_by(AuditLog.id).all()
        assert len(all_rows) >= 3
        db.session.delete(all_rows[1])
        db.session.commit()
        ok, _ = verify_chain()
        assert ok is False