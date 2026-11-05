from conftest import PASSWORD, SECRET
from extensions import db
from models import AuditLog, User


def user_id(app, email):
    with app.app_context():
        return User.query.filter_by(email=email).one().id


def test_non_admins_cannot_open_admin_pages(world):
    for client in (world.owner1, world.owner2, world.viewer):
        for path in ("/admin/", "/admin/audit"):
            assert client.get(path).status_code == 404
    assert world.app.test_client().get("/admin/").status_code == 302


def test_non_admin_cannot_use_admin_actions(world):
    assert world.owner1.post("/admin/verify").status_code == 404
    vid = user_id(world.app, "viewer1@test.com")
    assert world.owner1.post(f"/admin/users/{vid}/toggle").status_code == 404
    with world.app.app_context():
        assert User.query.filter_by(email="viewer1@test.com").one().active is True


def test_admin_sees_activity_but_cannot_read_documents(world):
    admin = world._user_client("admin@test.com", "admin")
    assert admin.get("/admin/").status_code == 200
    assert b"secret.txt" in admin.get("/admin/audit?action=upload").data
    r = admin.get(world.url("download"))
    assert r.status_code == 404
    assert SECRET not in r.data
    assert admin.get(world.url("edit")).status_code == 404
    assert admin.post(world.url("delete")).status_code == 404


def test_admin_can_verify_and_detect_tampering(world):
    admin = world._user_client("admin@test.com", "admin")
    assert b"verified" in admin.post("/admin/verify", follow_redirects=True).data
    with world.app.app_context():
        row = AuditLog.query.order_by(AuditLog.id).first()
        row.detail = "EDITED"
        db.session.commit()
    assert b"TAMPERING DETECTED" in admin.post("/admin/verify", follow_redirects=True).data


def test_disabling_a_user_logs_them_out_at_once(world):
    admin = world._user_client("admin@test.com", "admin")
    world.grant("viewer1@test.com", "read")
    assert world.viewer.get(world.url("download")).status_code == 200
    vid = user_id(world.app, "viewer1@test.com")
    assert admin.post(f"/admin/users/{vid}/toggle").status_code == 302
    assert world.viewer.get(world.url("download")).status_code == 302


def test_admin_cannot_disable_an_admin_or_themselves(world):
    admin = world._user_client("admin@test.com", "admin")
    admin.post(f"/admin/users/{user_id(world.app, 'admin@test.com')}/toggle")
    with world.app.app_context():
        assert User.query.filter_by(email="admin@test.com").one().active is True


def test_repeated_failed_logins_are_blocked(flask_app):
    c = flask_app.test_client()
    c.post("/register", data={"name": "Person", "email": "p@test.com",
                              "password": PASSWORD, "role": "viewer"})
    for _ in range(5):
        r = c.post("/login", data={"email": "p@test.com", "password": "wrong-wrong-1"})
        assert r.status_code == 401
    assert c.post("/login", data={"email": "p@test.com", "password": PASSWORD}).status_code == 429
    assert c.post("/login", data={"email": "other@test.com", "password": "x" * 12}).status_code == 401
    with flask_app.app_context():
        assert AuditLog.query.filter_by(action="login_blocked").count() == 1


def test_security_headers_are_set(flask_app):
    r = flask_app.test_client().get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


def test_admin_registration_attempt_is_recorded(flask_app):
    c = flask_app.test_client()
    c.post("/register", data={"name": "Eve", "email": "eve@test.com",
                              "password": PASSWORD, "role": "admin"})
    with flask_app.app_context():
        assert AuditLog.query.filter_by(action="register", outcome="denied").count() == 1