from models import User

GOOD = {"name": "Test Person", "email": "person@test.com",
        "password": "TestPass12345", "role": "viewer"}


def register(client, **changes):
    return client.post("/register", data={**GOOD, **changes})


def test_registration_can_never_create_an_admin(flask_app):
    r = register(flask_app.test_client(), email="eve@test.com", role="admin")
    assert r.status_code == 400
    with flask_app.app_context():
        assert User.query.filter_by(email="eve@test.com").first() is None


def test_normal_registration_works(flask_app):
    assert register(flask_app.test_client(), role="owner").status_code == 302
    with flask_app.app_context():
        assert User.query.filter_by(email="person@test.com").one().role == "owner"


def test_short_password_is_refused(flask_app):
    assert register(flask_app.test_client(), password="abc123").status_code == 400


def test_duplicate_email_is_refused(flask_app):
    c = flask_app.test_client()
    assert register(c).status_code == 302
    assert register(c).status_code == 400


def test_login_errors_do_not_reveal_which_emails_exist(flask_app):
    c = flask_app.test_client()
    register(c)
    wrong_password = c.post("/login", data={"email": "person@test.com", "password": "nope-nope-nope"})
    unknown_email = c.post("/login", data={"email": "nobody@test.com", "password": "nope-nope-nope"})
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert b"Invalid email or password." in wrong_password.data
    assert b"Invalid email or password." in unknown_email.data


def test_login_does_not_redirect_to_other_websites(flask_app):
    c = flask_app.test_client()
    register(c)
    r = c.post("/login?next=https://evil.com",
               data={"email": "person@test.com", "password": "TestPass12345"})
    assert r.status_code == 302
    assert "evil.com" not in r.headers["Location"]


def test_logout_by_plain_link_is_not_allowed(flask_app):
    c = flask_app.test_client()
    register(c)
    c.post("/login", data={"email": "person@test.com", "password": "TestPass12345"})
    assert c.get("/logout").status_code == 405


def test_dashboard_needs_login(flask_app):
    r = flask_app.test_client().get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]