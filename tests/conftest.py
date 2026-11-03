import io
from datetime import timedelta

import pytest

from config import Config
from extensions import db
from models import Document, Grant, User, utcnow

SECRET = b"top secret contents"
PASSWORD = "TestPass12345"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"   # throw-away in-memory database
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-key"


@pytest.fixture()
def flask_app(tmp_path):
    from app import create_app

    application = create_app(TestingConfig)
    application.instance_path = str(tmp_path)   # uploads go to a temp folder
    return application


def file_data(content, name, category="general"):
    return {"file": (io.BytesIO(content), name), "category": category}


class World:
    """owner1 owns one document. owner2 and viewer1 were given nothing."""

    def __init__(self, app):
        self.app = app
        self.owner1 = self._user_client("owner1@test.com", "owner")
        self.owner2 = self._user_client("owner2@test.com", "owner")
        self.viewer = self._user_client("viewer1@test.com", "viewer")

        r = self.owner1.post("/upload", data=file_data(SECRET, "secret.txt"),
                             content_type="multipart/form-data")
        assert r.status_code == 302
        with app.app_context():
            self.doc_id = Document.query.filter_by(original_name="secret.txt").one().id

    def _user_client(self, email, role):
        with self.app.app_context():
            user = User(name=email.split("@")[0], email=email, role=role)
            user.set_password(PASSWORD)
            db.session.add(user)
            db.session.commit()
        client = self.app.test_client()
        r = client.post("/login", data={"email": email, "password": PASSWORD})
        assert r.status_code == 302
        return client

    def url(self, what):
        return f"/documents/{self.doc_id}/{what}"

    def grant(self, email, permission):
        r = self.owner1.post(self.url("grant"),
                             data={"email": email, "permission": permission})
        assert r.status_code == 302

    def _grant_id(self, email):
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            return Grant.query.filter_by(document_id=self.doc_id,
                                         user_id=user.id).one().id

    def revoke(self, email):
        gid = self._grant_id(email)
        r = self.owner1.post(self.url(f"revoke/{gid}"))
        assert r.status_code == 302

    def expire_grant(self, email):
        gid = self._grant_id(email)
        with self.app.app_context():
            g = db.session.get(Grant, gid)
            g.expires_at = utcnow() - timedelta(hours=1)
            db.session.commit()

    def set_active(self, email, active):
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            user.active = active
            db.session.commit()


@pytest.fixture()
def world(flask_app):
    return World(flask_app)