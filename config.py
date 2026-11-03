import os

from dotenv import load_dotenv

load_dotenv()

IS_PRODUCTION = os.environ.get("APP_ENV") == "production"
_DEV_KEY = "dev-only-not-for-production"
_SECRET = os.environ.get("SECRET_KEY", _DEV_KEY)

if IS_PRODUCTION and _SECRET == _DEV_KEY:
    raise RuntimeError("SECRET_KEY must be set when APP_ENV=production")


def database_url():
    """Neon gives postgresql://... ; SQLAlchemy needs the psycopg driver name."""
    url = os.environ.get("DATABASE_URL", "sqlite:///trustvault.db")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


class Config:
    IS_PRODUCTION = IS_PRODUCTION
    SECRET_KEY = _SECRET
    SQLALCHEMY_DATABASE_URI = database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}   # survives Neon waking up
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION                 # HTTPS only when live
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024                 # 10 MB