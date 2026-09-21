"""Shared fixtures: an isolated in-memory database and an authenticated API client."""
from __future__ import annotations

import os
import tempfile

import pytest

# Must be set before soar modules read settings. Models train once per test session into a temp dir.
os.environ["SOAR_MODEL_DIR"] = tempfile.mkdtemp(prefix="soar-test-models-")
os.environ["SOAR_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "test-secret-test-secret-test-secret-1234"
os.environ["INGEST_API_KEY"] = "test-ingest-key"
os.environ["LLM_PROVIDER"] = "none"
for var in ("WAZUH_API_URL", "MISP_URL", "THEHIVE_URL", "NOTIFY_WEBHOOK_URL", "SOAR_ADMIN_PASSWORD"):
    os.environ.pop(var, None)

from fastapi.testclient import TestClient  # noqa: E402

from soar import db as soar_db  # noqa: E402
from soar import security  # noqa: E402
from soar.config import reset_settings  # noqa: E402
from soar.models import Base, User  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Every test gets its own empty schema and data directory."""
    monkeypatch.setenv("SOAR_DATA_DIR", str(tmp_path / "data"))
    reset_settings()
    soar_db.reset_engine()
    Base.metadata.create_all(soar_db.get_engine())
    yield
    soar_db.reset_engine()


@pytest.fixture
def db():
    s = soar_db.new_session()
    try:
        yield s
    finally:
        s.close()


def make_user(db, username: str, role: str) -> User:
    u = User(username=username, password_hash=security.hash_password(PASSWORD), role=role)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def client(db):
    from soar.main import create_app
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def login(client, db):
    """login('analyst1', 'SOC_ANALYST') -> headers for an authenticated user (creates it)."""
    def _login(username: str = "admin", role: str = "ADMIN") -> dict:
        if not db.query(User).filter_by(username=username).first():
            make_user(db, username, role)
        r = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        client.cookies.clear()
        return {"Authorization": f"Bearer {r.json()['token']}"}
    return _login


@pytest.fixture
def admin(login):
    return login("admin", "ADMIN")
