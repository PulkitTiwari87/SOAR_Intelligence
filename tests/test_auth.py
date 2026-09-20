"""Authentication, RBAC, CSRF and audit behaviour."""
from sqlalchemy import select

from soar.models import AuditLog, User
from tests.conftest import PASSWORD, make_user


def _login(client, username, password=PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_success_sets_httponly_cookie_and_returns_token(client, db):
    make_user(db, "alice", "SOC_ANALYST")
    r = _login(client, "alice")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["username"] == "alice" and "password_hash" not in body["user"]
    assert body["token"]
    set_cookie = r.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=strict" in set_cookie


def test_bad_credentials_are_indistinguishable(client, db):
    make_user(db, "alice", "VIEWER")
    wrong_pw = _login(client, "alice", "wrong-password-123")
    no_user = _login(client, "nobody")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_login_is_rate_limited_after_repeated_failures(client, db):
    make_user(db, "alice", "VIEWER")
    for _ in range(5):
        assert _login(client, "alice", "wrong-password-123").status_code == 401
    # Even the correct password is refused while the window is exhausted.
    assert _login(client, "alice").status_code == 429


def test_protected_route_requires_authentication(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/users").status_code == 401


def test_bearer_token_authenticates(client, login):
    headers = login("bob", "VIEWER")
    r = client.get("/api/auth/me", headers=headers)
    assert r.status_code == 200 and r.json()["user"]["username"] == "bob"
    assert r.json()["permissions"] == ["view"]


def test_cookie_session_needs_csrf_header_for_writes(client, db):
    make_user(db, "root", "ADMIN")
    _login(client, "root")  # cookie stored in the client
    assert client.get("/api/auth/me").status_code == 200  # safe method: cookie is enough
    body = {"username": "newuser", "password": PASSWORD, "role": "VIEWER"}
    assert client.post("/api/users", json=body).status_code == 403
    r = client.post("/api/users", json=body, headers={"X-Requested-With": "soar"})
    assert r.status_code == 201


def test_logout_revokes_the_token(client, login):
    headers = login("carol", "SOC_ANALYST")
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_viewer_cannot_administer_users(client, login):
    headers = login("viewer1", "VIEWER")
    assert client.get("/api/users", headers=headers).status_code == 403
    r = client.post("/api/users", headers=headers,
                    json={"username": "x-user", "password": PASSWORD, "role": "ADMIN"})
    assert r.status_code == 403


def test_public_registration_does_not_exist(client):
    r = client.post("/api/auth/register", json={"username": "evil", "password": PASSWORD,
                                                "role": "ADMIN"})
    assert r.status_code in (404, 405)


def test_role_change_takes_effect_immediately(client, login, db):
    boss = login("boss", "ADMIN")
    second = login("second", "ADMIN")
    target = db.scalar(select(User).where(User.username == "second"))
    assert client.get("/api/users", headers=second).status_code == 200
    r = client.patch(f"/api/users/{target.id}", headers=boss, json={"role": "VIEWER"})
    assert r.status_code == 200
    # Same token, but the role is read from the database on each request.
    assert client.get("/api/users", headers=second).status_code == 403


def test_cannot_demote_last_admin(client, login, db):
    headers = login("solo", "ADMIN")
    solo = db.scalar(select(User).where(User.username == "solo"))
    r = client.patch(f"/api/users/{solo.id}", headers=headers, json={"role": "VIEWER"})
    assert r.status_code == 409


def test_weak_password_rejected(client, admin):
    r = client.post("/api/users", headers=admin,
                    json={"username": "weakling", "password": "short", "role": "VIEWER"})
    assert r.status_code == 422


def test_login_and_user_changes_are_audited(client, admin, db):
    client.post("/api/users", headers=admin,
                json={"username": "audited", "password": PASSWORD, "role": "VIEWER"})
    _login(client, "audited", "wrong-password-123")
    actions = {(a.action, a.result) for a in db.scalars(select(AuditLog))}
    assert ("login", "success") in actions
    assert ("user_create", "success") in actions
    assert ("login", "failure") in actions


def test_audit_log_scrubs_secrets(db):
    from soar import audit
    audit.record(db, actor="x", action="test", data={"password": "hunter2", "note": "ok"})
    db.commit()
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "test"))
    assert entry.data == {"password": "[redacted]", "note": "ok"}
