import os, uuid

os.environ.update(DATABASE_URL="sqlite:///./test.db", COOKIE_SECURE="0", RATE_LIMIT="1000")
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import main

CODES: dict = {}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main, "send_code", lambda email, code, purpose: CODES.__setitem__((email, purpose), code))
    with TestClient(main.app) as c:
        yield c


def payload(email=None, **over):
    email = email or f"{uuid.uuid4().hex[:8]}@example.com"
    return {"first_name": "Ana", "last_name": "Dela Cruz", "phone": "+63 917 123 4567", "email": email, "email_confirm": email, **over}


def test_full_flow(client):
    p = payload()
    assert client.post("/api/register", json=p).status_code == 200
    assert client.post("/api/verify", json={"email": p["email"], "code": CODES[(p["email"], "verify")]}).status_code == 200
    me = client.get("/api/me").json()
    assert me["first_name"] == "Ana" and me["phone"] == "+639171234567" and me["seconds_left"] > 86000
    assert client.post("/api/logout").status_code == 200
    assert client.get("/api/me").status_code == 401
    client.post("/api/login", json={"email": p["email"]})
    assert client.post("/api/login/verify", json={"email": p["email"], "code": CODES[(p["email"], "login")]}).status_code == 200
    assert client.get("/api/me").status_code == 200


def test_validation(client):
    assert client.post("/api/register", json=payload(email_confirm="other@example.com")).status_code == 422
    assert client.post("/api/register", json=payload(phone="12345")).status_code == 422
    assert client.post("/api/register", json=payload(first_name="R2D2")).status_code == 422
    assert client.post("/api/register", json=payload(email="not-an-email", email_confirm="not-an-email")).status_code == 422


def test_wrong_code_and_lockout(client):
    p = payload()
    client.post("/api/register", json=p)
    for _ in range(5):
        assert client.post("/api/verify", json={"email": p["email"], "code": "000000" if CODES[(p["email"], "verify")] != "000000" else "111111"}).status_code == 400
    assert client.post("/api/verify", json={"email": p["email"], "code": CODES[(p["email"], "verify")]}).status_code == 400
    assert client.get("/api/me").status_code == 401


def test_unknown_email_gets_same_response(client):
    r = client.post("/api/login", json={"email": "nobody@example.com"})
    assert r.status_code == 200 and ("nobody@example.com", "login") not in CODES


def test_expired_accounts_are_purged(client):
    p = payload()
    client.post("/api/register", json=p)
    client.post("/api/verify", json={"email": p["email"], "code": CODES[(p["email"], "verify")]})
    with main.engine.begin() as c:
        c.execute(text("UPDATE users SET expires_at=:t WHERE email=:e"), {"t": main.now() - 1, "e": p["email"]})
    assert client.get("/api/me").status_code == 401
    main.purge()
    with main.engine.begin() as c:
        assert c.execute(text("SELECT COUNT(*) FROM users WHERE email=:e"), {"e": p["email"]}).scalar() == 0
        assert c.execute(text("SELECT COUNT(*) FROM sessions")).scalar() >= 0
