import pytest

from hushhunt.session_manager import ResilientSession


def test_session_auto_heals_on_401():
    import httpx

    login_count = 0
    token = "token_old"

    def login():
        nonlocal login_count, token
        login_count += 1
        token = f"token_fresh_{login_count}"
        return {"Authorization": f"Bearer {token}"}

    def handler(request: httpx.Request):
        auth = request.headers.get("Authorization", "")
        if auth == "Bearer token_old":
            return httpx.Response(401, json={"error": "expired token"})
        if auth == "Bearer token_fresh_1":
            return httpx.Response(200, json={"user": "admin", "status": "active"})
        return httpx.Response(403)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    session = ResilientSession(client, reauth_fn=login, initial_headers={"Authorization": "Bearer token_old"})

    resp = session.get("https://t.invalid/api/profile")
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"
    assert login_count == 1
