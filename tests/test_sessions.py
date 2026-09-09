import pytest

from hushhunt.config import Config
from hushhunt.sessions import SessionBroker, load_accounts, SessionError


def _accounts_file(tmp_path):
    p = tmp_path / "seeds"
    p.mkdir()
    (p / "accounts.yaml").write_text(
        "h1:1:\n"
        "  - id: acct_a\n"
        "    user: a@example.com\n"
        "    password_env: HH_A\n"
        "    login_url: https://app.smallco.io/login\n"
        "    csrf_field: authenticity_token\n"
        "  - id: acct_b\n"
        "    user: b@example.com\n"
        "    password_env: HH_B\n"
        "    login_url: https://app.smallco.io/login\n",
        encoding="utf-8")
    return Config({"sessions": {"file": "seeds/accounts.yaml"}, "limits": {}}, tmp_path)


def test_load_accounts(tmp_path):
    cfg = _accounts_file(tmp_path)
    accts = load_accounts(cfg, "h1:1")
    assert [a["id"] for a in accts] == ["acct_a", "acct_b"]
    assert load_accounts(cfg, "h1:999") == []


def test_login_uses_password_from_env_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_A", "sekret")
    monkeypatch.setenv("HH_B", "sekret")
    cfg = _accounts_file(tmp_path)
    sent = []

    def handler(req):
        sent.append((str(req.url), req.content.decode()))
        if req.url.path == "/login" and req.method == "GET":
            return __import__("httpx").Response(200, text='<input name="authenticity_token" value="tok123">')
        if req.url.path == "/login":
            return __import__("httpx").Response(
                302, headers=[("Location", "/"), ("Set-Cookie", "sid=A; Path=/")])
        return __import__("httpx").Response(404, text="x")

    import httpx
    def factory(**kw):
        return httpx.Client(transport=httpx.MockTransport(handler),
                            follow_redirects=False)
    broker = SessionBroker({"id": "h1:1", "includes": ["app.smallco.io"],
                            "excludes": []}, load_accounts(cfg, "h1:1"),
                           client_factory=factory)
    s = broker.session("acct_a")
    assert s.cookies.get("sid") == "A"
    body = sent[-1][1]
    assert "sekret" in body and "tok123" in body    # csrf scraped and reposted


def test_login_failure_raises_no_retry(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_A", "x")
    monkeypatch.setenv("HH_B", "x")
    cfg = _accounts_file(tmp_path)
    import httpx
    calls = []

    def handler(req):
        calls.append(str(req.url))
        if req.method == "GET":
            return httpx.Response(200, text="no csrf field here")
        return httpx.Response(403, text="denied")

    broker = SessionBroker({"id": "h1:1", "includes": ["app.smallco.io"],
                            "excludes": []}, load_accounts(cfg, "h1:1"),
                           client_factory=lambda **kw: httpx.Client(
                               transport=httpx.MockTransport(handler),
                               follow_redirects=False))
    with pytest.raises(SessionError):
        broker.session("acct_a")
    assert len(calls) == 2   # GET form + POST once; no retries


def test_password_env_missing_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("HH_A", raising=False)
    monkeypatch.delenv("HH_B", raising=False)
    cfg = _accounts_file(tmp_path)
    broker = SessionBroker({"id": "h1:1", "includes": [], "excludes": []},
                           load_accounts(cfg, "h1:1"), client_factory=None)
    with pytest.raises(RuntimeError):
        broker.session("acct_a")


def test_unknown_account_id(tmp_path):
    cfg = _accounts_file(tmp_path)
    broker = SessionBroker({"id": "h1:1", "includes": [], "excludes": []},
                           load_accounts(cfg, "h1:1"), client_factory=None)
    with pytest.raises(KeyError):
        broker.session("nope")


def test_credentials_never_sent_out_of_scope(tmp_path, monkeypatch):
    """login_url pointing outside program scope => refuse before any request."""
    monkeypatch.setenv("HH_A", "x")
    monkeypatch.setenv("HH_B", "x")
    cfg = _accounts_file(tmp_path)
    import httpx
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, text="would have leaked")

    broker = SessionBroker({"id": "h1:1", "includes": ["tinyshop.dev"], "excludes": []},
                           load_accounts(cfg, "h1:1"),
                           client_factory=lambda **kw: httpx.Client(
                               transport=httpx.MockTransport(handler)))
    with pytest.raises(SessionError):
        broker.session("acct_a")
    assert calls == []   # zero traffic: creds never leave scope
