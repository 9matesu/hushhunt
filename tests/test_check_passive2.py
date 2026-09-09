import socket
import ssl

import httpx

from hushhunt.checks import Ctx
import hushhunt.checks.files as files_mod
import hushhunt.checks.cors as cors_mod
import hushhunt.checks.tlsconfig as tls_mod

BASE_URL = "https://app.smallco.io/dashboard"


def _ctx_with(fake_pages):
    """fake_pages: url -> (status, text, headers). Counts every fetch."""
    calls = []

    def fetch(url, headers=None):
        calls.append(url)
        status, text, hdrs = fake_pages.get(url, (404, "not found", {}))
        return httpx.Response(status, text=text, headers=hdrs,
                              request=httpx.Request("GET", url))

    resp = httpx.Response(200, request=httpx.Request("GET", BASE_URL))
    return Ctx(resp=resp, fetch=fetch), calls


def _origin_pages(**overrides):
    o = f"https://app.smallco.io"
    pages = {
        o + "/robots.txt": (404, "no", {}),
        o + "/sitemap.xml": (404, "no", {}),
        o + "/.well-known/security.txt": (404, "no", {}),
        o + "/.git/config": (404, "no", {}),
        o + "/.env": (404, "no", {}),
    }
    pages.update(overrides)
    return pages


def test_exposed_git_config_flags_and_request_count_is_bounded():
    o = "https://app.smallco.io"
    pages = _origin_pages(**{o + "/.git/config": (200, "[core]\n\trepositoryformatversion = 0", {})})
    ctx, calls = _ctx_with(pages)
    signals = files_mod.check_exposed_files(ctx)
    assert len(signals) == 1
    assert signals[0]["severity_hint"] == "high"
    # LOW-NOISE CONTRACT: exactly the allowlist size, never more.
    assert len(calls) == len(files_mod.ALLOWED_PATHS)


def test_soft404_html_page_is_not_a_finding():
    o = "https://app.smallco.io"
    pages = _origin_pages(**{o + "/.env": (200, "<html><body>404 style page</body></html>", {})})
    ctx, _ = _ctx_with(pages)
    assert files_mod.check_exposed_files(ctx) == []


def test_env_needs_real_key_lines():
    o = "https://app.smallco.io"
    pages = _origin_pages(**{o + "/.env": (200, "just some text page", {})})
    ctx, _ = _ctx_with(pages)
    assert files_mod.check_exposed_files(ctx) == []
    pages = _origin_pages(**{o + "/.env": (200, "DATABASE_URL=postgres://u:p@h/db", {})})
    ctx, _ = _ctx_with(pages)
    out = files_mod.check_exposed_files(ctx)
    assert len(out) == 1
    # preview must exist for triage but be capped (120 chars)
    assert len(out[0]["payload"]["preview"]) <= 120


def test_cors_canary_echo_is_the_only_flag():
    o = "https://app.smallco.io"
    cors_page = {o + "/dashboard": (200, "", {"Access-Control-Allow-Origin":
                                              cors_mod.CANARY_ORIGIN})}
    ctx, calls = _ctx_with(cors_page)
    out = cors_mod.check_cors(ctx)
    assert len(out) == 1 and out[0]["payload"]["issue"] == "reflected_arbitrary_origin"
    assert len(calls) == 1  # exactly one canary request


def test_cors_wildcard_with_credentials():
    o = "https://app.smallco.io"
    ctx, _ = _ctx_with({o + "/dashboard": (200, "", {
        "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})})
    out = cors_mod.check_cors(ctx)
    assert out and out[0]["payload"]["issue"] == "wildcard_with_credentials"


def test_cors_vary_only_not_flagged():
    o = "https://app.smallco.io"
    ctx, _ = _ctx_with({o + "/dashboard": (200, "", {"Vary": "Origin"})})
    assert cors_mod.check_cors(ctx) == []


def test_tls_unreachable_host_is_silence(monkeypatch):
    def boom(*a, **k):
        raise OSError("nope")
    monkeypatch.setattr(tls_mod.socket, "create_connection", boom)
    resp = httpx.Response(200, request=httpx.Request("GET", BASE_URL))
    assert tls_mod.check_tls(Ctx(resp=resp)) == []


def test_tls_cert_verify_error_is_signal(monkeypatch):
    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def conn(*a, **k): raise ssl.SSLCertVerificationError("self signed certificate")
    monkeypatch.setattr(tls_mod.socket, "create_connection", conn)
    resp = httpx.Response(200, request=httpx.Request("GET", BASE_URL))
    out = tls_mod.check_tls(Ctx(resp=resp))
    assert len(out) == 1 and out[0]["payload"]["issue"] == "cert_verify_failed"
