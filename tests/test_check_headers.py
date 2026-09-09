import httpx
from hushhunt.checks import CHECK_CATALOG, Ctx
import hushhunt.checks.headers  # noqa: F401  (registers)


def _resp(headers, url="https://app.smallco.io/dashboard", text=""):
    return httpx.Response(200, headers=headers, request=httpx.Request("GET", url), text=text)


def _ctx(**kw):
    return Ctx(**kw)


def test_catalog_entries_have_wstg_mapping():
    import hushhunt.checks.active.xss  # noqa: F401  (active modules also registered)
    assert len(CHECK_CATALOG) >= 7
    for c in CHECK_CATALOG.values():
        assert c.wstg and c.wstg.startswith("WSTG-"), c.id
        assert c.risk in ("passive", "low", "medium", "high"), c.id
        assert c.fn is not None


def test_missing_headers_produce_signals():
    resp = _resp([("Set-Cookie", "sessionid=abcdef012345; Path=/"),
                  ("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/7.4.3")])
    signals = CHECK_CATALOG["passive_headers"].fn(_ctx(resp=resp))
    kinds = {s["payload"]["issue"] for s in signals}
    assert "missing_csp" in kinds
    assert "missing_hsts" in kinds
    assert any("httponly" in k.lower() for k in kinds)
    # session token must be truncated in payloads (never full secrets in DB)
    flat = str(signals)
    assert "abcdef012345" not in flat and "abcdef" in flat


def test_clean_https_response_yields_no_header_signals():
    resp = _resp([
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("Strict-Transport-Security", "max-age=63072000"),
        ("Set-Cookie", "sid=xyz123abc456; HttpOnly; Secure; SameSite=Lax; Path=/"),
        ("Server", "edge"),
    ])
    assert CHECK_CATALOG["passive_headers"].fn(_ctx(resp=resp)) == []


def test_version_disclosure_check():
    resp = _resp([("Server", "Apache/2.4.49 (Unix)")])
    out = CHECK_CATALOG["version_disclosure"].fn(_ctx(resp=resp))
    assert len(out) == 1
    assert "2.4.49" in out[0]["payload"]["value"]
    assert out[0]["check_id"] == "version_disclosure"


def test_no_version_no_signal():
    assert CHECK_CATALOG["version_disclosure"].fn(_ctx(resp=_resp([("Server", "edge")]))) == []
