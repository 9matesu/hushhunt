import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.jsmining import check_js, check_js_secrets

BASE = "https://app.smallco.io/"
FULL_FAKE_KEY = "AKIA1234567890ABCDEF"  # clearly synthetic test value


def _mk_ctx(html, js_pages):
    calls = []

    def fetch(url, headers=None):
        calls.append(url)
        text, status = js_pages.get(url, ("", 404))
        return httpx.Response(status, text=text, request=httpx.Request("GET", url))

    resp = httpx.Response(200, text=html, request=httpx.Request("GET", BASE))
    return Ctx(resp=resp, fetch=fetch), calls


def test_script_budget_is_four_of_six():
    html = "".join(f'<script src="/static/b{i}.js"></script>' for i in range(6))
    pages = {f"https://app.smallco.io/static/b{i}.js":
             (f'fetch("/api/v1/page{i}");', 200) for i in range(6)}
    ctx, calls = _mk_ctx(html, pages)
    out = check_js(ctx)
    assert len(calls) == 4, "must never fetch more than 4 scripts"
    assert out[0]["payload"]["routes"], "routes extracted from fetched scripts"
    assert len(out[0]["payload"]["routes"]) <= 30


def test_third_party_scripts_never_fetched():
    html = '<script src="https://cdn.thirdparty-analytics.io/x.js"></script>' \
           '<script src="/app.js"></script>'
    pages = {"https://app.smallco.io/app.js": ('f("/api/v2/orders");', 200)}
    ctx, calls = _mk_ctx(html, pages)
    check_js(ctx)
    assert calls == ["https://app.smallco.io/app.js"]  # no third-party traffic


def test_secret_in_script_redacted_never_full():
    js_body = f'var conf = {{ aws: "{FULL_FAKE_KEY}" }}; f("/api/v1/users");'
    html = '<script src="/app.js"></script>'
    pages = {"https://app.smallco.io/app.js": (js_body, 200)}
    ctx, _ = _mk_ctx(html, pages)
    check_js(ctx)                      # populates ctx.fetched_js
    leaks = check_js_secrets(ctx)
    assert len(leaks) == 1
    assert leaks[0]["check_id"] == "js_secret_leak"
    assert leaks[0]["severity_hint"] == "high"
    payload = str(leaks[0]["payload"])
    assert FULL_FAKE_KEY not in payload, "full secret must NEVER reach DB/reports"
    assert "AKIA1234" in payload and "len=20" in payload


def test_no_routes_no_signals_and_missing_fetch_is_safe():
    ctx, calls = _mk_ctx("<html><body>plain</body></html>", {})
    assert check_js(ctx) == [] and calls == []
    resp = httpx.Response(200, text="<html></html>", request=httpx.Request("GET", BASE))
    assert check_js(Ctx(resp=resp)) == []       # fetch None -> passive skip
    assert check_js_secrets(Ctx(resp=resp)) == []
