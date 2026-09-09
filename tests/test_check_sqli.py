import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.sqli import check_sqli_boolean, check_sqli_error
import hushhunt.checks.active.sqli  # registers
from tests.vulnapp import handler, safe_handler


def _ctx(h):
    calls = []

    def fetch(url, headers=None):
        calls.append(str(url))
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    resp = httpx.Client(transport=httpx.MockTransport(h)).get(
        "https://t.invalid/item?id=1")
    ctx = Ctx(resp=resp, fetch=fetch)
    ctx.params = [("https://t.invalid/item?id=1", "id", "1")]
    return ctx, calls


def test_error_fingerprint_flagged():
    ctx, calls = _ctx(handler)
    out = check_sqli_error(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["fingerprint"].lower().startswith("pg_query")
    assert len(calls) <= 3          # 1 baseline + 2 probes MAX


def test_boolean_delta_flagged():
    ctx, calls = _ctx(handler)
    out = check_sqli_boolean(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["delta_ratio"] >= 0.3
    assert len(calls) <= 2          # exactly TRUE+FALSE, no data extraction


def test_safe_handler_no_signals():
    ctx, calls = _ctx(safe_handler)
    assert check_sqli_error(ctx) == []
    ctx2, _ = _ctx(safe_handler)
    assert check_sqli_boolean(ctx2) == []


def test_static_page_no_false_positive():
    def static(req):
        return httpx.Response(200, text="blog post with the word sql and error")
    ctx, calls = _ctx(static)
    assert check_sqli_error(ctx) == []   # vague text must not trip fingerprint
    assert check_sqli_boolean(ctx) == []
