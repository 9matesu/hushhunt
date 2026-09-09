import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.ssti import check_ssti
import hushhunt.checks.active.ssti  # registers
from tests.vulnapp import handler, safe_handler


def _ctx(h):
    calls = []

    def fetch(url, headers=None):
        calls.append(str(url))
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    resp = httpx.Client(transport=httpx.MockTransport(h)).get(
        "https://t.invalid/render?tpl=hello")
    ctx = Ctx(resp=resp, fetch=fetch)
    ctx.params = [("https://t.invalid/render?tpl=hello", "tpl", "hello")]
    return ctx, calls


def test_vulnapp_render_flagged():
    ctx, calls = _ctx(handler)
    out = check_ssti(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["probe"] == "{{7*7}}"
    assert len(calls) <= 4      # baseline + first probe hits, stops


def test_safe_handler_zero():
    ctx, _ = _ctx(safe_handler)
    assert check_ssti(ctx) == []


def test_static_no_fp_even_with_49():
    def h(req):
        return httpx.Response(200, text="price is 49 dollars always")
    ctx, _ = _ctx(h)
    assert check_ssti(ctx) == []
