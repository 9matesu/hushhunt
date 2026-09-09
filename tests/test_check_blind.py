import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.blind import check_blind_oast
import hushhunt.checks.active.blind  # registers
from hushhunt.oast import FakeOast


def _ssrf_app(oast, fetches_outbound=True):
    """App whose /proxy?url= endpoint server-side-fetches the given URL.
    When fetches_outbound=True it 'hits' the canary -> fires the OAST."""
    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/proxy":
            u = req.url.params.get("url", "")
            if fetches_outbound and u.startswith("http://fake.oast/hit?"):
                token = httpx.URL(u).params.get("token", "")
                oast.fire(token, {"url": u, "type": "http"})
            return httpx.Response(200, text="proxied", request=req)
        return httpx.Response(200, text="base", request=req)
    return h


def _ctx(h):
    calls = []

    def fetch(url, headers=None):
        calls.append(url)
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    resp = httpx.Client(transport=httpx.MockTransport(h)).get(
        "https://t.invalid/proxy?url=/x")
    ctx = Ctx(resp=resp, fetch=fetch)
    ctx.params = [("https://t.invalid/proxy?url=/x", "url", "/x")]
    return ctx, calls


def test_blind_callback_proves_ssrf():
    oast = FakeOast()
    ctx, calls = _ctx(_ssrf_app(oast))
    ctx.oast = oast
    out = check_blind_oast(ctx)
    assert len(out) == 1
    assert out[0]["check_id"] == "blind_oast"
    assert "canary" in out[0]["payload"]
    assert len(calls) <= 3           # one probe per candidate param, capped


def test_no_callback_zero_signals():
    oast = FakeOast()
    ctx, _ = _ctx(_ssrf_app(oast, fetches_outbound=False))
    ctx.oast = oast
    assert check_blind_oast(ctx) == []   # no egress => no blind finding


def test_no_oast_no_op():
    ctx, calls = _ctx(_ssrf_app(FakeOast()))
    ctx.oast = None
    assert check_blind_oast(ctx) == []
    assert calls == []                   # doesn't even probe without OAST
