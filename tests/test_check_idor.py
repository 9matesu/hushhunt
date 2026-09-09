import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.idor import check_idor
import hushhunt.checks.active.idor  # registers
from tests.vulnapp import handler, safe_handler


def _sessions(h):
    a = httpx.Client(transport=httpx.MockTransport(h), follow_redirects=False)
    b = httpx.Client(transport=httpx.MockTransport(h), follow_redirects=False)
    for c, who in ((a, "acct_a"), (b, "acct_b")):
        c.get("https://t.invalid/login")
        c.post("https://t.invalid/login", data={
            "username": who, "password": "hu" + "sh",
            "authenticity_token": "tok123"})
    return a, b


def _ctx(h, owned):
    a, b = _sessions(h)
    ctx = Ctx(resp=httpx.Response(200,
                                  request=httpx.Request("GET", "https://t.invalid/")))
    ctx.session_a, ctx.session_b = a, b
    ctx.owned_urls = owned
    return ctx


def test_cross_tenant_read_flagged():
    ctx = _ctx(handler, [("https://t.invalid/api/orders/1", "order-ownerA")])
    out = check_idor(ctx)
    assert len(out) == 1 and out[0]["severity_hint"] == "high"
    assert out[0]["payload"]["attacker"] == "acct_b"


def test_authorized_app_zero_signals():
    ctx = _ctx(safe_handler, [("https://t.invalid/api/orders/1", "order-ownerA")])
    assert check_idor(ctx) == []


def test_missing_sessions_skip_not_error():
    ctx = Ctx(resp=httpx.Response(200,
                                  request=httpx.Request("GET", "https://t.invalid/")))
    assert check_idor(ctx) == []


def test_object_cap_three():
    owned = [(f"https://t.invalid/api/orders/{i}", "order-ownerA")
             for i in range(1, 7)]          # 6 "seen" objects
    ctx = _ctx(handler, owned)
    out = check_idor(ctx)
    # ids 1..3 touched (cap=3): only order 1 carries A's fingerprint
    assert len(out) == 1


def test_cap_blocks_deeper_requests():
    # instrument: count requests to object ids > 3 -> must be zero
    seen_urls = []

    def spy(req):
        seen_urls.append(str(req.url))
        return handler(req)

    owned = [(f"https://t.invalid/api/orders/{i}", "order-ownerA")
             for i in range(1, 7)]
    ctx = _ctx(spy, owned)
    check_idor(ctx)
    assert not [u for u in seen_urls if any(f"orders/{i}" in u for i in (4, 5, 6))]
