import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.massassign import check_mass_assign
import hushhunt.checks.active.massassign  # registers
from tests.vulnapp import handler, safe_handler

PROFILE = "https://t.invalid/api/profile"


def _session_a(h):
    a = httpx.Client(transport=httpx.MockTransport(h), follow_redirects=False)
    a.get("https://t.invalid/login")
    a.post("https://t.invalid/login", data={"username": "acct_a",
                                            "password": "hu" + "sh",
                                            "authenticity_token": "tok123"})
    return a


def test_marker_persists_then_cleaned_up():
    from tests import vulnapp
    vulnapp.PROFILE.clear()
    a = _session_a(handler)
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", PROFILE)))
    ctx.session_a = a
    ctx.profile_url = PROFILE
    out = check_mass_assign(ctx)
    assert len(out) == 1 and out[0]["severity_hint"] == "medium"
    # rollback ran: marker value is now null, field key may linger but must
    # not carry a usable value
    assert vulnapp.PROFILE.get("hushhunt_pwn") is None


def test_strict_api_zero_signals():
    def h(req):
        if req.url.path == "/login":
            return handler(req)
        if req.url.path == "/api/profile":
            return httpx.Response(200, json={"saved": "name only"}, request=req)
        return httpx.Response(404, text="nf", request=req)
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", PROFILE)))
    ctx.session_a = _session_a(h)
    ctx.profile_url = PROFILE
    assert check_mass_assign(ctx) == []


def test_no_session_no_op():
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", PROFILE)))
    assert check_mass_assign(ctx) == []
