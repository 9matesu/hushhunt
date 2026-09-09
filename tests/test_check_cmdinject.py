import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.cmdinject import check_cmd_inject
import hushhunt.checks.active.cmdinject  # registers
from hushhunt.oast import FakeOast


def _exec_app(oast, executes=True):
    """Mock /run?cmd= that 'shell-executes': if the injected value contains
    our canary URL and executes=True, the server fetches it (fires OAST)."""
    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/run":
            v = req.url.params.get("cmd", "")
            if executes and "fake.oast" in v:
                import re
                m = re.search(r"token=([\w\-]+)", v)
                if m:
                    oast.fire(m.group(1), {"type": "http", "host": "t.invalid"})
            return httpx.Response(200, text="ran", request=req)
        return httpx.Response(200, text="base", request=req)
    return h


def _ctx(h):
    calls = []

    def fetch(url, headers=None):
        calls.append(url)
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    resp = httpx.Client(transport=httpx.MockTransport(h)).get(
        "https://t.invalid/run?cmd=date")
    ctx = Ctx(resp=resp, fetch=fetch)
    ctx.params = [("https://t.invalid/run?cmd=date", "cmd", "date")]
    return ctx, calls


def test_command_execution_proven_via_oast():
    oast = FakeOast()
    ctx, calls = _ctx(_exec_app(oast))
    ctx.oast = oast
    out = check_cmd_inject(ctx)
    assert len(out) == 1
    assert out[0]["severity_hint"] == "critical"
    assert out[0]["payload"]["syntax"] == "semicolon_curl"
    # payloads are INERT: every probe command is only a canary fetch
    assert all("curl" in c and "fake.oast" in c for c in calls if "cmd=" in c)
    assert len(calls) <= 4          # probe cap honored


def test_safe_app_zero_callbacks_zero_signals():
    oast = FakeOast()
    ctx, _ = _ctx(_exec_app(oast, executes=False))
    ctx.oast = oast
    assert check_cmd_inject(ctx) == []


def test_no_oast_refuses_to_run():
    # without OAST there is no SAFE way to prove (or clean up) execution:
    # the module must not fire any probes at all
    ctx, calls = _ctx(_exec_app(FakeOast()))
    ctx.oast = None
    assert check_cmd_inject(ctx) == []
    assert calls == []


def test_param_cap_three():
    oast = FakeOast()
    ctx, calls = _ctx(_exec_app(oast))
    ctx.oast = oast
    ctx.params = [(f"https://t.invalid/run?cmd=date", "cmd", "date")] * 10
    check_cmd_inject(ctx)
    assert len([c for c in calls if "cmd=" in c]) <= 4


def test_payload_never_contains_destructive_tokens():
    import re
    from hushhunt.checks.active.cmdinject import _payloads
    probes = _payloads("http://fake.oast/hit?token=x")
    flat = " ".join(p for _, p in probes).lower()
    for bad in ("rm ", "mkfs", "shutdown", "dd if", ">", "wget"):
        assert bad not in flat, bad
