import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.xss import check_xss_reflected
from tests.vulnapp import handler, safe_handler

URL = "https://t.invalid/search?q=x"


def _ctx(h, budget=50):
    calls = []

    def fetch(url, headers=None):
        if len(calls) >= budget:
            raise AssertionError("budget blown")
        calls.append(str(url))
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    resp = httpx.Client(transport=httpx.MockTransport(h)).get(URL)
    return Ctx(resp=resp, fetch=fetch), calls


def test_vulnapp_search_flagged():
    ctx, calls = _ctx(handler)
    ctx.params = [(URL, "q", "x")]
    out = check_xss_reflected(ctx)
    assert len(out) == 1
    assert out[0]["check_id"] == "xss_reflected"
    assert "hush" in out[0]["payload"]["marker"]
    # noise contract: max 4 probes even though we keep probing until hit
    assert len(calls) <= 4


def test_safe_handler_zero_signals():
    ctx, calls = _ctx(safe_handler)
    ctx.params = [(URL, "q", "x")]
    assert check_xss_reflected(ctx) == []
    assert len(calls) <= 4          # safe app also gets max 4 probes


def test_one_signal_per_param_and_fanout_cap():
    ctx, calls = _ctx(handler)
    ctx.params = [(URL, "q", "x")] * 3
    out = check_xss_reflected(ctx)
    assert len(out) == 1
    many = [(f"https://t.invalid/search?p{i}=x", f"p{i}", "") for i in range(12)]
    ctx2, calls2 = _ctx(handler, budget=200)
    ctx2.params = many
    check_xss_reflected(ctx2)
    assert len(ctx2.params) == 12           # input untouched...
    assert sum(1 for u in calls2 if "p10=" in u or "p11=" in u) == 0  # ...but capped
