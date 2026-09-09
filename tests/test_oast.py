import httpx

from hushhunt.config import Config
from hushhunt.oast import FakeOast, OastClient


def _cfg(enabled, server="https://interact.invalid"):
    return Config({"oast": {"enabled": enabled, "server": server,
                            "poll_timeout_seconds": 2}}, ".")


def test_disabled_makes_zero_requests():
    calls = []
    client = OastClient(_cfg(False), client_factory=lambda **kw: httpx.Client(
        transport=httpx.MockTransport(lambda r: calls.append(r.url) or httpx.Response(200, json=[]))))
    t = client.new_token("https://app.smallco.io/x")
    assert t.startswith("hush-")
    assert client.poll(t) == []
    assert calls == []


def test_enabled_poll_hits_server_and_returns_matches():
    def handler(req):
        assert req.url.host == "interact.invalid"
        return httpx.Response(200, json={"requests": [
            {"uid": "u1", "host": "abc.example", "method": "GET",
             "url": "http://abc.example/hit?src=app"}]})
    client = OastClient(_cfg(True), client_factory=lambda **kw: httpx.Client(
        transport=httpx.MockTransport(handler)))
    out = client.poll("hush-token", tag="app")
    assert len(out) == 1 and out[0]["uid"] == "u1"


def test_token_is_deterministic_per_asset_and_unique_per_nonce():
    client = OastClient(_cfg(True), client_factory=None)
    a = client.new_token("https://app.smallco.io/x", nonce="n1")
    b = client.new_token("https://app.smallco.io/x", nonce="n1")
    c = client.new_token("https://app.smallco.io/x", nonce="n2")
    assert a == b and a != c
    assert "smallco" not in a.lower()          # asset name must not leak to OAST


def test_fake_oast_fire_and_poll():
    f = FakeOast()
    tok = f.new_token("asset")
    assert f.poll(tok) == []
    f.fire(tok, {"url": "http://hit"})
    assert f.poll(tok) == [{"url": "http://hit"}]
    assert f.poll(tok) == []   # consumed: callbacks match exactly once
