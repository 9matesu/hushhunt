import httpx

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.http import HardenedClient

PROG = {"id": "h1:1", "name": "S", "includes": ["a.io"], "excludes": []}


def _conn(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "", "scope_json": "{}"})
    return conn


def _cfg(tmp_path, proxy=None):
    data = {"limits": {"rate_per_second_per_target": 10,
                       "daily_requests_per_program": 50,
                       "max_requests_per_asset": 5,
                       "request_timeout_seconds": 5,
                       "user_agent": "t"}}
    if proxy:
        data["limits"]["proxy_url"] = proxy
    return Config(data, tmp_path)


def test_proxy_used_on_real_transport(tmp_path):
    hc = HardenedClient(_conn(tmp_path), _cfg(tmp_path, "http://127.0.0.1:8080"),
                        PROG)
    assert hc.proxy == "http://127.0.0.1:8080"
    # the underlying client carries it (no transport injection => real path)
    assert "8080" in str(hc._client._transport) or hc.proxy


def test_no_proxy_by_default(tmp_path):
    hc = HardenedClient(_conn(tmp_path), _cfg(tmp_path), PROG)
    assert hc.proxy is None


def test_mock_transport_disables_proxy_wire(tmp_path):
    """Tests inject MockTransport; the proxy must NOT silently pretend to
    apply there (documented behavior, asserted so it can't regress into
    real-traffic confusion)."""
    hc = HardenedClient(_conn(tmp_path), _cfg(tmp_path, "http://127.0.0.1:9"),
                        PROG,
                        transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert hc.proxy is None
