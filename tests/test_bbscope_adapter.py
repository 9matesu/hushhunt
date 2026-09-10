import json
from pathlib import Path

import httpx

from hushhunt.adapters.bbscope import (BBScopeAdapter, classify_target,
                                       classify_targets)
from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program

FIXTURE = [
    {"platform": "h1", "handle": "smallco-vdp",
     "url": "https://hackerone.com/smallco-vdp",
     "in_scope_count": 3, "out_of_scope_count": 0, "is_bbp": False,
     "targets": ["*.smallco.io", "app.smallco.io",
                 "https://shop.smallco.io/cart", "203.0.113.5",
                 "com.smallco.iosapp"]},
    {"platform": "h1", "handle": "empty-one", "url": "u",
     "targets": ["not a domain!!"]},
]


def _factory():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "bbscope.com"
        assert req.url.params.get("platform") == "h1"
        return httpx.Response(200, json=FIXTURE)
    return lambda **kw: httpx.Client(transport=httpx.MockTransport(handler))


def test_sync_classifies_targets():
    conn = open_db(Path(__file__).parent / "_unused_t.db") if False else None
    import tempfile
    from pathlib import Path as P
    tmp = P(tempfile.mkdtemp())
    conn = open_db(tmp / "t.db")
    cfg = Config({}, tmp)
    n = BBScopeAdapter(client_factory=_factory()).sync_programs(conn, cfg)
    assert n == 1     # the all-junk program is skipped
    row = conn.execute("SELECT * FROM programs WHERE id='h1:smallco-vdp'").fetchone()
    scope = json.loads(row["scope_json"])
    assert set(scope["includes"]) == {"*.smallco.io", "app.smallco.io",
                                      "shop.smallco.io"}
    assert scope["excludes"] == []
    # IP and mobile package dropped:
    assert all("203.0" not in i and "com." not in i for i in scope["includes"])
    assert row["risk_cap"] == "passive"          # conservative default
    assert row["safe_harbor"] == "unknown"       # honest: not synced
    assert "READ IT ON THE PROGRAM PAGE" in row["policy_text"]


def test_resync_preserves_operator_cap():
    import tempfile
    from pathlib import Path as P
    tmp = P(tempfile.mkdtemp())
    conn = open_db(tmp / "t.db")
    cfg = Config({}, tmp)
    BBScopeAdapter(client_factory=_factory()).sync_programs(conn, cfg)
    conn.execute("UPDATE programs SET risk_cap='medium' WHERE id='h1:smallco-vdp'")
    conn.commit()
    BBScopeAdapter(client_factory=_factory()).sync_programs(conn, cfg)
    cap = conn.execute("SELECT risk_cap FROM programs WHERE id='h1:smallco-vdp'"
                       ).fetchone()["risk_cap"]
    assert cap == "medium"       # sync must NEVER reset an operator choice


def test_classify_target():
    assert classify_target("https://a.io/x") == "a.io"
    assert classify_target("*.a.io") == "*.a.io"
    assert classify_target("A.IO") == "a.io"
    assert classify_target("198.51.100.7") is None
    assert classify_target("2001:db8::1") is None
    assert classify_target("org.mozilla.firefox") is None
    assert classify_target("github.com/org/repo/tree") == "github.com"
    assert classify_target("") is None


def test_registered_in_registry():
    from hushhunt.adapters import REGISTRY
    assert "bbscope" in REGISTRY
