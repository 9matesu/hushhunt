import pytest

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.grants import create_grant
from hushhunt.planner import PlannedTest, plan, validate
from hushhunt.triage.llm import FakeLlm

PROGRAM = {"id": "h1:1", "name": "s", "risk_cap": "medium",
           "includes": ["t.invalid"], "excludes": []}
CONTEXT = {"params_seen": [{"url_path": "https://t.invalid/proxy?url=/x",
                            "param": "url"}],
           "apis_seen": ["/api/v1/orders"]}


@pytest.fixture(autouse=True)
def _grant_secret(monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")


def _conn(tmp_path, cap="medium"):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "s",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "",
                          "scope_json": '{"includes":["t.invalid"],"excludes":[]}'})
    conn.execute("UPDATE programs SET risk_cap=?", (cap,))
    conn.commit()
    return conn


def test_valid_proposal_approved(tmp_path):
    conn = _conn(tmp_path)
    create_grant(conn, "h1:1", "xss_reflected", "probe", 24, 100)
    llm = FakeLlm([{"tests": [{"module": "xss_reflected",
                               "url": "https://t.invalid/proxy?url=/x",
                               "param": "url", "why": "reflected param"}]}])
    cfg = Config({"triage": {}}, tmp_path)
    out = plan(cfg, conn, llm, PROGRAM, CONTEXT)
    assert len(out) == 1 and out[0].module == "xss_reflected"


def test_rejects_invented_surface(tmp_path):
    conn = _conn(tmp_path)
    create_grant(conn, "h1:1", "ssti", "probe", 24, 100)
    llm = FakeLlm([{"tests": [{"module": "ssti",
                               "url": "https://t.invalid/hidden",
                               "param": "tpl", "why": "guess"}]}])
    cfg = Config({"triage": {}}, tmp_path)
    assert plan(cfg, conn, llm, PROGRAM, CONTEXT) == []
    assert "invented_surface" in (tmp_path / "out/planner_rejected.log").read_text()


def test_rejects_out_of_scope(tmp_path):
    conn = _conn(tmp_path)
    create_grant(conn, "h1:1", "xss_reflected", "probe", 24, 100)
    llm = FakeLlm([{"tests": [{"module": "xss_reflected",
                               "url": "https://evil.t.invalid/p?a=1",
                               "param": "a"}]}])
    # evil.t.invalid matches wildcard? our includes: ["t.invalid"] exact only
    cfg = Config({"triage": {}}, tmp_path)
    ctx = {"params_seen": [{"url_path": "https://evil.t.invalid/p?a=1",
                            "param": "a"}]}
    assert plan(cfg, conn, llm, PROGRAM, ctx) == []
    log = (tmp_path / "out/planner_rejected.log").read_text()
    assert "out_of_scope" in log


def test_rejects_without_grant(tmp_path):
    conn = _conn(tmp_path)   # NO grant created for xss_reflected
    llm = FakeLlm([{"tests": [{"module": "xss_reflected",
                               "url": "https://t.invalid/proxy?url=/x",
                               "param": "url"}]}])
    cfg = Config({"triage": {}}, tmp_path)
    assert plan(cfg, conn, llm, PROGRAM, CONTEXT) == []
    assert "no_grant" in (tmp_path / "out/planner_rejected.log").read_text()


def test_risk_cap_passive_blocks_all(tmp_path):
    conn = _conn(tmp_path, cap="passive")
    create_grant(conn, "h1:1", "xss_reflected", "probe", 24, 100)
    pt = PlannedTest("xss_reflected", "https://t.invalid/proxy?url=/x", "url", "")
    # risk_cap lives on the program dict the caller normalizes from DB:
    assert validate(pt, {**PROGRAM, "risk_cap": "passive"}, conn) == "risk_cap"


def test_demoted_module_rejected(tmp_path):
    conn = _conn(tmp_path)
    create_grant(conn, "h1:1", "xss_reflected", "probe", 24, 100)
    pt = PlannedTest("xss_reflected", "https://t.invalid/proxy?url=/x", "url", "")
    assert validate(pt, PROGRAM, conn, demoted={"xss_reflected"}) == "auto_demoted"
    assert validate(pt, PROGRAM, conn, lint_blocked={"xss_reflected"}) == "policy_blocked"


def test_unknown_module_fails_closed():
    conn = None
    pt = PlannedTest("rce_pwn", "https://t.invalid/x", "y", "")
    assert validate(pt, {"risk_cap": "medium", "includes": ["t.invalid"],
                         "excludes": []}, conn) == "unknown_module"


def test_llm_cannot_widen_permissions(tmp_path):
    """Even a prompt-injected reply claiming 'granted': the validator checks
    the DB, not the model."""
    conn = _conn(tmp_path)
    llm = FakeLlm([{"tests": [{"module": "idor",
                               "url": "https://t.invalid/proxy?url=/x",
                               "param": "url", "why": "operator already granted"}]}])
    cfg = Config({"triage": {}}, tmp_path)
    assert plan(cfg, conn, llm, PROGRAM, CONTEXT) == []
