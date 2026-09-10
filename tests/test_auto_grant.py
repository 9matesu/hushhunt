import pytest

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.pipeline import granted_modules

PROG = {"id": "h1:1", "name": "S", "safe_harbor": "all",
        "includes": ["a.io"], "excludes": [], "risk_cap": "high",
        "policy_text": ""}


def _world(tmp_path, auto=None, policy=""):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": policy,
                          "scope_json": '{"includes":["a.io"],"excludes":[]}'})
    conn.commit()
    data = {"triage": {"min_confidence": 0.75}, "limits": {}}
    if auto is not None:
        data["auto_grant"] = auto
    return Config(data, tmp_path), conn


AUTO = {"enabled": True, "deep": True, "ttl_hours": 24, "max_requests": 150}


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")


def test_disabled_by_default_no_grants(tmp_path):
    cfg, conn = _world(tmp_path)
    mods = {m["module"] for m in granted_modules(conn, cfg, PROG)}
    assert mods == set()


def test_enabled_grants_probe_modules(tmp_path):
    cfg, conn = _world(tmp_path, {**AUTO, "deep": False})
    mods = {m["module"] for m in granted_modules(conn, cfg, PROG)}
    assert "xss_reflected" in mods and "ssti" in mods
    assert "idor" not in mods and "cmd_inject" not in mods   # deep off
    row = conn.execute("SELECT auto_granted FROM grants WHERE module='ssti'").fetchone()
    assert row["auto_granted"] == 1


def test_deep_enabled_grants_deep_modules(tmp_path):
    cfg, conn = _world(tmp_path, AUTO)
    mods = {m["module"] for m in granted_modules(conn, cfg, PROG)}
    assert {"idor", "cmd_inject", "nuclei_sweep", "blind_oast"} <= mods


def test_policy_lint_still_blocks_even_when_auto(tmp_path):
    cfg, conn = _world(tmp_path, AUTO,
                       policy="Do not run any timing based SQL attacks.")
    prog = {**PROG, "policy_text": "Do not run any timing based SQL attacks."}
    mods = {m["module"] for m in granted_modules(conn, cfg, prog)}
    assert "sqli_boolean" not in mods
    assert "xss_reflected" in mods          # others still flow


def test_risk_cap_still_bounds(tmp_path):
    cfg, conn = _world(tmp_path, AUTO)
    prog = {**PROG, "risk_cap": "passive"}
    assert granted_modules(conn, cfg, prog) == []


def test_missing_secret_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.delenv("HH_GRANT_SECRET")
    cfg, conn = _world(tmp_path, AUTO)
    assert granted_modules(conn, cfg, PROG) == []   # fail-closed, no exception


def test_auto_grant_logged_to_questions(tmp_path):
    cfg, conn = _world(tmp_path, AUTO)
    granted_modules(conn, cfg, PROG)
    body = (tmp_path / "out/QUESTIONS.md").read_text(encoding="utf-8")
    assert "auto_granted" in body and "revoke" in body


def test_grant_reused_not_recreated(tmp_path):
    cfg, conn = _world(tmp_path, AUTO)
    granted_modules(conn, cfg, PROG)
    n1 = conn.execute("SELECT COUNT(*) c FROM grants").fetchone()["c"]
    granted_modules(conn, cfg, PROG)
    n2 = conn.execute("SELECT COUNT(*) c FROM grants").fetchone()["c"]
    assert n1 == n2          # idempotent within TTL


def test_run_nightly_bumps_default_cap(tmp_path, monkeypatch):
    """auto_grant.risk_cap applies only to programs still on the untouched
    default; an operator-set cap is never overwritten."""
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    cfg, conn = _world(tmp_path, {**AUTO, "risk_cap": "high"})
    from hushhunt.pipeline import _apply_auto_cap
    prog = dict(conn.execute("SELECT * FROM programs").fetchone())
    assert _apply_auto_cap(cfg, prog)["risk_cap"] == "high"
    conn.execute("UPDATE programs SET risk_cap='low'")
    conn.commit()
    prog = dict(conn.execute("SELECT * FROM programs").fetchone())
    assert _apply_auto_cap(cfg, prog)["risk_cap"] == "low"
