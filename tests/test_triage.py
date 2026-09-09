import json

import pytest

from hushhunt.config import Config
from hushhunt.db import add_signal, open_db
from hushhunt.triage.engine import triage_asset
from hushhunt.triage.llm import FakeLlm, TriageContractError
from hushhunt.triage.na_kb import NaKb
from pathlib import Path

CFG = Config({"triage": {"min_confidence": 0.75}}, ".")
PROGRAM = {"id": "h1:1", "name": "SmallCo", "platform": "hackerone",
           "safe_harbor": "all", "policy_text": "scope: *.smallco.io"}
KB = NaKb.load(Path(__file__).parent.parent / "seeds" / "na_kb.json")


def _sig(conn, check_id="cors_misconfig", payload='{"issue":"reflected_arbitrary_origin"}'):
    sid = add_signal(conn, program_id="h1:1", asset="https://app.smallco.io",
                     check_id=check_id, wstg="WSTG-CLNT-07",
                     severity_hint="medium", payload_json=payload, evidence_dir="e1")
    return dict(id=sid, check_id=check_id, payload_json=payload,
                asset="https://app.smallco.io", severity_hint="medium",
                wstg="WSTG-CLNT-07")


def _stage_rows(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM findings")]


def test_accepted_finding_written(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn)
    reply = {"findings": [{"signal_ids": [s["id"]], "title": "CORS reflected origin",
                           "severity": "medium", "cvss": "CVSS:3.1/AV:N/AC:L",
                           "impact": "Any origin can read session data cross-origin.",
                           "confidence": 0.9, "reasoning": "echo verified",
                           "dedupe_key": "cors-app"}], "dismissed": []}
    ids = triage_asset(conn, CFG, FakeLlm([reply]), PROGRAM, [s], KB, {})
    assert len(ids) == 1
    row = _stage_rows(conn)[0]
    assert row["stage"] == "triaged" and row["confidence"] == 0.9


def test_below_min_confidence_dropped_not_triaged(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn)
    reply = {"findings": [{"signal_ids": [s["id"]], "title": "x", "confidence": 0.74}],
             "dismissed": []}
    ids = triage_asset(conn, CFG, FakeLlm([reply]), PROGRAM, [s], KB, {})
    assert ids == []
    assert _stage_rows(conn)[0]["stage"] == "dropped"


def test_na_kb_short_circuit_never_calls_llm(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn, check_id="passive_headers",
             payload='{"issue":"cookie_no_httponly","detail":"no HttpOnly"}')
    llm = FakeLlm([{"findings": [], "dismissed": []}])
    triage_asset(conn, CFG, llm, PROGRAM, [s], KB, {})
    assert llm.calls == []
    row = _stage_rows(conn)[0]
    assert row["stage"] == "dropped" and "NA-003" in row["outcome"]


def test_invented_signal_ids_are_dropped(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn)
    reply = {"findings": [{"signal_ids": [99999], "title": "ghost", "confidence": 0.99}],
             "dismissed": []}
    ids = triage_asset(conn, CFG, FakeLlm([reply]), PROGRAM, [s], KB, {})
    assert ids == []  # wrote nothing for the ghost finding


def test_contract_error_writes_nothing(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn)
    with pytest.raises(TriageContractError):
        triage_asset(conn, CFG, FakeLlm([["not", "a", "dict"]]), PROGRAM, [s], KB, {})
    assert _stage_rows(conn) == []


def test_prompt_contains_policy_and_weights(tmp_path):
    conn = open_db(tmp_path / "t.db")
    s = _sig(conn)
    llm = FakeLlm([{"findings": [], "dismissed": [{"signal_ids": [s["id"]],
                                                   "reason": "NA-PATTERN:custom"}]}])
    triage_asset(conn, CFG, llm, PROGRAM, [s], KB, {"cors_misconfig": 0.4})
    system, user = llm.calls[0]
    assert "HackerOne triager" in system
    assert "SmallCo" in user and "0.4" in user
    assert _stage_rows(conn)[0]["stage"] == "dropped"
