import json
import shutil
import subprocess

import pytest

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.grants import create_grant
from hushhunt.nuclei_runner import (available, build_command, parse_nuclei,
                                    run_nuclei)

FIXTURE_JSONL = "\n".join([
    json.dumps({"template-id": "CVE-2021-44228",
                "matched-at": "https://app.smallco.io/api",
                "info": {"name": "Log4Shell", "severity": "critical",
                         "classification": {"cvss-score": 10.0,
                                            "cwe-id": ["cwe-502"]}}}),
    json.dumps({"template-id": "missing-csp",
                "matched-at": "https://app.smallco.io/",
                "info": {"name": "CSP Missing", "severity": "info"}}),
    "not json at all",
])


def test_build_command_is_quiet_slow_and_safe():
    cmd = build_command(["https://a.io/"], server="https://a.io")
    s = " ".join(str(c) for c in cmd)
    assert "-rl 1" in s                      # our rate rule applied to the tool
    assert "-silent" in s
    assert "-no-interactsh" in s             # no third-party eavesdropping
    assert "-duc" in s                        # never upload-check (no writes)
    assert "-severity" in s                   # filtered template set


def test_parse_maps_cvss_cwe_severity():
    out = parse_nuclei(FIXTURE_JSONL, keep_severities={"critical", "high"})
    assert len(out) == 1                      # info-severity template dropped
    sig = out[0]
    assert sig["payload"]["template"] == "CVE-2021-44228"
    assert sig["severity_hint"] == "critical"
    assert sig["payload"]["cwe"] == "CWE-502"
    assert sig["payload"]["cvss"] == 10.0


def test_available_respects_binary():
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(shutil, "which", lambda n: None)
        assert available() is False
        mp.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
        assert available() is True


def _world(tmp_path, granted=True):
    (tmp_path / "config.yaml").write_text("triage: {}\n", encoding="utf-8")
    conn = open_db(tmp_path / "var.db")
    upsert_program(conn, {"id": "h1:9", "platform": "hackerone", "name": "P",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "",
                          "scope_json": '{"includes":["smallco.io"],"excludes":[]}'})
    conn.commit()
    if granted:
        import os
        os.environ["HH_GRANT_SECRET"] = "k"
        create_grant(conn, "h1:9", "nuclei_sweep", "deep", 24, 500)
    return Config.load(tmp_path), conn


def test_run_refuses_without_grant(tmp_path):
    cfg, conn = _world(tmp_path, granted=False)
    with pytest.raises(PermissionError):
        run_nuclei(cfg, conn, {"id": "h1:9", "name": "P",
                               "includes": ["smallco.io"], "excludes": []},
                   ["https://smallco.io/"])


def test_run_filters_urls_to_scope(tmp_path):
    cfg, conn = _world(tmp_path)
    calls = []
    import subprocess as sp

    class FakeP:
        stdout = FIXTURE_JSONL
        returncode = 0

    def fake_run(*a, **k):
        calls.append(a[0])
        return FakeP()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(shutil, "which", lambda n: "/x/" + n)
        mp.setattr(sp, "run", fake_run)
        sigs = run_nuclei(cfg, conn, {"id": "h1:9", "name": "P",
                                      "includes": ["smallco.io"],
                                      "excludes": []},
                          ["https://smallco.io/", "https://evil-not.io/"])
    urls = calls[0][calls[0].index("-u") + 1:]
    assert any("smallco.io" in u for u in urls)
    assert not any("evil-not.io" in u for u in urls)   # scope wall holds
    assert [s["check_id"] for s in sigs] == ["nuclei_sweep"]


def test_missing_binary_returns_empty_not_crash(tmp_path):
    cfg, conn = _world(tmp_path)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(shutil, "which", lambda n: None)
        out = run_nuclei(cfg, conn, {"id": "h1:9", "name": "P",
                                     "includes": ["smallco.io"], "excludes": []},
                         ["https://smallco.io/"])
    assert out == []
