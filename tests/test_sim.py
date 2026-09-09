import re
from pathlib import Path

import pytest

CFG_YAML = """
llm: {base_url: "http://sim.invalid/v1", model: "sim", temperature: 0.0}
limits:
  rate_per_second_per_target: 10000
  daily_requests_per_program: 500
  max_requests_per_asset: 80
  request_timeout_seconds: 5
  user_agent: "hushhunt-simtest"
  active: {daily_requests_per_program: 400, burst_rate_per_second: 1000}
selection: {small_target_max_bounty: 1500, new_program_days: 540,
            max_targets_per_night: 6, min_signals_to_triage: 1}
triage: {min_confidence: 0.75}
submit: {mode: "draft"}
platforms: {hackerone: {enabled: true}, bugcrowd: {enabled: false}}
oast: {enabled: false}
"""


@pytest.fixture(autouse=True)
def no_tls(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))


def test_sim_nightly_finds_reports_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "sim-k")
    monkeypatch.delenv("HH_H1_USER", raising=False)   # sync warns, must not kill
    (tmp_path / "config.yaml").write_text(CFG_YAML, encoding="utf-8")
    from hushhunt.config import Config
    from hushhunt.sim import run_sim
    cfg = Config.load(tmp_path)
    line = run_sim(cfg)
    m = dict(re.findall(r"(\w+)=(\S+)", line))
    assert m["failed"] == "0"
    assert int(m["signals"]) >= 1
    assert int(m["verified"]) >= 1
    assert int(m["reports"]) >= 1
    # every recorded request hit ONLY t.invalid (sim scope) — the money-test
    from hushhunt.db import open_db
    conn = open_db(tmp_path / "var" / "hushhunt.db")
    for r in conn.execute("SELECT url FROM request_log"):
        assert "t.invalid" in r["url"], r["url"]
    # report + machine export both exist
    reports = list((tmp_path / "out/reports").glob("*.md"))
    assert reports and "## PoC Script" in reports[0].read_text(encoding="utf-8")
    sarif = tmp_path / "out/reports/findings.sarif"
    assert sarif.exists()
    assert json_loads(sarif)["runs"][0]["results"]
    # sim skipped blindly-noisy modules via QUESTIONS (oast disabled for real use)
    assert (tmp_path / "out/QUESTIONS.md").exists()


def json_loads(p):
    import json
    return json.loads(p.read_text(encoding="utf-8"))
