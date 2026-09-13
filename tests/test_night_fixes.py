import json
import httpx

from hushhunt.scope import scope_of
from hushhunt.mail_pool import DisposableMailbox, MAILTM_API


def test_scope_of_reads_raw_db_row():
    row = {"id": "h1:x", "scope_json": json.dumps(
        {"includes": ["*.arlo.com"], "excludes": ["investor.arlo.com"]})}
    inc, exc = scope_of(row)
    assert inc == ["*.arlo.com"] and exc == ["investor.arlo.com"]


def test_scope_of_prefers_normalized_stage():
    prog = {"includes": ["a.io"], "excludes": [],
            "scope_json": json.dumps({"includes": ["other.io"], "excludes": []})}
    assert scope_of(prog) == (["a.io"], [])


def test_mailbox_falls_back_to_mailtm(tmp_path, monkeypatch):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        host = req.url.host
        if host.endswith("1secmail.com"):
            return httpx.Response(403, text="blocked")
        if host == "api.guerrillamail.com":
            return httpx.Response(200, json={"email_addr": "", "sid_token": ""})
        if host == "api.mail.tm":
            calls.append(str(req.url))
            if req.url.path == "/domains":
                return httpx.Response(200, json={"hydra:member": [{"domain": "clean.dom"}]})
            if req.url.path == "/accounts":
                return httpx.Response(201, json={"address": "x@clean.dom"})
            if req.url.path == "/token":
                return httpx.Response(200, json={"token": "jwt-123"})
            if req.url.path == "/messages":
                return httpx.Response(200, json={"hydra:member": [
                    {"id": "m1", "subject": "confirm"}]})
            if req.url.path.startswith("/messages/"):
                return httpx.Response(200, json={"text": "",
                                    "html": ["<a href='https://site.example/confirm?t=1'>ok</a>"]})
        return httpx.Response(404)

    box = DisposableMailbox(client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert box.provider == "mailtm" and box.token == "jwt-123"
    assert box.check_messages()[0]["id"] == "m1"
    link = box.wait_for_link(["site.example"], timeout=2, interval=0.1)
    assert link == "https://site.example/confirm?t=1"


def test_run_nightly_pinned_program(tmp_path, monkeypatch):
    from hushhunt.pipeline import run_nightly
    from hushhunt.db import open_db, upsert_program
    import hushhunt.pipeline as pl

    cfgd = tmp_path / "config.yaml"
    cfgd.write_text(
        "llm:\n  base_url: x\n  model: m\n  temperature: 0\n  prices: {}\n"
        "limits:\n  rate_per_second_per_target: 100\n  daily_requests_per_program: 50\n"
        "  max_requests_per_asset: 10\n  request_timeout_seconds: 5\n"
        "  user_agent: ua\n  proxy_url: ''\n  active:\n"
        "    daily_requests_per_program: 50\n    burst_rate_per_second: 10\n"
        "oast:\n  enabled: false\n  server: x\n  poll_timeout_seconds: 1\n"
        "selection:\n  small_target_max_bounty: 1500\n  new_program_days: 540\n"
        "  max_targets_per_night: 30\n  min_signals_to_triage: 1\n"
        "triage:\n  min_confidence: 0.75\nsubmit:\n  mode: draft\n"
        "auto_grant:\n  enabled: false\n  deep: false\n  risk_cap: medium\n"
        "  ttl_hours: 24\n  max_requests: 150\n"
        "platforms: {}\n")
    (tmp_path / "seeds").mkdir()
    (tmp_path / "seeds" / "na_kb.json").write_text("[]")
    from hushhunt.config import Config
    cfg = Config.load(tmp_path)
    (cfg.root / "var").mkdir(parents=True, exist_ok=True)
    conn = open_db(cfg.root / "var" / "hushhunt.db")
    upsert_program(conn, {"id": "h1:pin", "platform": "hackerone", "name": "P",
                          "url": "", "safe_harbor": "none", "max_bounty": 0,
                          "avg_resolution_h": 0.0, "created_at_remote": None,
                          "policy_text": "",
                          "scope_json": json.dumps({"includes": ["t.invalid"],
                                                    "excludes": []})})
    seen: list[str] = []
    monkeypatch.setattr(pl, "probe_program",
                        lambda c, k, p, **kw: seen.append(p["id"]) or 0)
    run_nightly(cfg, client_factory=lambda **kw: None,
                ct_factory=lambda **kw: httpx.Client(
                    transport=httpx.MockTransport(lambda r: httpx.Response(404))),
                only="h1:pin")
    assert seen == ["h1:pin"]
