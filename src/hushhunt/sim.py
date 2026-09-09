"""--sim: REDCELL's sim-mode pattern. A full offline nightly against the
built-in vulnerable mock app (tests/vulnapp.py): real pipeline, real gates,
zero network. Use it to demo, to smoke-test after edits, or to tune the
triage prompt without burning budget on real programs."""
from __future__ import annotations

import json
from pathlib import Path


def build_sim_world(cfg, conn):
    """Register the sim program + grants so every gate is genuinely exercised."""
    from .db import upsert_program
    from .grants import create_grant
    upsert_program(conn, {
        "id": "sim:1", "platform": "simulator", "name": "VulnApp (SIM)",
        "url": "https://github.com/OWASP/wstg", "safe_harbor": "all",
        "max_bounty": 500, "avg_resolution_h": 1.0,
        "created_at_remote": None,
        "policy_text": "Everything t.invalid is in scope.",
        "scope_json": json.dumps({"includes": ["t.invalid"], "excludes": []})})
    conn.execute("INSERT OR IGNORE INTO assets(program_id,asset_type,"
                 "identifier,origin) VALUES('sim:1','DOMAIN','t.invalid','sim')")
    conn.execute("UPDATE programs SET risk_cap='high' WHERE id='sim:1'")
    conn.commit()
    import os
    if not os.environ.get("HH_GRANT_SECRET"):
        os.environ["HH_GRANT_SECRET"] = "sim-not-secret"
    for module in ("xss_reflected", "ssti", "idor", "blind_oast"):
        create_grant(conn, "sim:1", module,
                     "deep" if module in ("idor", "blind_oast") else "probe",
                     24, 500)


def run_sim(cfg) -> str:
    import httpx

    vp = Path(__file__).resolve().parents[2] / "tests" / "vulnapp.py"
    if not vp.exists():
        # shipped installs may not carry tests/: load the sibling copy
        raise SystemExit("sim mode needs the repo checkout (tests/vulnapp.py)")
    import importlib.util
    spec = importlib.util.spec_from_file_location("vulnapp_sim", vp)
    va = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(va)

    from .db import get_weights, open_db
    from .oast import FakeOast
    from .pipeline import run_nightly
    from .triage.sim_llm import SimLlm

    (Path(cfg.root) / "var").mkdir(exist_ok=True)
    conn = open_db(Path(cfg.root) / "var" / "hushhunt.db")
    build_sim_world(cfg, conn)
    oast = FakeOast()
    return run_nightly(cfg, llm=SimLlm(), transport=va.transport(va.handler),
                       ct_factory=lambda **kw: httpx.Client(
                           transport=httpx.MockTransport(
                               lambda r: httpx.Response(200, json=[]))),
                       client_factory=lambda **kw: httpx.Client(
                           transport=httpx.MockTransport(
                               lambda r: httpx.Response(200, json={
                                   "data": [], "links": {"next": None}}))),
                       oast=oast)
