from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .adapters import REGISTRY
import hushhunt.adapters.hackerone  # noqa: F401  (registers)
import hushhunt.adapters.bugcrowd   # noqa: F401  (registers)
from .checks import CHECK_CATALOG, Ctx
import hushhunt.checks.headers     # noqa: F401  (registration side-effects)
import hushhunt.checks.tlsconfig   # noqa: F401
import hushhunt.checks.files       # noqa: F401
import hushhunt.checks.cors        # noqa: F401
import hushhunt.checks.jsmining    # noqa: F401
from .ctlogs import discover
from .db import add_signal, get_weights, open_db, set_stage
from .http import BudgetExceeded, HardenedClient, OutOfScope
from .learn import propose_playbook_patch
from .push import push_finding
from .report import render_report
from .scope import url_in_scope
from .select import pick_targets
from .triage.engine import triage_asset
from .triage.na_kb import NaKb
from .verify import verify_finding

MAX_ASSETS_PER_PROGRAM = 20


def _load(cfg) -> sqlite3.Connection:
    (Path(cfg.root) / "var").mkdir(parents=True, exist_ok=True)
    return open_db(Path(cfg.root) / "var" / "hushhunt.db")


def _seeds_path(cfg) -> Path:
    local = Path(cfg.root) / "seeds" / "na_kb.json"
    if local.exists():
        return local
    return Path(__file__).resolve().parents[2] / "seeds" / "na_kb.json"


def sync(cfg, conn, client_factory=None) -> int:
    """One missing platform credential must never kill the night."""
    total = 0
    for name, cls in REGISTRY.items():
        if not cfg.get(f"platforms.{name}.enabled", False):
            continue
        try:
            adapter = cls(client_factory=client_factory) if client_factory else cls()
            total += adapter.sync_programs(conn, cfg)
        except (RuntimeError, httpx.HTTPError) as e:
            print(f"SYNC-WARN {name}: {e}")
    return total


def _asset_urls(conn, program: dict) -> list[str]:
    urls: list[str] = []
    for row in conn.execute(
            "SELECT identifier FROM assets WHERE program_id=?", (program["id"],)):
        inc = row["identifier"]
        if inc.startswith("*."):
            continue  # apex comes from ct-log rows; wildcards aren't connectable
        if "://" in inc:
            urls.append(inc)
        else:
            urls.append(f"https://{inc}/")
    return list(dict.fromkeys(urls))


def probe_program(cfg, conn, program: dict, transport=None, ct_factory=None) -> int:
    """Baseline GET once per asset; all checks evaluated against the SAME
    response (fetch-once-evaluate-many). safe_harbor=none => passive-only
    checks. Returns #new signals stored."""
    hc = HardenedClient(conn, cfg, program, transport=transport)
    passive_only = program.get("safe_harbor") == "none"
    discover(conn, cfg, program, client_factory=ct_factory)
    urls = _asset_urls(conn, program)[:MAX_ASSETS_PER_PROGRAM]
    n = 0
    for url in urls:
        if not url_in_scope(url, program["includes"], program["excludes"]):
            continue
        try:
            resp = hc.get(url)
        except (OutOfScope, BudgetExceeded, httpx.HTTPError):
            continue
        ctx = Ctx(resp=resp, fetch=(None if passive_only else hc.get),
                  asset_url=url)
        for defn in CHECK_CATALOG.values():
            if defn.risk != "passive" and ctx.fetch is None:
                continue
            try:
                produced = defn.fn(ctx)
            except Exception:
                continue
            for sig in produced:
                ev = hc.evidence_by_url.get(sig.get("asset", url),
                                            hc.evidence_by_url.get(url, ""))
                if add_signal(conn, program_id=program["id"],
                              asset=sig.get("asset", url),
                              check_id=sig["check_id"],
                              wstg=CHECK_CATALOG[sig["check_id"]].wstg,
                              severity_hint=sig["severity_hint"],
                              payload_json=json.dumps(sig["payload"], sort_keys=True),
                              evidence_dir=ev) is not None:
                    n += 1
    return n


def _signal_rows_for(conn, finding: dict) -> list[dict]:
    ids = json.loads(finding.get("detail_json") or "{}").get("signal_ids") or \
        [finding["signal_id"]]
    rows = conn.execute(
        f"SELECT * FROM signals WHERE id IN ({','.join('?' * len(ids))})",
        tuple(ids)).fetchall()
    return [dict(r) for r in rows]


def triage_verify_report(cfg, conn, llm, program: dict, na_kb: NaKb,
                         live_fetch=None) -> tuple[int, int, int]:
    """(triaged, verified, reported) — the positive-only funnel."""
    signals = [dict(r) for r in conn.execute(
        """SELECT s.* FROM signals s LEFT JOIN findings f ON f.signal_id=s.id
           WHERE s.program_id=? AND f.id IS NULL""", (program["id"],))]
    if len(signals) < cfg["selection.min_signals_to_triage"]:
        return 0, 0, 0
    triaged_ids = triage_asset(conn, cfg, llm, program, signals, na_kb,
                               get_weights(conn))
    verified = reported = 0
    for fid in triaged_ids:
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        sigs = _signal_rows_for(conn, f)
        stage, outcome = verify_finding(conn, cfg, CHECK_CATALOG, f, sigs,
                                        live_fetch=live_fetch)
        if stage != "verified":
            set_stage(conn, fid, stage, outcome=outcome)
            continue
        set_stage(conn, conn.execute(
            "SELECT id FROM findings WHERE id=?", (fid,)).fetchone()["id"], "verified")
        verified += 1
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        render_report(conn, cfg, f, sigs, CHECK_CATALOG)
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        push_finding(conn, cfg, f, program)
        reported += 1
    return len(triaged_ids), verified, reported


def run_nightly(cfg, llm=None, client_factory=None, verify_fetch=None,
                transport=None, ct_factory=None) -> str:
    conn = _load(cfg)
    na_kb = NaKb.load(_seeds_path(cfg))
    programs = sync(cfg, conn, client_factory=client_factory)
    targets = pick_targets(conn, cfg, get_weights(conn))
    ok = failed = sig_n = verified_n = reports_n = 0
    for prog in targets:
        try:
            sig_n += probe_program(cfg, conn, prog, transport=transport,
                                   ct_factory=ct_factory)
            # one client for the whole verify pass keeps budget/rate accounting
            live = verify_fetch or HardenedClient(conn, cfg, prog,
                                                  transport=transport).get
            _, v, r = triage_verify_report(cfg, conn, llm, prog, na_kb,
                                           live_fetch=live)
            verified_n += v
            reports_n += r
            ok += 1
        except Exception as e:  # one poison program never kills the night
            failed += 1
            print(f"PROGRAM-FAIL {prog['id']}: {type(e).__name__}: {e}")
    try:
        propose_playbook_patch(conn, cfg)
    except Exception:
        pass
    reqs = conn.execute("SELECT COUNT(*) c FROM request_log").fetchone()["c"]
    line = (f"RUN {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
            f"ok={ok} failed={failed} programs_synced={programs} "
            f"signals={sig_n} verified={verified_n} reports={reports_n} "
            f"requests={reqs}")
    print(line)
    return line
