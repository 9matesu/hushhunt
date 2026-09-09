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
import hushhunt.checks.headers       # noqa: F401  (registration side-effects)
import hushhunt.checks.tlsconfig     # noqa: F401
import hushhunt.checks.files         # noqa: F401
import hushhunt.checks.cors          # noqa: F401
import hushhunt.checks.jsmining      # noqa: F401
import hushhunt.checks.active.xss    # noqa: F401
import hushhunt.checks.active.domxss   # noqa: F401
import hushhunt.checks.active.sqli   # noqa: F401
import hushhunt.checks.active.ssti   # noqa: F401
import hushhunt.checks.active.idor   # noqa: F401
import hushhunt.checks.active.jwtchecks  # noqa: F401
import hushhunt.checks.active.redirect   # noqa: F401
import hushhunt.checks.active.graphql    # noqa: F401
import hushhunt.checks.active.blind      # noqa: F401
import hushhunt.checks.active.cmdinject  # noqa: F401
import hushhunt.checks.active.nuclei_check  # noqa: F401
import hushhunt.checks.active.massassign  # noqa: F401
from .checks.active import ACTIVE_MODULES
from .crawl import crawl
from .ctlogs import discover
from .db import add_signal, get_weights, open_db, set_stage
from .grants import active_grant, risk_allows
from .http import BudgetExceeded, HardenedClient, OutOfScope
from .learn import auto_demote, demoted_modules, propose_playbook_patch
from .oast import OastClient
from .operator import ask, drain_steer
from .planner import plan as plan_tests
from .policy_lint import allowed_module, lint_policy
from .push import push_finding
from .report import render_report
from .scope import url_in_scope
from .select import pick_targets
from .sessions import SessionBroker, SessionError, load_accounts
from .triage.engine import triage_asset
from .triage.na_kb import NaKb
from .verify import POC_REQUIRED, verify_finding

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


def _params_seen(conn, program_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT url, param, sample_url, sample_value FROM params_seen "
        "WHERE program_id=? ORDER BY rowid DESC LIMIT 200", (program_id,)).fetchall()
    return [dict(r) for r in rows]


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
            if defn.risk in ("medium", "high"):
                continue   # active modules run only via active_probe()
            try:
                produced = defn.fn(ctx)
            except Exception:
                continue
            n += _store_signals(conn, program, hc, url, produced)
    return n


def _store_signals(conn, program, hc, url, produced) -> int:
    n = 0
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


def _module_risk(module: str) -> str:
    defn = CHECK_CATALOG.get(module)
    return defn.risk if defn else "high"


def granted_modules(conn, cfg, program: dict) -> list[dict]:
    """ALL THREE gates must pass: risk_cap >= module risk, policy lint not
    blocking, unexpired in-headroom grant. Precedence: policy > grant > cap."""
    lint = lint_policy(program.get("policy_text", ""))
    dem = demoted_modules(conn)
    out = []
    for module, scope in ACTIVE_MODULES.items():
        if not risk_allows(program.get("risk_cap", "passive"), _module_risk(module)):
            continue
        if not allowed_module(lint["blocked"], module):
            continue
        if module in dem:
            continue
        g = active_grant(conn, program["id"], module, scope)
        if g is None:
            continue
        out.append({"module": module, "grant": g, "scope": scope})
    return out


def active_probe(cfg, conn, program: dict, transport=None,
                 session_factory=None, oast=None) -> int:
    """Active WSTG modules, ONLY for granted+linted+cap-passed modules.
    Session-based modules use broker accounts; graphql posts are grant-gated
    (HardenedClient.post). Returns #new active signals."""
    modules = granted_modules(conn, cfg, program)
    if not modules:
        return 0
    hc = HardenedClient(conn, cfg, program, transport=transport)
    crawl(cfg, conn, program, transport=transport)
    params = [tuple((p["sample_url"], p["param"], p["sample_value"]))
              for p in _params_seen(conn, program["id"]) if p["sample_url"]]
    n = 0
    first = _asset_urls(conn, program)[:1]
    if not first:
        return 0
    baseline = hc.get(first[0])
    ctx = Ctx(resp=baseline, fetch=hc.get, asset_url=first[0], params=params)
    ctx.post = hc.post
    names = {m["module"]: m["grant"]["id"] for m in modules}
    ctx.grant_id = next(iter(names.values()), None)
    js_signals = [dict(r) for r in conn.execute(
        "SELECT payload_json FROM signals WHERE program_id=? AND check_id='js_endpoints'",
        (program["id"],))]
    routes = []
    for s in js_signals:
        routes = json.loads(s["payload_json"]).get("routes", [])
    ctx.graphql_urls = [f"{first[0].rstrip('/')}{r}" for r in routes
                        if "graph" in r][:2]
    # session modules: broker with the operator's own throwaway accounts
    if "idor" in names or "mass_assign" in names:
        accts = load_accounts(cfg, program["id"]) if session_factory else []
        if len(accts) < 2:
            ask(cfg, program, "no_test_accounts",
                f"{program['id']}: idor/mass_assign granted but no usable "
                "session accounts (register 2 throwaway accounts in "
                "seeds/accounts.yaml or run without --sim)",
                ["register accounts", "revoke the deep grants"])
        else:
            broker = SessionBroker(program, accts, client_factory=session_factory)
            try:
                ctx.session_a = broker.session(accts[0]["id"])
                ctx.session_b = (broker.session(accts[1]["id"])
                                 if len(accts) > 1 else None)
            except (SessionError, RuntimeError, IndexError, KeyError):
                ctx.session_a = ctx.session_b = None
            ctx.profile_url = f"{first[0].rstrip('/')}/api/profile"
            ctx.owned_urls = _owned_from_session(conn, program, ctx)
            if "idor" in names and ctx.session_a and ctx.session_b:
                for sig in CHECK_CATALOG["idor"].fn(ctx):
                    n += _store_signals(conn, program, hc, first[0], [sig])
            if "mass_assign" in names and ctx.session_a:
                for sig in CHECK_CATALOG["mass_assign"].fn(ctx):
                    n += _store_signals(conn, program, hc, first[0], [sig])
    # GET-based active modules
    for module in ("xss_reflected", "sqli_error", "sqli_boolean", "ssti",
                   "open_redirect_chain"):
        if module in names:
            for sig in CHECK_CATALOG[module].fn(ctx):
                n += _store_signals(conn, program, hc, first[0], [sig])
    if "xss_dom" in names:
        for sig in CHECK_CATALOG["xss_dom"].fn(ctx):
            n += _store_signals(conn, program, hc, first[0], [sig])
    if "jwt_misuse" in names and getattr(ctx, "session_a", None) is not None:
        try:
            login = ctx.session_a.get(f"{first[0].rstrip('/')}/login")
            tok = login.headers.get("x-jwt") or login.cookies.get("jwt")
            if tok:
                ctx.own_jwt = tok
                ctx.jwt_api_url = f"{first[0].rstrip('/')}/api/whoami"
                for sig in CHECK_CATALOG["jwt_misuse"].fn(ctx):
                    n += _store_signals(conn, program, hc, first[0], [sig])
        except Exception:
            pass
    if "graphql_probe" in names and ctx.graphql_urls:
        try:
            for sig in CHECK_CATALOG["graphql_probe"].fn(ctx):
                n += _store_signals(conn, program, hc, first[0], [sig])
        except Exception:
            pass
    if "blind_oast" in names or "cmd_inject" in names:
        if oast is None and not cfg.get("oast.enabled", False):
            ask(cfg, program, "oast_disabled",
                f"{program['id']}: deep OAST modules granted but oast.enabled"
                " is false — cannot prove blind bugs",
                ["enable oast (self-host interactsh)", "revoke those grants"])
        else:
            ctx.oast = oast or OastClient(cfg)
            for module in ("blind_oast", "cmd_inject"):
                if module in names:
                    try:
                        for sig in CHECK_CATALOG[module].fn(ctx):
                            n += _store_signals(conn, program, hc, first[0], [sig])
                    except Exception:
                        pass
    if "nuclei_sweep" in names:
        try:
            from .nuclei_runner import run_nuclei
            urls = list(dict.fromkeys(p[0] for p in params[:20])) or first
            for sig in run_nuclei(cfg, conn, program, urls):
                n += _store_signals(conn, program, hc, first[0], [sig])
        except PermissionError:
            pass     # grant vanished mid-run: correct fail-closed behavior
        except Exception as e:
            print(f"NUCLEI-WARN {type(e).__name__}: {e}")
    return n


def _owned_from_session(conn, program, ctx) -> list[tuple]:
    """Object URLs account A legitimately saw (crawl of A's session isn't
    done in v2; use params_seen paths under /api/ as candidate own-objects,
    plus any A-confirmed 200s). Conservative: only ids present in
    params_seen sample values matching [0-9a-f]{1,24}."""
    import re
    owned = []
    for p in _params_seen(conn, program["id"])[:50]:
        m = re.fullmatch(r"([0-9a-f]{1,24})", str(p["sample_value"] or ""))
        if m and p["url"].startswith("/api/"):
            owned.append((f"{p['sample_url'].split('?')[0].rsplit('/', 1)[0]}/"
                          f"{m.group(1)}", ""))
    return owned[:3]


def _signal_rows_for(conn, finding: dict) -> list[dict]:
    ids = json.loads(finding.get("detail_json") or "{}").get("signal_ids") or \
        [finding["signal_id"]]
    rows = conn.execute(
        f"SELECT * FROM signals WHERE id IN ({','.join('?' * len(ids))})",
        tuple(ids)).fetchall()
    return [dict(r) for r in rows]


def triage_verify_report(cfg, conn, llm, program: dict, na_kb: NaKb,
                         live_fetch=None, poc_client=None,
                         live_recheck=None, focus=None) -> tuple[int, int, int]:
    """(triaged, verified, reported) — the positive-only funnel."""
    signals = [dict(r) for r in conn.execute(
        """SELECT s.* FROM signals s LEFT JOIN findings f ON f.signal_id=s.id
           WHERE s.program_id=? AND f.id IS NULL""", (program["id"],))]
    if len(signals) < cfg["selection.min_signals_to_triage"]:
        return 0, 0, 0
    granted = [m["module"] for m in
               (granted_modules(conn, cfg, program) if llm else [])]
    triaged_ids = triage_asset(conn, cfg, llm, program, signals, na_kb,
                               get_weights(conn), granted=granted, focus=focus)
    verified = reported = 0
    for fid in triaged_ids:
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        sigs = _signal_rows_for(conn, f)
        # PoC path: synthesize + run once BEFORE verify (for requires_poc)
        detail = json.loads(f.get("detail_json") or "{}")
        if detail.get("requires_poc") and poc_client is not None and llm is not None:
            from .poc import PoCContractError, run_poc, synthesize_poc
            try:
                code = synthesize_poc(cfg, llm, f, sigs)
                ok = run_poc(code, poc_client)
                conn.execute(
                    "INSERT INTO poc_scripts(finding_id,code,ok_last_run,ran_at) "
                    "VALUES(?,?,?,?)",
                    (fid, code, int(ok),
                     datetime.now(timezone.utc).isoformat()))
                conn.commit()
            except PoCContractError:
                pass
        stage, outcome = verify_finding(conn, cfg, CHECK_CATALOG, f, sigs,
                                        live_fetch=live_fetch,
                                        live_recheck=live_recheck)
        if stage != "verified":
            set_stage(conn, fid, stage, outcome=outcome)
            continue
        set_stage(conn, fid, "verified")
        verified += 1
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        render_report(conn, cfg, f, sigs, CHECK_CATALOG)
        f = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
        f["id"] = fid
        push_finding(conn, cfg, f, program)
        reported += 1
    return len(triaged_ids), verified, reported


def _poc_client(conn, cfg, program, transport):
    hc = HardenedClient(conn, cfg, program, transport=transport)

    class _C:
        def fetch(self, url, headers=None):
            return hc.get(url, headers=headers)
    return _C()


def run_nightly(cfg, llm=None, client_factory=None, verify_fetch=None,
                transport=None, ct_factory=None, session_factory=None,
                oast=None) -> str:
    conn = _load(cfg)
    na_kb = NaKb.load(_seeds_path(cfg))
    programs = sync(cfg, conn, client_factory=client_factory)
    targets = pick_targets(conn, cfg, get_weights(conn))
    steer = drain_steer(cfg)          # operator input between runs (REDCELL port)
    if steer["skip"]:
        targets = [t for t in targets if t["id"] not in steer["skip"]]
    ok = failed = sig_n = verified_n = reports_n = active_n = 0
    for prog in targets:
        if steer["stop"]:
            print("RUN-ABORT per operator steer (stop)")
            break
        try:
            db_prog = dict(conn.execute(
                "SELECT * FROM programs WHERE id=?", (prog["id"],)).fetchone())
            prog["risk_cap"] = db_prog.get("risk_cap", "passive")
            prog["policy_text"] = db_prog.get("policy_text", "")
            sig_n += probe_program(cfg, conn, prog, transport=transport,
                                   ct_factory=ct_factory)
            try:
                a = active_probe(cfg, conn, prog, transport=transport,
                                 session_factory=session_factory, oast=oast)
                active_n += a
                sig_n += a
            except (BudgetExceeded, OutOfScope):
                pass
            live = verify_fetch or HardenedClient(conn, cfg, prog,
                                                  transport=transport).get
            _, v, r = triage_verify_report(cfg, conn, llm, prog, na_kb,
                                           live_fetch=live,
                                           poc_client=_poc_client(conn, cfg, prog,
                                                                  transport),
                                           focus=steer["focus"])
            verified_n += v
            reports_n += r
            ok += 1
        except Exception as e:  # one poison program never kills the night
            failed += 1
            print(f"PROGRAM-FAIL {prog['id']}: {type(e).__name__}: {e}")
    try:
        auto_demote(conn, cfg)
        propose_playbook_patch(conn, cfg)
        from .sarif import export_sarif
        export_sarif(conn, cfg)
    except Exception:
        pass
    reqs = conn.execute("SELECT COUNT(*) c FROM request_log").fetchone()["c"]
    usage = getattr(llm, "usage", None)
    if usage:
        (Path(cfg.root) / "var").mkdir(exist_ok=True)
        (Path(cfg.root) / "var" / "llm_cost.json").write_text(
            json.dumps(usage), encoding="utf-8")
        cost_str = f" llm_calls={usage['calls']} llm_cost_usd={round(usage['cost_usd'], 4)}"
    else:
        cost_str = ""
    line = (f"RUN {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
            f"ok={ok} failed={failed} programs_synced={programs} "
            f"signals={sig_n} active_reqs={active_n} verified={verified_n} "
            f"reports={reports_n} requests={reqs}{cost_str}")
    print(line)
    return line
