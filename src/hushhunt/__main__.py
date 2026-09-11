from __future__ import annotations

import argparse
import sys

from .config import Config
from .pipeline import run_nightly


def _load_cfg(root: str):
    from pathlib import Path
    if (Path(root) / "config.yaml").exists():
        return Config.load(root)
    # bare root (tests, fresh checkouts): repo-default config, root overridden
    cfg = Config.load(Path(__file__).resolve().parents[2])
    cfg.root = Path(root)
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hushhunt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    nightly = sub.add_parser("run-nightly", help="full pipeline once")
    nightly.add_argument("--root", default=".")
    nightly.add_argument("--sim", action="store_true",
                         help="offline run against the built-in vulnapp (no network)")
    auto = sub.add_parser("run-autonomous",
                          help="AI-guided loop (9router) until quiet or --max-cycles")
    auto.add_argument("--root", default=".")
    auto.add_argument("--sim", action="store_true",
                      help="offline loop against the built-in vulnapp (no network, no cost)")
    auto.add_argument("--model", default=None,
                      help="override llm.model for this loop (e.g. ag/claude-sonnet-4-6)")
    auto.add_argument("--max-cycles", type=int, default=3,
                      help="stop after N full passes (default 3; quiet stops earlier)")
    learn = sub.add_parser("learn", help="record one human-observed outcome")
    learn.add_argument("--root", default=".")
    learn.add_argument("--outcome", required=True,
                       choices=["resolved", "not-applicable", "informative",
                                "duplicate"])
    learn.add_argument("--finding", type=int, required=True)
    status = sub.add_parser("status", help="summary incl. active posture")
    status.add_argument("--root", default=".")
    status.add_argument("--analytics", action="store_true",
                        help="show per-module yield, conversion, and precision metrics")
    dash = sub.add_parser("dashboard", help="local read-only live dashboard")
    dash.add_argument("--root", default=".")
    dash.add_argument("--port", type=int, default=8765)
    grant = sub.add_parser("grant", help="sign an operator grant (v2)")
    grant.add_argument("--root", default=".")
    grant.add_argument("--program", required=True)
    grant.add_argument("--module", required=True)
    grant.add_argument("--scope", default="probe", choices=["probe", "deep"])
    grant.add_argument("--hours", type=int, default=72)
    grant.add_argument("--max-requests", type=int, default=200)
    revoke = sub.add_parser("revoke", help="revoke a grant by id")
    revoke.add_argument("--root", default=".")
    revoke.add_argument("grant_id", type=int)
    und = sub.add_parser("undemote", help="manually re-enable a demoted module")
    und.add_argument("--root", default=".")
    und.add_argument("module")
    audit_cmd = sub.add_parser("local-audit", help="run defensive SSH or AD baseline audit")
    audit_cmd.add_argument("--sshd-config", help="path to sshd_config")
    audit_cmd.add_argument("--ad-policy", help="path to JSON AD policy dump")
    audit_cmd.add_argument("--scan-dir", help="directory path to scan for leaked secrets")
    audit_cmd.add_argument("--export-feed", action="store_true", help="export findings to out/hermes-feed/findings.json")
    bf_cmd = sub.add_parser("bountyforge", help="run BountyForge hunt against an in-scope target")
    bf_cmd.add_argument("--target", required=True, help="target URL (must be in scope of program)")
    bf_cmd.add_argument("--program", help="program ID to check scope against")
    bf_cmd.add_argument("--cookie", help="session cookie string")
    bf_cmd.add_argument("--bearer", help="bearer token")
    bf_cmd.add_argument("--auth-file", help="auth JSON file path")
    bf_cmd.add_argument("--auth-file-a", help="user A auth JSON file path (IDOR)")
    bf_cmd.add_argument("--auth-file-b", help="user B auth JSON file path (IDOR)")
    bf_cmd.add_argument("--idor-only", action="store_true", help="run only IDOR checks")
    bf_cmd.add_argument("--active", action="store_true", help="run active injection checks")
    bf_cmd.add_argument("--import-db", action="store_true", help="store results into DB signals table")
    reg = sub.add_parser("register", help="auto-provision disposable test accounts for a program")
    reg.add_argument("--root", default=".")
    reg.add_argument("--program", required=True, help="program ID (scope + policy gate)")
    reg.add_argument("--signup-url", required=True, help="signup endpoint (must be in scope)")
    reg.add_argument("--login-url", required=True, help="login endpoint (must be in scope)")
    reg.add_argument("--dual", action="store_true", help="provision acct_a AND acct_b (IDOR diffing)")
    args = ap.parse_args(argv)
    cfg = _load_cfg(getattr(args, "root", "."))
    if args.cmd == "run-autonomous":
        if getattr(args, "sim", False):
            from .sim import run_sim
            run_sim(cfg)
            return 0
        if getattr(args, "model", None):
            cfg._d["llm"]["model"] = args.model
        from .triage.llm import LlmClient
        llm = LlmClient(cfg)
        max_cycles = getattr(args, "max_cycles", 3)
        print(f"HushHunt Autonomous Suite [AI: 9router / {cfg['llm.model']}]")
        print(f"Starting loop (max {max_cycles} cycles, auto-grant enabled)...")
        from .db import open_db
        from .metaharness import append_loop_journal, export_hermes_findings
        for cycle in range(1, max_cycles + 1):
            print(f"\n--- CYCLE {cycle}/{max_cycles} ---")
            line = run_nightly(cfg, llm=llm)
            import re
            m = dict(re.findall(r"(\w+)=(\S+)", line))
            try:
                conn = open_db(cfg.root / "var" / "hushhunt.db")
                export_hermes_findings(conn, cfg.root / "out")
                append_loop_journal(cfg.root / "var", "cycle_complete", {"cycle": cycle, "metrics": m})
            except Exception:
                pass
            # Stop if no new signals or no actions were taken
            if int(m.get("signals", "0")) == 0 and int(m.get("active_reqs", "0")) == 0:
                print("Suite reached quiet state: no new signals to investigate.")
                break
        print("\nAutonomous scan completed. Review out/PENDING.md and out/reports/.")
        return 0
    if args.cmd == "run-nightly":
        if getattr(args, "sim", False):
            from .sim import run_sim
            run_sim(cfg)
        else:
            run_nightly(cfg)
        return 0
    if args.cmd == "learn":
        from .db import open_db
        from .learn import find_check_id, record_outcome
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        cid = find_check_id(conn, args.finding)
        w = record_outcome(conn, cfg, args.finding, cid, args.outcome)
        print(f"OK weight[{cid}]={w:.3f}")
        return 0
    if args.cmd == "status":
        from .db import get_weights, open_db
        from .grants import active_grant
        from .learn import demoted_modules
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        for stage, c in conn.execute(
                "SELECT stage, COUNT(*) c FROM findings GROUP BY stage"):
            print(f"{stage}: {c}")
        print("weights:", get_weights(conn))
        print("demoted:", demoted_modules(conn) or "-")
        print("grants:")
        for r in conn.execute("SELECT id,program_id,module,scope,expires_at,"
                              "max_requests FROM grants ORDER BY id"):
            print(f"  #{r['id']} {r['program_id']} {r['module']} "
                  f"({r['scope']}) expires {r['expires_at'][:19]} "
                  f"max {r['max_requests']}")
        if getattr(args, "analytics", False):
            from .analytics import compute_analytics, format_analytics
            print("analytics:")
            print(format_analytics(compute_analytics(conn)))
        return 0
    if args.cmd == "grant":
        from .db import open_db
        from .grants import create_grant
        from .policy_lint import allowed_module, lint_policy
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        row = conn.execute("SELECT policy_text, risk_cap FROM programs WHERE id=?",
                           (args.program,)).fetchone()
        if row is None:
            print(f"REFUSED: program {args.program} not synced")
            return 2
        blocked = lint_policy(row["policy_text"])
        if not allowed_module(blocked["blocked"], args.module):
            print(f"REFUSED: policy lint blocks {args.module}. matched lines:")
            for pat, line in blocked["flags"]:
                from .policy_lint import RULES
                for rx, mods in RULES:
                    if rx == pat and args.module in mods:
                        print(f"  - {line!r}")
            print("  The block stands unless the program truly allows it "
                  "(then edit RULES with a written reason).")
            return 2
        gid = create_grant(conn, args.program, args.module, args.scope,
                           args.hours, args.max_requests)
        print(f"GRANT #{gid} {args.program} {args.module} scope={args.scope} "
              f"ttl={args.hours}h max_requests={args.max_requests}")
        return 0
    if args.cmd == "revoke":
        from .db import open_db
        from .grants import revoke_grant
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        revoke_grant(conn, args.grant_id)
        print(f"REVOKED #{args.grant_id}")
        return 0
    if args.cmd == "dashboard":
        from .dashboard import run_server
        import pathlib
        root = pathlib.Path(args.root)
        db = str(root / "var" / "hushhunt.db")
        log = next((str(p) for n in ("paid_run.log", "night_run.log", "live_run.log")
                    if (p := root / "var" / n).exists()), None)
        srv, port = run_server(db, log, args.port)
        print(f"dashboard on http://127.0.0.1:{port}/ (db={db} log={log})")
        srv.serve_forever()
        return 0
    if args.cmd == "undemote":
        from .db import open_db
        from .learn import undemote
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        undemote(conn, args.module)
        print(f"UNDEMOTED {args.module}")
        return 0
    if args.cmd == "local-audit":
        from .local_audit import audit_ad_policy, audit_sshd_config
        import json
        import pathlib
        findings = []
        if getattr(args, "sshd_config", None):
            text = pathlib.Path(args.sshd_config).read_text(encoding="utf-8")
            findings.extend(audit_sshd_config(text))
        if getattr(args, "ad_policy", None):
            data = json.loads(pathlib.Path(args.ad_policy).read_text(encoding="utf-8"))
            findings.extend(audit_ad_policy(data))
        if getattr(args, "scan_dir", None):
            from .checks.file_analyzer import scan_directory
            for hit in scan_directory(pathlib.Path(args.scan_dir)):
                findings.append({
                    "id": hit["check_id"],
                    "severity": hit.get("severity", "medium"),
                    "issue": f"exposed secret in {hit['filename']}:{hit['line']} ({hit['match']})",
                })
        if getattr(args, "export_feed", False):
            from .db import open_db
            from .metaharness import export_hermes_findings
            conn = open_db(cfg.root / "var" / "hushhunt.db")
            out_file = export_hermes_findings(conn, cfg.root / "out")
            print(f"FEED-EXPORTED {out_file}")
        print(json.dumps({"findings_count": len(findings), "findings": findings}, indent=2))
        return 0 if not findings else 2
    if args.cmd == "bountyforge":
        import json as _bfjson
        from .adapters.bountyforge import run_bountyforge_hunt, import_bountyforge_findings
        from .db import open_db
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        includes: list[str] = []
        excludes: list[str] = []
        pid = getattr(args, "program", None)
        if pid:
            row = conn.execute("SELECT scope_json FROM programs WHERE id=?", (pid,)).fetchone()
            if row and row["scope_json"]:
                scope = _bfjson.loads(row["scope_json"])
                includes = scope.get("in_scope", scope.get("includes", []))
                excludes = scope.get("out_of_scope", scope.get("excludes", []))
        else:
            # No program specified: derive scope from DB programs (default-deny).
            for r in conn.execute("SELECT scope_json FROM programs"):
                if r["scope_json"]:
                    scope = _bfjson.loads(r["scope_json"])
                    includes.extend(scope.get("in_scope", scope.get("includes", [])))
                    excludes.extend(scope.get("out_of_scope", scope.get("excludes", [])))
        data = run_bountyforge_hunt(
            args.target,
            includes=includes,
            excludes=excludes,
            cookie=args.cookie,
            bearer=args.bearer,
            auth_file=args.auth_file,
            auth_file_a=args.auth_file_a,
            auth_file_b=args.auth_file_b,
            idor_only=args.idor_only,
            active=args.active,
        )
        findings = data.get("findings", [])
        if getattr(args, "import_db", False) and pid:
            n = import_bountyforge_findings(conn, pid, args.target, findings)
            conn.commit()
            print(f"IMPORTED {n}")
        print(_bfjson.dumps(data, indent=2)[:4000])
        return 0
    if args.cmd == "register":
        import json as _rjson
        from .registration import register_account, save_program_accounts
        from .mail_pool import DisposableMailbox
        from .db import open_db
        from .sessions import accounts_path
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        row = conn.execute("SELECT id, policy_text, scope_json FROM programs WHERE id=?",
                           (args.program,)).fetchone()
        if not row:
            print(f"UNKNOWN-PROGRAM {args.program}")
            return 1
        scope = _rjson.loads(row["scope_json"] or "{}")
        prog = {"id": row["id"], "policy_text": row["policy_text"] or "",
                "includes": scope.get("in_scope", scope.get("includes", [])),
                "excludes": scope.get("out_of_scope", scope.get("excludes", []))}
        labels = ["acct_a", "acct_b"] if getattr(args, "dual", False) else ["acct_a"]
        created = []
        for label in labels:
            acct = register_account(args.signup_url, args.login_url, prog,
                                    mailbox=DisposableMailbox(), account_label=label)
            created.append(acct)
            print(f"REGISTERED {label} user={acct['user']}")
        save_program_accounts(accounts_path(cfg), args.program, created)
        print(f"SAVED {len(created)} account(s) -> {accounts_path(cfg)}")
        return 0
    return 1


def _module_in_pat(pat: str, module: str) -> bool:
    """Heuristic: does this lint rule (by pattern id) cover the module?
    Mirrors policy_lint.RULES membership without importing internals logic
    twice — kept simple; the grant CLI re-checks authoritatively."""
    from .policy_lint import RULES
    for rx, mods in RULES:
        if rx == pat and module in mods:
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
