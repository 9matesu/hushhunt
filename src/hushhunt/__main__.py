from __future__ import annotations

import argparse
import sys

from .config import Config
from .pipeline import run_nightly


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hushhunt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    nightly = sub.add_parser("run-nightly", help="full pipeline once")
    nightly.add_argument("--root", default=".")
    learn = sub.add_parser("learn", help="record one human-observed outcome")
    learn.add_argument("--root", default=".")
    learn.add_argument("--outcome", required=True,
                       choices=["resolved", "not-applicable", "informative",
                                "duplicate"])
    learn.add_argument("--finding", type=int, required=True)
    status = sub.add_parser("status", help="summary incl. active posture")
    status.add_argument("--root", default=".")
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
    args = ap.parse_args(argv)
    cfg = Config.load(args.root)
    if args.cmd == "run-nightly":
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
    if args.cmd == "undemote":
        from .db import open_db
        from .learn import undemote
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        undemote(conn, args.module)
        print(f"UNDEMOTED {args.module}")
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
