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
    sub.add_parser("status", help="summary of last run").add_argument("--root",
                                                                      default=".")
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
        conn = open_db(cfg.root / "var" / "hushhunt.db")
        for stage, c in conn.execute(
                "SELECT stage, COUNT(*) c FROM findings GROUP BY stage"):
            print(f"{stage}: {c}")
        print("weights:", get_weights(conn))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
