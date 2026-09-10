from __future__ import annotations

import sqlite3


def compute_analytics(conn: sqlite3.Connection) -> dict:
    """Aggregate ROI, request-to-signal conversion rates, and precision curves."""
    total_requests = conn.execute("SELECT COUNT(*) c FROM request_log").fetchone()["c"]
    total_signals = conn.execute("SELECT COUNT(*) c FROM signals").fetchone()["c"]
    total_verified = conn.execute(
        "SELECT COUNT(*) c FROM findings WHERE stage='verified' OR stage='reported'"
    ).fetchone()["c"]

    yield_by_check: dict[str, dict] = {}
    for r in conn.execute(
            "SELECT check_id, COUNT(*) n FROM signals GROUP BY check_id"):
        cid = r["check_id"]
        verified = conn.execute(
            """SELECT COUNT(*) c FROM findings f
               JOIN signals s ON s.id = f.signal_id
               WHERE s.check_id=? AND (f.stage='verified' OR f.stage='reported')""",
            (cid,)).fetchone()["c"]
        yield_by_check[cid] = {
            "signals": r["n"],
            "verified": verified,
            "yield": round(verified / r["n"], 4) if r["n"] else 0.0,
        }

    precision_avg = None
    row = conn.execute(
        "SELECT AVG(precision_ewma) a FROM weights").fetchone()
    if row and row["a"] is not None:
        precision_avg = round(row["a"], 4)

    return {
        "total_requests": total_requests,
        "total_signals": total_signals,
        "total_verified": total_verified,
        "yield_by_check": yield_by_check,
        "precision_avg": precision_avg,
    }


def format_analytics(stats: dict) -> str:
    lines = [
        f"requests={stats['total_requests']} signals={stats['total_signals']} "
        f"verified={stats['total_verified']} "
        f"precision_avg={stats.get('precision_avg') or '-'}",
    ]
    for cid, y in sorted(stats["yield_by_check"].items(),
                         key=lambda kv: kv[1]["yield"], reverse=True):
        lines.append(
            f"  {cid}: signals={y['signals']} verified={y['verified']} "
            f"yield={y['yield']}")
    return "\n".join(lines)
