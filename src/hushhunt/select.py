from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone


def _age_days(iso: str | None) -> float:
    if not iso:
        return 1e9
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return 1e9
    return (datetime.now(timezone.utc) - dt).days


def target_score(program: dict, weights: dict[str, float], cfg) -> float:
    """Higher = better hunt. Small/young programs first; historical per-check
    precision (self-improvement) shifts expectation. No safe harbor is a
    heavy penalty: we may not actively probe them at all."""
    s = 0.0
    mb = program.get("max_bounty") or 0
    if mb and mb <= cfg["selection.small_target_max_bounty"]:
        s += 2.0
    if _age_days(program.get("created_at_remote")) <= cfg["selection.new_program_days"]:
        s += 1.5
    if program.get("safe_harbor") != "none":
        s += 0.5
    quality = (sum(weights.values()) / len(weights)) if weights else 0.5
    s += 1.0 * quality
    if program.get("safe_harbor") == "none":
        s -= 3.0
    return s


def _crowded_program_ids(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        """SELECT DISTINCT s.program_id FROM findings f
           JOIN signals s ON s.id = f.signal_id
           WHERE f.stage IN ('verified','reported')""")
    return {r["program_id"] for r in rows}


def pick_targets(conn: sqlite3.Connection, cfg, weights: dict[str, float],
                 k: int | None = None) -> list[dict]:
    """Top-k programs to hunt tonight, normalized for the probing stage."""
    k = k or cfg["selection.max_targets_per_night"]
    crowded = _crowded_program_ids(conn)
    scored: list[tuple[float, dict]] = []
    for row in conn.execute("SELECT * FROM programs").fetchall():
        p = dict(row)
        if p["id"] in crowded:
            continue
        scope = json.loads(p["scope_json"] or "{}")
        norm = {"id": p["id"], "name": p["name"], "url": p["url"],
                "platform": p["platform"], "safe_harbor": p["safe_harbor"],
                "max_bounty": p["max_bounty"],
                "created_at_remote": p["created_at_remote"],
                "policy_text": p["policy_text"],
                "includes": scope.get("includes", []),
                "excludes": scope.get("excludes", [])}
        scored.append((target_score(norm, weights, cfg), norm))
    scored.sort(key=lambda t: -t[0])
    return [p for _, p in scored[:k]]
