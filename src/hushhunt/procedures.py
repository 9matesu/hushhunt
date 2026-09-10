from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_procedure(conn: sqlite3.Connection, module: str, target_pattern: str,
                     param: str, payload_template: str, notes: str = "") -> None:
    """Record a successful test procedure. Repeats increment success_count
    so future planner prompts rank proven paths higher (maximum efficiency)."""
    row = conn.execute(
        "SELECT id, success_count FROM procedures WHERE topic=? AND target_pattern=? "
        "AND param=? AND payload_template=?",
        (module, target_pattern, param, payload_template)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO procedures(topic, target_pattern, param, payload_template,"
            " success_count, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (module, target_pattern, param, payload_template, 1, notes,
             _now(), _now()))
    else:
        conn.execute(
            "UPDATE procedures SET success_count=success_count+1, notes=?, updated_at=? "
            "WHERE id=?", (notes or None, _now(), row["id"]))
    conn.commit()


def get_procedures_for_target(conn: sqlite3.Connection, url: str,
                              limit: int = 5) -> list[dict]:
    """Retrieve procedures whose target_pattern matches the URL host.
    Ordered by success_count DESC so the most proven paths come first."""
    try:
        host = urlparse(url).hostname or url
    except Exception:
        host = url
    rows = conn.execute(
        "SELECT topic AS module, target_pattern, param, payload_template,"
        " success_count, notes FROM procedures ORDER BY success_count DESC"
    ).fetchall()
    out = []
    for r in rows:
        pat = (r["target_pattern"] or "").lstrip("*.")
        if pat and pat in host:
            out.append(dict(r))
        if len(out) >= limit:
            break
    return out


def format_procedures_for_prompt(procs: list[dict]) -> str:
    """Compact procedural memory block injected into the planner prompt."""
    if not procs:
        return "No proven procedures recorded for this target yet."
    lines = ["PROVEN PROCEDURES (use first, ranked by success count):"]
    for p in procs:
        lines.append(
            f"- {p['module']} on *{p['target_pattern']} param={p['param']!r} "
            f"template={p['payload_template']!r} (successes={p['success_count']}"
            f"{'; '+p['notes'] if p.get('notes') else ''})")
    return "\n".join(lines)
