from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

# ponytail: write flat json / jsonl to disk; Hermes reads directly from path.


def export_hermes_findings(conn, out_dir: Path, min_confidence: float = 0.5) -> Path:
    """Export triaged/verified findings to out/hermes-feed/findings.json."""
    feed_dir = out_dir / "hermes-feed"
    feed_dir.mkdir(parents=True, exist_ok=True)
    rows = conn.execute(
        """SELECT f.id, f.signal_id, f.stage, f.confidence, f.report_path, f.outcome, f.detail_json, f.updated_at,
                  s.program_id, s.asset, s.check_id, s.severity_hint
           FROM findings f
           LEFT JOIN signals s ON s.id = f.signal_id
           WHERE f.confidence >= ?
           ORDER BY f.id DESC""", (min_confidence,)
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d.get("detail_json") or "{}")
        except Exception:
            d["detail"] = {}
        items.append(d)
    out_file = feed_dir / "findings.json"
    out_file.write_text(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "findings": items
    }, indent=2), encoding="utf-8")
    return out_file


def append_loop_journal(var_dir: Path, entry_type: str, data: dict) -> None:
    """Append continuous decision trace to var/metaharness_loop.jsonl."""
    var_dir.mkdir(parents=True, exist_ok=True)
    journal_path = var_dir / "metaharness_loop.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": entry_type,
        "payload": data
    }
    with journal_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
