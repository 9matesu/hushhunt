from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import bump_weight, get_weights, set_stage

STATE_MAP = {
    "resolved": ("accepted", True),
    "triaged": ("accepted", True),          # accepted by triage, bounty pending
    "not-applicable": ("na", False),
    "informative": ("informative", False),
    "duplicate": ("duplicate", False),
    "no reply": ("pending", None),
}


def demoted_modules(conn) -> set[str]:
    """Modules currently auto-demoted (not expired): the pipeline refuses to
    run them, and the planner rejects proposals for them, until `undemote`
    or expiry."""
    now = datetime.now(timezone.utc).isoformat()
    return {r["module"] for r in conn.execute(
        "SELECT module FROM demoted WHERE until > ?", (now,))}


def undemote(conn, module: str) -> None:
    conn.execute("DELETE FROM demoted WHERE module=?", (module,))
    conn.commit()


def auto_demote(conn, cfg=None, precision_floor: float = 0.25,
                min_n: int = 4, days: int = 30) -> list[str]:
    """Self-improvement's brake: a check/module whose observed precision
    dropped below the floor with enough samples is silenced for `days`.
    One accepted outcome after demotion is the human's cue to `undemote` —
    the tool never re-enables its own noisy modules silently."""
    newly = []
    for row in conn.execute(
            "SELECT check_id, precision_ewma, n FROM weights WHERE n >= ?",
            (min_n,)):
        if row["precision_ewma"] < precision_floor:
            until = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            cur = conn.execute(
                """INSERT INTO demoted(module,until,reason) VALUES(?,?,?)
                   ON CONFLICT(module) DO UPDATE SET until=excluded.until,
                     reason=excluded.reason""",
                (row["check_id"], until,
                 f"precision {round(row['precision_ewma'], 2)} after n={row['n']}"))
            newly.append(row["check_id"])
    conn.commit()
    return newly


def record_outcome(conn, cfg, finding_id: int, check_id: str, state: str) -> float:
    """Manual/assisted learning loop: one bounty outcome nudges the check's
    precision EWMA and the finding lifecycle. Weights feed target scoring
    (select.py) AND the triage prompt (prompts.py) -> the tool gets better at
    hunting where it's accurate and quieter where it isn't."""
    if state not in STATE_MAP:
        raise ValueError(f"unknown state {state!r}; known: {sorted(STATE_MAP)}")
    outcome, accepted = STATE_MAP[state]
    row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        raise KeyError(f"finding {finding_id} not found")
    w = bump_weight(conn, check_id, accepted=bool(accepted))
    if accepted is None:
        return w
    set_stage(conn, finding_id, outcome, outcome=outcome)
    return w


def find_check_id(conn, finding_id: int) -> str:
    row = conn.execute(
        """SELECT s.check_id FROM findings f JOIN signals s ON s.id=f.signal_id
           WHERE f.id=?""", (finding_id,)).fetchone()
    return row["check_id"] if row else "unknown"


def propose_playbook_patch(conn, cfg, out_path: str | Path | None = None) -> str:
    """Grows the NA corpus + playbook as DATA, for human merge — the tool
    never rewrites its own rules silently (that's how it would learn to miss
    things). Writes out/playbook_patch.md and out/na_kb_proposed.json."""
    out = Path(out_path or Path(cfg.root) / "out")
    out.mkdir(parents=True, exist_ok=True)
    weights = get_weights(conn)
    counts = {r["check_id"]: dict(r) for r in conn.execute(
        "SELECT check_id, precision_ewma, n FROM weights")}
    worst = sorted(weights.items(), key=lambda kv: kv[1])[:5]
    recent_na = [dict(r) for r in conn.execute(
        """SELECT f.outcome, f.detail_json, s.check_id FROM findings f
           JOIN signals s ON s.id=f.signal_id
           WHERE f.stage IN ('na','dropped','informative')
           ORDER BY f.updated_at DESC LIMIT 10""")]
    md = ["# Proposed playbook patch (human review REQUIRED before merge)", ""]
    md.append("## Lowest-precision checks (consider disabling or gating)")
    for cid, w in worst:
        c = counts.get(cid, {})
        md.append(f"- `{cid}` precision={round(w,2)} n={c.get('n','?')}")
    md.append("")
    md.append("## Recent drops / NAs — candidate NA-KB entries")
    proposed = []
    for r in recent_na:
        md.append(f"- `{r['check_id']}`: {r['outcome']} {r['detail_json'] or ''}")
        try:
            detail = json.loads(r["detail_json"] or "{}")
        except ValueError:
            detail = {}
        if r["outcome"] and r["outcome"].startswith("NA-PATTERN") or \
                detail.get("reason", "").startswith("NA-PATTERN"):
            proposed.append({"id": f"NA-CAND-{len(proposed)+1}",
                             "pattern": r["check_id"], "check_ids": [r["check_id"]],
                             "regex": "", "why_rejected": detail.get("why", r["outcome"])})
    patch = out / "playbook_patch.md"
    patch.write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / "na_kb_proposed.json").write_text(json.dumps(proposed, indent=2),
                                             encoding="utf-8")
    return str(patch)
