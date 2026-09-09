"""Operator interaction channels ported from REDCELL's steer/questions pattern:

- questions: when the pipeline SKIPS a granted module for a human reason
  (no test accounts registered, OAST disabled, cap too low, missing binary),
  it writes a decision request to out/QUESTIONS.md instead of staying silent.
  Silent skips are how autonomous tools rot.
- steer: the operator drops lines into var/steer.txt; the nightly drains them
  between programs. 'stop' aborts the run, 'skip:<program_id>' drops one
  target, anything else is injected as focus text into triage/planner
  prompts. Cheap, file-based, no server needed (REDCELL has Redis; we have
  SQLite + a text file — same capability shape for a solo hunter).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def ask(cfg, program: dict, topic: str, detail: str, options: list[str]) -> None:
    out = Path(cfg.root) / "out"
    out.mkdir(parents=True, exist_ok=True)
    q = out / "QUESTIONS.md"
    if not q.exists():
        q.write_text("# Operator questions (answer by editing steer.txt)\n\n",
                     encoding="utf-8")
    with q.open("a", encoding="utf-8") as fh:
        fh.write(f"## {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
                 f"{program.get('id', '?')} — {topic}\n"
                 f"{detail}\n"
                 f"Options: {' | '.join(options)}\n"
                 f"Steer reply: put `answer:{topic}:<option>` in var/steer.txt\n\n")


def drain_steer(cfg) -> dict:
    """Returns {'stop': bool, 'skip': set[str], 'focus': list[str]} and
    truncates the file (one-shot semantics like REDCELL's drain_steer)."""
    p = Path(cfg.root) / "var" / "steer.txt"
    result = {"stop": False, "skip": set(), "focus": []}
    if not p.exists():
        return result
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("", encoding="utf-8")
    for line in lines:
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if low == "stop":
            result["stop"] = True
        elif low.startswith("skip:"):
            result["skip"].add(low.split(":", 1)[1].strip())
        else:
            result["focus"].append(s[:400])
    return result
