from __future__ import annotations

import json
from pathlib import Path

from .db import set_stage


def push_finding(conn, cfg, finding: dict, program: dict) -> str:
    """The one human gate of the pipeline.

    mode=draft  : append to out/PENDING.md (human reviews, edits, submits).
    mode=auto   : additionally requires confidence >= 0.9 AND program safe
                  harbor (never 'none'); writes out/submit_payload.json for
                  the browser-assisted submission flow. Nothing is ever
                  silently POSTed to a platform in v1 (OQ-1: researcher-side
                  submission API is unverified — see docs/SAFETY.md).
    Returns the artifact path.
    """
    out_dir = Path(cfg.root) / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    mode = cfg["submit.mode"]
    detail = json.loads(finding.get("detail_json") or "{}")
    line = (f"- [{finding['id']}] {program['name']}: {detail.get('title', '?')} "
            f"-> {finding.get('report_path')}\n")

    if mode == "draft":
        pending = out_dir / "PENDING.md"
        if not pending.exists():
            pending.write_text("# Awaiting human review\n\n", encoding="utf-8")
        with pending.open("a", encoding="utf-8") as fh:
            fh.write(line)
        return str(pending)

    if mode == "auto":
        conf = finding.get("confidence") or 0
        if conf < 0.9:
            return "blocked:below_auto_threshold"
        if program.get("safe_harbor") == "none":
            return "blocked:no_safe_harbor"
        payload = {"platform": program.get("platform"),
                   "program_id": program.get("id"),
                   "program_url": program.get("url"),
                   "title": detail.get("title"),
                   "severity": detail.get("severity"),
                   "body_file": finding.get("report_path"),
                   "finding_id": finding["id"]}
        path = out_dir / f"submit_payload_{finding['id']}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        set_stage(conn, finding["id"], "reported",
                  outcome="queued_for_submission")
        return str(path)

    raise ValueError(f"unknown submit.mode {mode!r}")
