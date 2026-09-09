from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
             "low": "note", "informational": "note", "info": "note"}


def export_sarif(conn: sqlite3.Connection, cfg) -> str:
    """SARIF 2.1.0 of live (non-dropped) findings — REDCELL port: platforms
    and IDEs ingest SARIF natively; our markdown reports stay human artifacts,
    this file is the machine one. Report stage+ verified+accepted included."""
    out_dir = Path(cfg.root) / "out" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    rules: dict[str, dict] = {}
    results = []
    rows = conn.execute(
        """SELECT f.*, s.check_id, s.asset, s.wstg FROM findings f
           JOIN signals s ON s.id = f.signal_id
           WHERE f.stage IN ('verified','reported','accepted')""").fetchall()
    for r in rows:
        detail = json.loads(r["detail_json"] or "{}")
        cid = r["check_id"]
        rules.setdefault(cid, {
            "id": cid,
            "shortDescription": {"text": detail.get("title", cid)},
            "helpUri": f"https://owasp.org/www-project-web-security-testing-guide/",
            "properties": {"tags": [r["wstg"]] if r["wstg"] else []},
        })
        results.append({
            "ruleId": cid,
            "level": SEV_LEVEL.get(detail.get("severity", "info"), "note"),
            "message": {"text": detail.get("title", cid)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": r["asset"]}}}],
            "properties": {"tags": [t for t in
                                    (detail.get("cwe"), detail.get("cvss"))
                                    if t]},
        })
    doc = {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "main/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "hushhunt", "version": "0.2",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }
    path = out_dir / "findings.sarif"
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return str(path)
