from __future__ import annotations

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Any
from hushhunt.scope import url_in_scope

# ponytail: locates BountyForge skill folder from standard Hermes paths
def find_bountyforge_dir() -> Path:
    candidates = [
        Path(os.environ.get("APPDATA", "")) / "hermes" / "skills" / "bountyforge",
        Path.home() / ".hermes" / "skills" / "bountyforge",
        Path.home() / "AppData" / "Local" / "hermes" / "skills" / "bountyforge",
    ]
    for c in candidates:
        if (c / "tools" / "hunt.py").is_file():
            return c
    raise FileNotFoundError("BountyForge skill not found in Hermes skills directories.")


def run_bountyforge_hunt(
    target_url: str,
    includes: list[str],
    excludes: list[str],
    cookie: str | None = None,
    bearer: str | None = None,
    auth_file: str | None = None,
    auth_file_a: str | None = None,
    auth_file_b: str | None = None,
    idor_only: bool = False,
    active: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    """Execute BountyForge's hunt engine strictly against in-scope target."""
    if not url_in_scope(target_url, includes, excludes):
        raise PermissionError(f"Target {target_url} is out of scope for this program.")

    bf_dir = find_bountyforge_dir()
    hunt_py = bf_dir / "tools" / "hunt.py"

    cmd = [sys.executable, str(hunt_py), "--target", target_url, "--json"]
    if cookie:
        cmd.extend(["--cookie", cookie])
    if bearer:
        cmd.extend(["--bearer", bearer])
    if auth_file:
        cmd.extend(["--auth-file", auth_file])
    if auth_file_a and auth_file_b:
        cmd.extend(["--auth-file-a", auth_file_a, "--auth-file-b", auth_file_b])
    if idor_only:
        cmd.append("--idor-only")
    if active:
        cmd.append("--active")

    proc = subprocess.run(
        cmd,
        cwd=str(bf_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    stdout = proc.stdout.strip()
    try:
        data = json.loads(stdout) if stdout else {}
    except Exception:
        data = {"raw_output": stdout, "findings": []}

    return data


def import_bountyforge_findings(
    conn: Any,
    program_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
) -> int:
    """Store BountyForge findings as signals/findings in HushHunt's database."""
    count = 0
    for item in findings:
        vuln_type = item.get("type", "BountyForge finding")
        severity = item.get("severity", "medium").lower()
        evidence = item.get("evidence", "")
        endpoint = item.get("endpoint", target_url)

        # ponytail: direct insert into signals, upgrades to full triage pipeline as needed
        conn.execute(
            """INSERT INTO signals (program_id, asset, check_id, severity_hint, payload_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                program_id,
                endpoint,
                f"bountyforge_{vuln_type.lower()}",
                severity,
                json.dumps({"source": "bountyforge", "evidence": evidence, "raw": item}),
            ),
        )
        count += 1
    return count
