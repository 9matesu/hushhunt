"""External nuclei runner — REDCELL port (engine/webscan.py), but gated hard.

Nuclei is loud and noisy, so v1 banned it; here it is a DEEP-grant-only,
scope-filtered, severity-filtered, rate-limited sweep whose output goes
through our OWN positive gates (signal -> triage -> PoC/verify), never
straight to a report. Honest budget gap: nuclei traffic is NOT accounted in
request_log (subprocess); the grant's max_requests is the only bound, so
--rl 1 (1 req/s) and a per-run wall-clock timeout keep worst case sane.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .grants import active_grant
from .scope import url_in_scope

MODULE = "nuclei_sweep"
KEEP_SEVERITIES = {"critical", "high"}     # low-noise filter: known-CVEs only


def available() -> bool:
    return shutil.which("nuclei") is not None


def build_command(urls: list[str], server: str) -> list[str]:
    cmd = ["nuclei", "-silent", "-jsonl", "-nc", "-no-interactsh", "-duc",
           "-rl", "1", "-timeout", "5", "-retention-days", "1",
           "-severity", ",".join(sorted(KEEP_SEVERITIES))]
    if server:
        cmd += ["-H", f"X-Hushhunt-Run: {server}"]
    cmd += ["-u"] + list(urls)
    return cmd


def parse_nuclei(jsonl_text: str, keep_severities=KEEP_SEVERITIES) -> list[dict]:
    out: list[dict] = []
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        sev = (info.get("severity") or "info").lower()
        if sev not in keep_severities:
            continue
        cls = info.get("classification") or {}
        cwes = cls.get("cwe-id") or []
        out.append({
            "check_id": MODULE,
            "asset": obj.get("matched-at") or "",
            "severity_hint": sev,
            "payload": {"template": obj.get("template-id") or info.get("name")
                        or "nuclei-hit",
                        "cwe": (cwes[0].upper().replace("CWE-CWE-", "CWE-")
                                if cwes else None),
                        "cvss": cls.get("cvss-score"),
                        "source": "nuclei"},
        })
    return out


def run_nuclei(cfg, conn, program: dict, urls: list[str],
               timeout_s: int = 600) -> list[dict]:
    """Deep grant only (checked here, not delegated); input URLs re-filtered
    through scope; results returned as raw signals for the normal funnel."""
    grant = active_grant(conn, program["id"], MODULE, "deep")
    if grant is None:
        raise PermissionError("nuclei_sweep requires an active deep grant")
    if not available():
        print("NUCLEI-WARN binary not installed; skipping")
        return []
    scoped = [u for u in urls if url_in_scope(u, program["includes"],
                                              program["excludes"])]
    if not scoped:
        return []
    r = subprocess.run(build_command(scoped, program["id"]),
                       capture_output=True, text=True, timeout=timeout_s)
    if r.returncode != 0 and not r.stdout:
        print(f"NUCLEI-WARN exit={r.returncode} {r.stderr[:200]}")
        return []
    return parse_nuclei(r.stdout)
