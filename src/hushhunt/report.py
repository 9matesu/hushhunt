from __future__ import annotations

import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .db import set_stage

WSTG_BASE = "https://owasp.org/www-project-web-security-testing-guide/"
_UNSAFE = re.compile(r'[^A-Za-z0-9._-]+')


def _template_dirs(cfg) -> list[str]:
    """templates/ ships with the repo (parent of src/); cfg.root may be a
    workspace dir (tests), so include the package-relative template dir."""
    pkg_root = Path(__file__).resolve().parents[2]   # .../hushhunt (repo root)
    dirs = [str(pkg_root / "templates")]
    local = str(Path(cfg.root) / "templates")
    if local not in dirs:
        dirs.append(local)
    return dirs


def _safe(name: str) -> str:
    return _UNSAFE.sub("-", name)[:80]


def _evidence_texts(signals: list[dict], cap: int = 4096) -> list[str]:
    """Full request+response pair per signal, capped — the triager needs the
    raw transaction, but reports must stay lean."""
    out = []
    for s in signals:
        d = Path(s.get("evidence_dir") or "")
        if not d.is_dir():
            continue
        for req in sorted(d.glob("*_req.http")):
            resp = req.with_name(req.name.replace("_req.", "_resp."))
            text = req.read_text(encoding="utf-8", errors="replace")
            if resp.exists():
                text += "\n---\n" + resp.read_text(encoding="utf-8", errors="replace")
            out.append(text[:cap])
    return out


def render_report(conn, cfg, finding: dict, signals: list[dict], catalog) -> str:
    """finding: row dict with detail_json holding the triage decision.
    Writes out/reports/<pid>-<fid>-<slug>.md, flips stage to 'reported'.
    Idempotent on dedupe_key: re-rendering the same vuln returns the
    existing path (one bounty per vulnerability)."""
    detail = json.loads(finding["detail_json"] or "{}")
    dedupe = _safe(detail.get("dedupe_key") or f"f{finding['id']}")
    out_dir = Path(cfg.root) / "out/reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    existing = list(out_dir.glob(f"*-{dedupe}.md"))
    if existing:
        return str(existing[0])

    first = signals[0] if signals else {}
    check = catalog.get(first.get("check_id", ""))
    steps: list[str] = []
    for s in signals:
        c = catalog.get(s["check_id"])
        if c and c.repro_steps:
            try:
                sig = {**s, "payload": json.loads(s["payload_json"])}
                steps.extend(c.repro_steps(sig))
            except Exception:
                steps.append(f"Reproduce the passive request captured for {s['check_id']}.")
    steps = list(dict.fromkeys(steps)) or ["Follow the captured PoC requests below."]

    env = Environment(loader=FileSystemLoader(_template_dirs(cfg)),
                      autoescape=False, keep_trailing_newline=True)
    body = env.get_template("report.md.j2").render(
        title=detail.get("title", "Untitled finding"),
        severity=detail.get("severity", "unknown"),
        cvss=detail.get("cvss", ""),
        summary=detail.get("reasoning", detail.get("title", "")),
        impact=detail.get("impact", ""),
        steps=steps,
        evidence=_evidence_texts(signals),
        remediation=_remediation(first.get("check_id", "")),
        refs=[WSTG_BASE, cfg.get("program_url") or first.get("asset", "")],
    )
    pid = _safe((first.get("program_id") or f"f{finding['id']}").replace(":", "_"))
    path = out_dir / f"{pid}-{finding['id']}-{dedupe}.md"
    path.write_text(body, encoding="utf-8")
    set_stage(conn, finding["id"], "reported", report_path=str(path))
    return str(path)


_REMEDIATION = {
    "cors_misconfig": "Do not reflect arbitrary Origin values; allowlist exact origins server-side and disable credentials on wildcard.",
    "exposed_files": "Remove the exposed file from the web root / revoke access; if it ever contained secrets, rotate them immediately.",
    "js_secret_leak": "Rotate the exposed credential and remove it from client-side bundles; serve secrets only from authenticated APIs.",
    "passive_headers": "Add the missing security headers (CSP, HSTS, cookie flags) per the OWASP Secure Headers Project.",
    "version_disclosure": "Suppress product/version tokens from Server/X-Powered-By headers.",
    "tls_config": "Disable deprecated TLS versions; renew/replace the certificate with a valid chain.",
}


def _remediation(check_id: str) -> str:
    return _REMEDIATION.get(check_id, "See reproduction steps; apply defense-in-depth per OWASP guidance.")
