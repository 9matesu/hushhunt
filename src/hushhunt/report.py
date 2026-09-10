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


def _curl_one_liner(signals: list[dict]) -> str:
    """Derive a copy-paste repro command from the FIRST captured request file
    (001_req.http), redacted exactly as stored — the report never invents."""
    for s in signals:
        d = Path(s.get("evidence_dir") or "")
        if not d.is_dir():
            continue
        reqs = sorted(d.glob("*_req.http"))
        if not reqs:
            continue
        first = reqs[0].read_text(encoding="utf-8", errors="replace").splitlines()[0]
        parts = first.split()
        if len(parts) < 2:
            continue
        method, url = parts[0], parts[1]
        flags = f"-X {method} " if method != "GET" else ""
        return f"curl {flags}'{url}'"
    return ""


def render_report(conn, cfg, finding: dict, signals: list[dict], catalog) -> str:
    """finding: row dict with detail_json holding the triage decision.
    Writes out/reports/<pid>-<fid>-<slug>.md, flips stage to 'reported'.
    Idempotent on dedupe_key: re-rendering the same vuln returns the
    existing path (one bounty per vulnerability)."""
    from .checks.cwe import CWE_MAP
    detail = json.loads(finding["detail_json"] or "{}")
    first = signals[0] if signals else {}
    cwe = detail.get("cwe") or CWE_MAP.get(first.get("check_id", ""), "")
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

    poc_rows = conn.execute(
        "SELECT code FROM poc_scripts WHERE finding_id=? AND ok_last_run=1",
        (finding["id"],)).fetchall()
    poc_script = poc_rows[0]["code"] if poc_rows else ""

    env = Environment(loader=FileSystemLoader(_template_dirs(cfg)),
                      autoescape=False, keep_trailing_newline=True)
    cid = first.get("check_id", "")
    body = env.get_template("report.md.j2").render(
        title=detail.get("title", "Untitled finding"),
        severity=detail.get("severity", "unknown"),
        cvss=detail.get("cvss") or get_cvss_for_check(cid),
        summary=detail.get("reasoning", detail.get("title", "")),
        impact=detail.get("impact") or get_impact_for_check(cid),
        steps=steps,
        evidence=_evidence_texts(signals),
        poc_script=poc_script,
        curl=_curl_one_liner(signals),
        remediation=_remediation(first.get("check_id", "")),
        refs=[WSTG_BASE, cfg.get("program_url") or first.get("asset", "")],
    )
    pid = _safe((first.get("program_id") or f"f{finding['id']}").replace(":", "_"))
    path = out_dir / f"{pid}-{finding['id']}-{dedupe}.md"
    path.write_text(body, encoding="utf-8")
    set_stage(conn, finding["id"], "reported", report_path=str(path))
    return str(path)


_CVSS_MAP = {
    "cmd_inject": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",       # 10.0
    "sqli_error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",       # 9.1
    "sqli_boolean": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 9.1
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",             # 10.0
    "blind_oast": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",       # 9.3
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",             # 8.1
    "jwt_misuse": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",       # 9.1
    "mass_assign": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",      # 6.5
    "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",    # 6.1
    "xss_dom": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",          # 6.1
    "open_redirect_chain": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", # 4.7
    "graphql_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",    # 5.3
    "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",   # 6.5
    "exposed_files": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",    # 7.5
    "js_secret_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # 7.5
    "nuclei_sweep": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "passive_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0
    "version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3
    "tls_config": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",       # 5.9
}

_IMPACT_MAP = {
    "cmd_inject": "An unauthenticated remote attacker can execute arbitrary operating system commands with the privileges of the web service user, potentially compromising the host, internal networks, and sensitive data stores.",
    "sqli_error": "An attacker can manipulate backend SQL queries to extract sensitive database contents, bypass authentication mechanisms, or alter database records.",
    "sqli_boolean": "An attacker can extract complete database schema and confidential data bit-by-bit via inference attacks without triggering overt database error displays.",
    "ssti": "Server-Side Template Injection allows remote attackers to execute arbitrary code within the template engine context, frequently leading to complete host takeover.",
    "blind_oast": "Server-Side Request Forgery allows an attacker to induce the backend server to make unconstrained outbound network requests, accessing cloud metadata endpoints (e.g., 169.254.169.254) or internal services.",
    "idor": "Insecure Direct Object Reference enables horizontal privilege escalation, allowing an authenticated user to view or modify confidential resources belonging to other tenants.",
    "jwt_misuse": "Flaws in JWT signature verification (e.g. 'none' algorithm, key confusion, or unverified claims) permit attackers to forge tokens and impersonate arbitrary privileged accounts.",
    "mass_assign": "Unfiltered request parameters allow attackers to bind sensitive domain model fields (such as 'is_admin', 'role', or 'account_balance') during record creation or update.",
    "xss_reflected": "An attacker can execute arbitrary JavaScript in the context of the victim's authenticated browser session, leading to session hijacking, credential theft, or unauthorized actions performed on behalf of the victim.",
    "xss_dom": "Client-side script execution enables theft of sensitive DOM-stored tokens (localStorage, sessionStorage) and manipulation of the application's interface.",
    "open_redirect_chain": "Attackers can redirect unsuspecting victims to phishing domains or leverage the redirect in OAuth token harvesting flows.",
    "graphql_probe": "Full introspection exposure reveals private schema definitions, hidden queries, mutations, and internal database object relations.",
    "cors_misconfig": "Overly permissive CORS headers (e.g., reflection of arbitrary Origin with Access-Control-Allow-Credentials: true) allow malicious third-party websites to extract authenticated user data via cross-origin requests.",
    "exposed_files": "Public exposure of backup archives, configuration files, or VCS metadata (.git) reveals internal architecture, credentials, and source code.",
    "js_secret_leak": "Hardcoded API keys, bearer tokens, or internal service credentials discovered in client JavaScript bundles allow unauthorized access to connected cloud resources.",
    "nuclei_sweep": "Verified known CVE exposure or high-severity template match allowing remote exploitation.",
    "passive_headers": "Absence of hardening headers weakens browser defense against clickjacking, MIME-confusion attacks, and protocol downgrade.",
    "version_disclosure": "Software version exposure aids targeted exploit selection by remote attackers.",
    "tls_config": "Weak cipher suites or outdated TLS protocols expose client-server communication to passive eavesdropping or active man-in-the-middle decryption.",
}

_REMEDIATION = {
    "cmd_inject": "Avoid invoking operating system shells. If execution is unavoidable, use parameterized APIs with strict argument arrays and validate inputs against an allowlist.",
    "sqli_error": "Use parameterized queries (prepared statements) or ORM abstraction for all database operations. Never concatenate untrusted user input into SQL statements.",
    "sqli_boolean": "Ensure all SQL operations use parameterized queries and object-relational mapping libraries that separate SQL code from user-supplied parameters.",
    "ssti": "Never pass unvalidated user input directly into template engines. Use logic-less templates or enforce strict sandbox configurations.",
    "blind_oast": "Implement strict URL and hostname allowlists for outbound requests. Block requests to internal RFC1918 subnets and cloud metadata services (169.254.169.254).",
    "idor": "Implement robust server-side authorization checks verifying that the requesting user owns or has permission to access the requested object ID before returning it.",
    "jwt_misuse": "Enforce strong asymmetric signature verification (e.g., RS256/ES256), reject 'none' algorithm tokens, and validate 'aud', 'iss', and 'exp' claims strictly.",
    "mass_assign": "Implement explicit parameter allowlisting (Data Transfer Objects / strong parameters) ensuring sensitive fields cannot be bound from request bodies.",
    "xss_reflected": "Apply context-aware output encoding (HTML, JavaScript, attribute context) and implement a robust Content Security Policy (CSP).",
    "xss_dom": "Sanitize inputs before passing them to execution sinks (innerHTML, eval, document.write) using trusted libraries such as DOMPurify.",
    "open_redirect_chain": "Validate redirect URLs against a strict whitelist of relative paths or trusted domains, or use an index-based redirection table.",
    "graphql_probe": "Disable GraphQL schema introspection in production environments and enforce query depth/complexity limits.",
    "cors_misconfig": "Do not reflect arbitrary Origin values; allowlist exact origins server-side and disable credentials on wildcard.",
    "exposed_files": "Remove the exposed file from the web root / revoke access; if it ever contained secrets, rotate them immediately.",
    "js_secret_leak": "Rotate the exposed credential and remove it from client-side bundles; serve secrets only from authenticated APIs.",
    "passive_headers": "Add the missing security headers (CSP, HSTS, cookie flags) per the OWASP Secure Headers Project.",
    "version_disclosure": "Suppress product/version tokens from Server/X-Powered-By headers.",
    "tls_config": "Disable deprecated TLS versions; renew/replace the certificate with a valid chain.",
    "nuclei_sweep": "Apply vendor security patches or update vulnerable dependencies to the latest supported version.",
}


def get_cvss_for_check(check_id: str) -> str:
    return _CVSS_MAP.get(check_id, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


def get_impact_for_check(check_id: str) -> str:
    return _IMPACT_MAP.get(check_id, "Demonstrated by captured evidence.")


def get_remediation_for_check(check_id: str) -> str:
    return _REMEDIATION.get(check_id, "See reproduction steps; apply defense-in-depth per OWASP guidance.")


def _remediation(check_id: str) -> str:
    return get_remediation_for_check(check_id)

