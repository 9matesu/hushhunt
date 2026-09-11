from __future__ import annotations

import re
from pathlib import Path

# ponytail: simple regex search; add AST/tree-sitter when false-positive rate on comments exceeds 10%
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("ad_connection_string", re.compile(r"LDAP://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[a-zA-Z0-9_=\-,]+)?", re.I)),
    ("password_assignment", re.compile(r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]", re.I)),
    ("bearer_token", re.compile(r"bearer\s+[a-zA-Z0-9\.\-_~+/]+=*", re.I)),
]


def scan_file_content(content: str, filename: str = "") -> list[dict]:
    """Detect exposed credentials, keys, and AD connection strings in file text."""
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for check_id, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if m:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                findings.append({
                    "check_id": f"secret:{check_id}",
                    "filename": filename,
                    "line": lineno,
                    "match": m.group(0)[:30] + "...",
                    "snippet": snippet,
                    "severity": "high" if "private_key" in check_id or "ad_" in check_id else "medium"
                })
    return findings


def scan_directory(root_path: Path, max_files: int = 500) -> list[dict]:
    """Scan local directory for exposed secrets, skipping VCS and virtualenvs."""
    results = []
    scanned = 0
    for p in root_path.rglob("*"):
        if scanned >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in p.parts for part in (".git", "node_modules", ".venv", "__pycache__", "dist")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            matches = scan_file_content(text, filename=str(p))
            results.extend(matches)
            scanned += 1
        except OSError:
            continue
    return results
