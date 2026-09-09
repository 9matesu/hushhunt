from __future__ import annotations

import re

"""Destructive-command denylist (pattern ported from REDCELL's engine/scope.py):
even though hushhunt PoC scripts have no shell builtins (AST sandbox blocks
os/subprocess), any text emitted inside a payload or PoC must never contain a
system-destroying command — a triager copy-pasting it should not brick a box.
Enforced as a belt on top of the sandbox: validate every poc script AND every
injected payload string."""

_DESTRUCTIVE = [
    re.compile(r"\bmkfs(\.\w+)?\b", re.I),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/(sd|nvme|vd|hd)", re.I),
    re.compile(r">\s*/dev/(sd|nvme|vd|hd)\w+", re.I),
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.I),  # fork bomb
    re.compile(r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b", re.I),
    re.compile(r"\bchmod\s+-R\s+0?00\s+/(?:\s|$)", re.I),
    re.compile(r"\b(wipefs|shred)\b[^\n]*/dev/", re.I),
]

_RM = re.compile(r"\brm\b((?:\s+\S+)+)\s+(\S.*)?", re.I)
_WIPE_TARGETS = {"/", "/*", "~", "$HOME", "/etc", "/var", "/usr", "/bin",
                 "/sbin", "/boot", "/lib", "/lib64", "/root", "/home", "/opt",
                 "/sys", "/proc", "/dev", "/srv"}


def _dangerous_rm(text: str) -> bool:
    for m in _RM.finditer(text):
        toks = (m.group(1) or "").split() + (m.group(2) or "").split()
        flags = "".join(t for t in toks if t.startswith("-"))
        if not (re.search(r"-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r", flags, re.I)):
            continue
        for tok in toks:
            if tok.startswith("-"):
                continue
            # strip code punctuation/quotes so targets embedded in script
            # strings ("rm -rf /')") are caught, not just shell tokens
            clean = tok.strip("()'\" ").rstrip("/") or "/"
            if clean in _WIPE_TARGETS:
                return True
    return False


def is_destructive(text: str) -> bool:
    t = text or ""
    return _dangerous_rm(t) or any(p.search(t) for p in _DESTRUCTIVE)
