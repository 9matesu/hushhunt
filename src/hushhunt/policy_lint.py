from __future__ import annotations

import re

# Keyword lint is ADVISORY GRADE (belt), the operator-run `grant` CLI is the
# suspender: it re-runs lint and REFUSES blocked modules, printing the matched
# line. A grant can never out-rank policy. Rules are deliberately conservative
# to over-block rather than under-block; false-blocks annoy, false-allows
# damage accounts.
RULES: list[tuple[str, set[str]]] = [
    # blanket dos/stress bans -> anything bursty
    (r"\bstress[- ]test\w*\b|\bflood\w*\b|\bdenial of service\b"
     r"|(?:\bno\b|not allowed|do not|don'?t|prohibit\w*).{0,40}\bdos\b",
     {"sqli_boolean", "ssti", "graphql_probe", "blind_oast"}),
    # timing/sleep bans -> time-based oracle only
    (r"(?:do not|don'?t|not allowed|prohibit\w*|never|avoid|please refrain from)"
     r".{0,80}\b(?:timing|sleep(?:[- ]based)?)\b",
     {"sqli_boolean"}),
    # "we ignore self-XSS ..." -> persisted-state modules need victim chains
    (r"(?:ignore|out of scope|not accepted|will not (?:be )?pay\w*)\s*"
     r".{0,40}?self[- ]?xss",
     {"mass_assign", "idor"}),
    # must use own throwaway accounts (or no registration at all)
    (r"(?:may not|cannot|can'?t|not allowed|not permitted|do not|don'?t|\bno\b)"
     r".{0,40}(?:creat\w+|regist\w+).{0,25}account|account.{0,25}(?:creat|regist)",
     {"idor", "mass_assign", "jwt_misuse"}),
    # blind-oast bans
    (r"(?:\bno\b|not allowed|prohibit\w*|do not|don'?t).{0,30}"
     r"(?:ssrf|oast|interactsh|out.?of.?band|callback)",
     {"blind_oast"}),
]

_COMPILED = [(re.compile(rx, re.I), mods) for rx, mods in RULES]


def lint_policy(policy_text: str | None) -> dict:
    blocked: set[str] = set()
    flags: list[tuple[str, str]] = []
    for line in (policy_text or "").splitlines():
        for rx, mods in _COMPILED:
            if rx.search(line):
                blocked |= mods
                flags.append((rx.pattern, line.strip()[:80]))
    return {"blocked": blocked, "flags": flags}


def allowed_module(blocked: set[str], module: str) -> bool:
    return module not in blocked
