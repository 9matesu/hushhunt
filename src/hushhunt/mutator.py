"""Context-aware payload mutator.

Analyzes reflection context (HTML attribute, script string, tag body, JSON)
and uses heuristic ladders (or 9router LLM) to generate the minimal, exact
escape sequence instead of blind static fuzzing.
"""
from __future__ import annotations

import json
import re

_ATTR_RX = re.compile(r'<[^>]+\b[a-zA-Z0-9_-]+=["\'][^"\']*{token}[^"\']*["\']', re.I)
_SCRIPT_RX = re.compile(r'<script[^>]*>.*?(?:var|let|const|["\']).*?{token}.*?</script>', re.I | re.S)


def analyze_reflection_context(body: str, token: str) -> str:
    """Classify the syntax context where the marker is reflected."""
    if not body or not token or token not in body:
        return "none"
    if re.search(r'<script[^>]*>[\s\S]*?' + re.escape(token) + r'[\s\S]*?</script>', body, re.I):
        return "script_string"
    if re.search(r'<[^>]+\b[a-zA-Z0-9_-]+=["\'][^"\']*' + re.escape(token) + r'[^"\']*["\']', body, re.I):
        return "html_attribute"
    return "html_body"


def mutate_payload_for_context(context_type: str, token: str,
                               llm=None) -> str:
    """Generate context-specific escape sequence."""
    if llm is not None:
        sys = ("You are an expert XSS and injection payload researcher. Given a reflection "
               "syntax context, generate a single minimal, benign inert probe payload. "
               "Output ONLY JSON: {\"payload\": \"...\"}")
        usr = json.dumps({"context": context_type, "token": token})
        try:
            res = llm.complete_json(sys, usr)
            p = res.get("payload")
            if p and token in p:
                return str(p)
        except Exception:
            pass

    # Deterministic fallback ladder per context
    if context_type == "html_attribute":
        return f'">{token}"<'
    elif context_type == "script_string":
        return f"'-{token}-'"
    return f"<x>{token}</x>"
