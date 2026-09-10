"""Differential hidden parameter miner.

Probes unlinked parameters (debug, test, redirect, admin, etc.) against
a baseline response, measuring length deltas, status transitions, or header
changes to identify undocumented inputs.
"""
from __future__ import annotations

from typing import Any

DEFAULT_CANDIDATES = [
    "debug", "test", "admin", "redirect", "url", "dest", "next",
    "callback", "jsonp", "view", "show", "load", "format"
]


def find_hidden_params(client: Any, base_url: str,
                       candidate_params: list[str] | None = None) -> list[dict]:
    candidates = candidate_params or DEFAULT_CANDIDATES
    try:
        baseline = client.get(base_url)
        base_status = baseline.status_code
        base_len = len(baseline.text)
    except Exception:
        return []

    found = []
    sep = "&" if "?" in base_url else "?"

    for param in candidates:
        val = "true" if param in ("debug", "test", "admin") else "https://attacker.invalid"
        probe_url = f"{base_url}{sep}{param}={val}"
        try:
            resp = client.get(probe_url)
            # Detect differential signals
            status_changed = resp.status_code != base_status
            len_delta = abs(len(resp.text) - base_len)
            location_present = "location" in resp.headers

            if status_changed or len_delta > 15 or location_present:
                found.append({
                    "param": param,
                    "status": resp.status_code,
                    "delta_len": len_delta,
                    "probe_url": probe_url,
                })
        except Exception:
            continue

    return found
