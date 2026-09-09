from __future__ import annotations

import json
import time

from .. import register, register_repro


@register("mass_assign", "WSTG-INPV-20", "high")
def check_mass_assign(ctx) -> list[dict]:
    """Grant 'deep', session REQUIRED, SELF-targeted only: the tester's own
    profile object gets an extra field ('hushhunt_pwn'). If the server
    persists fields the API schema never declares, that's mass-assignment.
    CLEANUP step is MANDATORY and runs in `finally`: the marker field is
    overwritten back to null via the same endpoint — no state left behind.
    This is the only module that writes; writes are limited to our own
    object, one field, plus immediate rollback."""
    sa = getattr(ctx, "session_a", None)
    url = getattr(ctx, "profile_url", None)
    if sa is None or not url:
        return []
    marker = {"hushhunt_pwn": "yes"}
    try:
        r = sa.post(url, json=marker)
        if r.status_code != 200:
            return []
        echo = sa.get(url)
        if echo.status_code == 200 and "hushhunt_pwn" in echo.text:
            return [{"check_id": "mass_assign", "asset": url,
                     "severity_hint": "medium",
                     "payload": {"field": "hushhunt_pwn", "cleaned_up": False}}]
        return []
    except Exception:
        return []
    finally:
        try:   # rollback must run even on error paths — leave nothing behind
            sa.post(url, json={"hushhunt_pwn": None})
        except Exception:
            pass


register_repro("mass_assign", lambda sig: [
    f"As the tester's own account, POST {sig['asset']} with an undeclared "
    "field hushhunt_pwn — it persists (see capture); declaring unknown fields "
    "in trusted APIs can let attackers set role/admin flags.",
    "Cleanup: field re-posted as null (second capture proves rollback).",
])
