from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

RISK_ORDER = {"off": -1, "passive": 0, "low": 1, "medium": 2, "high": 3}
SCOPE_ORDER = {"probe": 0, "deep": 1}


def _sig(program_id: str, module: str, expires_at: str) -> str:
    key = os.environ.get("HH_GRANT_SECRET", "")
    if not key:
        raise RuntimeError("HH_GRANT_SECRET must be set to sign grants")
    return hmac.new(key.encode(), f"{program_id}|{module}|{expires_at}".encode(),
                    hashlib.sha256).hexdigest()


def create_grant(conn, program_id: str, module: str, scope: str,
                 ttl_hours: int, max_requests: int, auto: bool = False) -> int:
    if scope not in SCOPE_ORDER:
        raise ValueError(f"unknown scope {scope!r}")
    expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    cur = conn.execute(
        """INSERT INTO grants(program_id,module,scope,max_requests,expires_at,
             signed,auto_granted) VALUES(?,?,?,?,?,?,?)""",
        (program_id, module, scope, max_requests, expires,
         _sig(program_id, module, expires), int(auto)))
    conn.commit()
    return cur.lastrowid


def ensure_auto_grant(conn, program_id: str, module: str, scope: str,
                      auto: dict) -> bool:
    """Auto-grant mode: mint the grant the operator would have typed, with
    the same expiry/budget/HMAC machinery — but only if none is already
    active (idempotent) and HH_GRANT_SECRET exists (fail-closed otherwise).
    This NEVER bypasses policy-lint/risk_cap/demotion: those checks happen in
    granted_modules() before this is ever called."""
    if active_grant(conn, program_id, module, scope) is not None:
        return False
    try:
        create_grant(conn, program_id, module, scope,
                     int(auto.get("ttl_hours", 24)),
                     int(auto.get("max_requests", 150)), auto=True)
    except RuntimeError:
        return False
    return True


def active_grant(conn, program_id: str, module: str,
                 scope_needed: str = "probe", now=None) -> dict | None:
    """A module may run only if: a grant exists for it, is unexpired, has
    scope >= what the module needs, and has request headroom left. The grant
    is an upper bound, never a requirement — absence simply means 'off'."""
    now = (now or (lambda: datetime.now(timezone.utc)))()
    best = None
    for g in conn.execute(
            "SELECT * FROM grants WHERE program_id=? AND module=? "
            "ORDER BY expires_at DESC", (program_id, module)):
        try:
            if datetime.fromisoformat(g["expires_at"]) < now:
                continue
        except ValueError:
            continue
        if SCOPE_ORDER[scope_needed] > SCOPE_ORDER.get(g["scope"], -1):
            continue  # scope insufficient
        used = conn.execute(
            "SELECT COUNT(*) c FROM request_log WHERE program_id=? AND kind='active'",
            (program_id,)).fetchone()["c"]
        if used >= g["max_requests"]:
            continue  # headroom spent
        best = dict(g)
        break
    return best


def risk_allows(risk_cap: str, module_risk: str) -> bool:
    """Outer bound the operator sets per program. A grant cannot out-rank the
    cap: cap=passive means no active module ever runs, grant or not."""
    return RISK_ORDER.get(module_risk, 99) <= RISK_ORDER.get(risk_cap, -1)


def revoke_grant(conn, grant_id: int) -> None:
    conn.execute("DELETE FROM grants WHERE id=?", (grant_id,))
    conn.commit()
