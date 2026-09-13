from __future__ import annotations

import json
from .. import CHECK_CATALOG, CheckDef, Ctx, register


@register("actuator_check", "WSTG-INFO-02", "passive")
def check_actuator(ctx: Ctx) -> list[dict]:
    """Detect publicly exposed Spring Boot Actuator endpoints and Git/env leakage.

    Uses ctx.fetch (HardenedClient.get, 1 extra req allowed per check).
    Never sends payloads, never guesses beyond the 3 canonical actuator paths.
    """
    fetch = getattr(ctx, "fetch", None)
    base = getattr(ctx, "asset_url", "") or ""
    if not fetch or not base:
        return []
    root = base.rstrip("/")

    out = []
    try:
        r = fetch(root + "/actuator")
    except Exception:
        return []
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, dict) and "_links" in data:
                links = list(data["_links"].keys())
                info_leak = None
                try:
                    ri = fetch(root + "/actuator/info")
                    if ri.status_code == 200:
                        di = ri.json()
                        if isinstance(di, dict) and ("git" in di or "build" in di):
                            info_leak = di
                except Exception:
                    pass
                payload = {"links": links}
                check_id = "actuator_index_exposed"
                if info_leak:
                    payload["info"] = info_leak
                    check_id = "actuator_git_leak"
                out.append({
                    "check_id": check_id,
                    "asset": root + "/actuator",
                    "severity_hint": "low",
                    "payload": payload,
                    "payload_json": json.dumps(payload),
                })
                return out
        except Exception:
            pass
    # index missed but /info directly exposed
    try:
        ri = fetch(root + "/actuator/info")
        if ri.status_code == 200:
            di = ri.json()
            if isinstance(di, dict) and ("git" in di or "build" in di):
                payload = {"info": di}
                out.append({
                    "check_id": "actuator_git_leak",
                    "asset": root + "/actuator/info",
                    "severity_hint": "low",
                    "payload": payload,
                    "payload_json": json.dumps(payload),
                })
    except Exception:
        pass
    return out


# The check emits two concrete signal IDs (index vs git leak) while the
# registered entry above is the runner. Pipeline + verifier look up signals
# by emitted ID, so alias both here — same WSTG, same passive risk, same fn
# for live re-confirm. Without this probe_program KeyErrors on a hit.
CHECK_CATALOG["actuator_index_exposed"] = CheckDef(
    "actuator_index_exposed", "WSTG-INFO-02", "passive", check_actuator)
CHECK_CATALOG["actuator_git_leak"] = CheckDef(
    "actuator_git_leak", "WSTG-INFO-02", "passive", check_actuator)
