from __future__ import annotations

import socket
from urllib.parse import urlparse
from . import Ctx, register

# Non-HTTP admin/management ports to detect for unintended exposure (CWE-200)
# ponytail: test 22 and 389 only; add 636/3389/445 if program scope explicitly includes infra blocks
PORTS = [
    (22, "ssh"),
    (389, "ldap"),
]


@register("exposed_services", "WSTG-INFO-02", "passive")
def check_exposed_services(ctx: Ctx) -> list[dict]:
    """Check if in-scope asset host has non-HTTP administrative ports (SSH 22, LDAP 389)
    open to the public internet. Non-intrusive: single TCP connect check, closed immediately.
    Never attempts authentication or sends payloads."""
    url = getattr(ctx, "asset_url", "") or (str(ctx.resp.request.url) if getattr(ctx, "resp", None) else "")
    if not url:
        return []

    host = urlparse(url).hostname
    if not host or host == "127.0.0.1" or host == "localhost":
        return []

    out = []
    for port, service in PORTS:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                out.append({
                    "check_id": "exposed_services",
                    "asset": f"{host}:{port}",
                    "severity_hint": "low",
                    "payload": {
                        "host": host,
                        "port": port,
                        "service": service,
                        "issue": f"unintended_{service}_exposure",
                    }
                })
        except (OSError, socket.timeout):
            continue

    return out
