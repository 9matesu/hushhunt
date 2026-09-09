from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from . import Ctx, register


@register("tls_config", "WSTG-CRYP-01", "passive")
def check_tls(ctx: Ctx) -> list[dict]:
    """Single TLS handshake to the asset's own host:443 (host comes from the
    already-scope-gated asset row). Never retries; unreachable = no signal."""
    url = str(ctx.resp.request.url)
    if not url.startswith("https://"):
        return []
    host = httpx_host(url)
    out: list[dict] = []
    try:
        ctx_ssl = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        out.append(_sig(url, "cert_verify_failed", str(e)[:200], "medium"))
        return out
    except (OSError, socket.timeout, ssl.SSLError):
        return []
    if version in ("TLSv1", "TLSv1.1"):
        out.append(_sig(url, "weak_tls_version", version, "medium"))
    try:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 14:
            out.append(_sig(url, "cert_expiring", f"{days_left} days left", "low"))
    except (KeyError, ValueError):
        pass
    return out


def httpx_host(url: str) -> str:
    import httpx
    return str(httpx.URL(url).host)


def _sig(asset, issue, detail, sev):
    return {"check_id": "tls_config", "asset": asset, "severity_hint": sev,
            "payload": {"issue": issue, "detail": detail}}
