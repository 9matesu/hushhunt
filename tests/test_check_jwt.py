import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.jwtchecks import check_jwt, forge_hs256, forge_none_alg
import hushhunt.checks.active.jwtchecks  # registers
from tests.vulnapp import JWT, handler, safe_handler

API = "https://t.invalid/api/whoami"


def _ctx(h, token=JWT):
    seen = []

    def fetch(url, headers=None):
        seen.append((str(url), (headers or {}).get("Authorization", "")))
        req = httpx.Request("GET", url, headers=headers or {})
        return httpx.Client(transport=httpx.MockTransport(h)).send(req)

    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", API)),
              fetch=fetch)
    ctx.own_jwt = token
    ctx.jwt_api_url = API
    return ctx, seen


def test_forgers_are_pure_local():
    import base64, json
    none_tok = forge_none_alg(JWT)
    hdr, claims, sig = none_tok.split(".")
    assert json.loads(base64.urlsafe_b64decode(hdr + "=="))["alg"] == "none"
    assert sig == ""                       # unsigned
    hs = forge_hs256(JWT, b"hush")
    assert hs.count(".") == 2 and hs != JWT  # re-signed copy, still 3 parts


def test_vulnerable_app_flags_alg_none():
    ctx, seen = _ctx(handler)
    out = check_jwt(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["issue"] == "alg_none"
    assert out[0]["severity_hint"] == "high"
    assert len(seen) <= 2          # replays capped (never a wordlist storm)
    assert all(auth != f"Bearer {JWT}" for _, auth in seen)  # own token never replayed


def test_safe_app_zero_signals():
    ctx, seen = _ctx(safe_handler)
    assert check_jwt(ctx) == []
    assert len(seen) <= 5          # 1 alg-none + max 4 weak-secret replays


def test_weak_hmac_key_detected_when_none_rejected():
    # app that rejects alg:none but accepts weak-secret re-sign:
    def h(req):
        auth = req.headers.get("authorization", "")
        tok = auth.removeprefix("Bearer ").strip()
        hdr = tok.split(".")[0] if tok else ""
        import base64, json as _json
        try:
            alg = _json.loads(base64.urlsafe_b64decode(hdr + "==")).get("alg")
        except Exception:
            alg = None
        if alg == "HS256" and tok == forge_hs256(JWT, b"hush"):
            return httpx.Response(200, json={"whoami": "acct_a"})
        return httpx.Response(401, text="no")
    ctx, _ = _ctx(h)
    out = check_jwt(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["issue"].startswith("hs256_weak")


def test_no_jwt_no_op():
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", API)),
              fetch=lambda u, headers=None: httpx.Response(200))
    assert check_jwt(ctx) == []
