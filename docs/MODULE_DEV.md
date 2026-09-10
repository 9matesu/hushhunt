# HushHunt Module Development Guide

## 1. Quick Example: Creating an Active Check

Create `src/hushhunt/checks/active/mycheck.py`:

```python
from __future__ import annotations
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from .. import Ctx, register, register_repro


@register("my_check", "WSTG-INPV-99", "medium")
def check_my_check(ctx: Ctx) -> list[dict]:
    """Inspects candidate parameters in ctx.params using ctx.fetch."""
    if ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    hits = []
    for url, param, _orig in ctx.params[:4]:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = ["test_payload"]
        target_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
        try:
            resp = ctx.fetch(target_url)
        except Exception:
            continue
        if "vuln_marker" in resp.text:
            hits.append({
                "check_id": "my_check",
                "asset": target_url,
                "severity_hint": "medium",
                "payload": {"param": param, "marker": "vuln_marker"}
            })
            break  # One proof per asset is enough
    return hits


register_repro("my_check", lambda sig: [
    f"Send GET request to {sig['asset']}.",
    f"Parameter {sig['payload']['param']!r} echoes the unescaped payload.",
])
```

---

## 2. The `Ctx` Object Interface

| Attribute | Type | Description |
|-----------|------|-------------|
| `ctx.resp` | `httpx.Response` | Baseline GET response from initial asset probe. |
| `ctx.fetch` | `Callable[[str], Response]` | Budgeted GET client (`HardenedClient.get`). Omitted in passive mode. |
| `ctx.post` | `Callable[[str, ...], Response]` | Budgeted, grant-gated POST client. Raises `PermissionError` without grant. |
| `ctx.asset_url` | `str` | Root URL of the current asset being tested. |
| `ctx.params` | `list[tuple[url, param, orig]]` | Discovered crawl parameters (`params_seen`). |
| `ctx.grant_id` | `int` or `None` | Active grant ID backing this execution. |
| `ctx.oast` | `OastClient` or `None` | Out-of-band canary generator and listener for blind bugs. |
| `ctx.session_a` | `httpx.Client` or `None` | Authenticated session for Account A (IDOR testing). |
| `ctx.session_b` | `httpx.Client` or `None` | Authenticated session for Account B (IDOR testing). |

---

## 3. Registering the Module Contract

1. In `src/hushhunt/checks/active/__init__.py`:
   Add the module name and its grant requirement (`probe` or `deep`):
   ```python
   ACTIVE_MODULES["my_check"] = "probe"  # or "deep" for high blast-radius
   ```
2. In `src/hushhunt/checks/cwe.py`:
   Map the check ID to its canonical CWE identifier:
   ```python
   CWE_MAP["my_check"] = "CWE-20"
   ```
3. In `src/hushhunt/report.py`:
   Add CVSS v3.1 vector, impact description, and specific remediation advice in `_CVSS_MAP`, `_IMPACT_MAP`, and `_REMEDIATION`.
4. In `src/hushhunt/poc.py`:
   Add a deterministic Python PoC template in `generate_deterministic_poc`:
   ```python
   elif cid == "my_check":
       return (
           f"r = client.fetch({url!r})\n"
           f"assert 'vuln_marker' in r.text\n"
           f"result['ok'] = True\n"
       )
   ```

---

## 4. Writing Unit & Offline Mock Tests

Every check requires an offline unit test file (`tests/test_check_mycheck.py`) using `httpx.MockTransport`:

```python
import httpx
from hushhunt.checks import Ctx
from hushhunt.checks.active.mycheck import check_my_check

def test_my_check_detects_vulnerable():
    def handler(request: httpx.Request):
        if "test_payload" in str(request.url):
            return httpx.Response(200, text="vuln_marker in body")
        return httpx.Response(200, text="clean")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = Ctx(
        resp=httpx.Response(200),
        fetch=client.get,
        params=[("https://t.invalid/page?param=1", "param", "1")]
    )
    hits = check_my_check(ctx)
    assert len(hits) == 1
    assert hits[0]["check_id"] == "my_check"

def test_my_check_quiet_on_safe():
    def handler(request: httpx.Request):
        return httpx.Response(200, text="safely sanitized")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ctx = Ctx(
        resp=httpx.Response(200),
        fetch=client.get,
        params=[("https://t.invalid/page?param=1", "param", "1")]
    )
    hits = check_my_check(ctx)
    assert len(hits) == 0
```
