# HushHunt AI Operational Procedures Handbook

## 1. AI Test Planning Heuristics

### 1.1 Parameter Semantics -> Likely Vulnerability Class

| Parameter Name Pattern | Likely Vulnerability | Modules to Probe |
|------------------------|----------------------|------------------|
| `url`, `redirect`, `dest`, `next`, `returnUrl`, `link` | SSRF / Open Redirect | `blind_oast`, `open_redirect_chain` |
| `id`, `uuid`, `user`, `account`, `doc`, `file`, `order` | IDOR / Broken Access Control | `idor` |
| `q`, `search`, `keyword`, `name`, `comment`, `tpl` | XSS / SSTI | `xss_reflected`, `xss_dom`, `ssti` |
| `page`, `template`, `view`, `theme`, `layout` | LFI / SSTI | `ssti`, `exposed_files` |
| `callback`, `jsonp` | JSONP / DOM XSS | `xss_dom` |
| `sort`, `filter`, `orderBy`, `query` | SQL Injection | `sqli_error`, `sqli_boolean` |
| `cmd`, `exec`, `ping`, `host`, `shell` | Command Injection (RCE) | `cmd_inject` |
| `role`, `is_admin`, `price`, `balance`, `group` | Mass Assignment | `mass_assign` |
| `token`, `jwt`, `auth`, `api_key` | JWT Misuse / Auth Bypass | `jwt_misuse` |
| `query`, `graphql`, `introspection` | GraphQL Exposure / Injection | `graphql_probe` |

### 1.2 Route Pattern Priority

1. `/api/v*/` — Highest priority. Structured backends reveal internal templates and error verbosity.
2. `/graphql` or `/gql` — Probe for schema introspection (`query{__schema{types{name}}}`).
3. `/admin/`, `/internal/`, `/debug/`, `/console` — Administrative interfaces and IDOR sinks.
4. `/.git/`, `/.env`, `/backup.zip`, `/config.php~` — Exposed sensitive files.
5. `/search`, `/profile`, `/order`, `/document` — User-controlled reflections and object references.

---

## 2. Payload Escalation Ladders

### 2.1 Reflected XSS (WSTG-INPV-01)
1. Plain token echo: `hush<rand>` — Establishes reflection; no context proof.
2. Attribute-break: `">hush<rand>"<` — Breaks out of `value="..."` contexts.
3. Tag injection: `<x>hush<rand></x>` — Tests raw HTML injection points.
4. Script context: `'-"-hush<rand>-"'"` — Tests JS-string sinks.
**Proof Rule:** Only `<>` payloads that appear verbatim in `response.text` count as proof. Markup with escaped entities (`&lt;`, `&gt;`) is a PASS (safe handling).

### 2.2 SQL Injection: Error & Boolean (WSTG-INPV-05)
1. Error probes: `'`, `"`, `\`, `')`, `"))` — Match response against regexed DB error fingerprints (MySQL, Postgres, MSSQL, Oracle).
2. Numeric probes: `1' OR '1'='1`, `1; SELECT SLEEP(1)--` — Only allowed under `deep` granted scope.
3. Boolean/oracle probes: `1 AND 1=1` vs `1 AND 1=2` — If content-length difference or status divergence observed, confirms blind oracle.
**Proof Rule:** Requires database error string in-band OR consistent TRUE/FALSE response delta.

### 2.3 Server-Side Template Injection (WSTG-INPV-18, Medium)
1. Math probe: `{{7*7}}` -> expect literal `49` in response.
2. Alternate engines: `${7*7}`, `#{7*7}`, `<%= 7*7 %>`.
3. Confirm by varying operands (e.g. `{{8*8}}` -> `64`) to rule out coincidences.

### 2.4 Command Injection (RCE, Deep-Grant Only, Inert OAST)
1. Inert DNS canary: Payload references unique tokenized subdomain (`$(host <token>.oast)` or `;nslookup <token>.oast;`).
2. HTTP canary: Payload references unique HTTP token URL.
3. Poll OAST server for 10s; single callback = proof of command execution capability.
4. **Never use destructive syntax** (`rm`, `wget`, `curl` to pull payloads, shell forks, exfiltration loops).

### 2.5 IDOR (WSTG-ATHZ-04, Deep-Grant Only)
1. Authenticate as accounts A and B (throwaway test accounts via `SessionBroker`).
2. As account A, record all object URLs account A legitimately accesses.
3. As account B, request the same object belonging to A (`/api/orders/<A-object-id>`).
4. If B gets HTTP 200 + body hash-matches A's view of the same object, horizontal privilege escalation is confirmed.
**Proof Rule:** Requires equal fingerprints (`fnv1a`) between A-view and B-view of foreign-object endpoints.

### 2.6 JWT Misuse (WSTG-SESS-10, Medium)
1. Extract `Authorization: Bearer <jwt>` from test account sessions.
2. Replay without signature (`alg: none`), with null bytes, with swapped `RS256 -> HS256` using the public key.
3. Assert forged token is accepted (200 on `/api/whoami` with impersonated `sub`).

### 2.7 Open Redirect Chain & SSRF (WSTG-CLNT-04 / WSTG-INPV-19)
1. Probe `?next=https://evil.invalid` and observe `Location` header. Assert redirect destination leaks to external host.
2. SSRF probes always point to OAST canary domain. Poll for out-of-band callback.

---

## 3. False-Positive Traps & Bypass Knowledge

1. **CDN Reflection Mirrors**: WAF edge nodes may echo inputs in block pages. Require that reflection originates from an application route (`/search`, `/profile`) not a WAF/CDN block stub.
2. **Static Cache Poisoning Traps**: Query parameter variants (e.g. `?cb=1`) may be served from cached copies. Use fresh inert tokens per request (`hush<hex4>`) to defeat caching artifacts.
3. **Error Page Echoes**: Generic 404 handlers may reflect unknown paths in error messages. Confirm injection via *parameter value*, not path-derived echo.
4. **Rate-Limit Throttling Traps**: Under request limits, servers may return HTTP 429 with reflected `Retry-After`. Treat 429 responses as "inconclusive, STOP probing host."
5. **Time-Based Decoy Responses**: Legitimate functions may take $> 2$s due to queueing. Do not classify timing alone as proof without strict 2-request confirmation.
