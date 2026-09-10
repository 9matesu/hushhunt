# hushhunt operating safety policy

This document is binding: the code enforces these rules and operators may not
relax them without editing the code AND this file. North star: HackerOne
disclosure guidelines and program policy.

## Hard rules (enforced in code)

1. **Default-deny scope.** Every URL touching program-owned infrastructure must
   pass `scope.url_in_scope` against the program's published includes minus
   excludes. Non-domain asset types (IP, mobile, "Other") are never probed.
   Enforced in `src/hushhunt/scope.py` + `HardenedClient.get` (raises
   `OutOfScope` before any socket opens). The e2e test asserts
   `request_log ⊆ scope`.
2. **GET/HEAD only.** `HardenedClient` has no POST/PUT/PATCH/DELETE — accessing
   them raises. No auth'd endpoints, no forms, no mutation, ever.
3. **Rate & volume.** ≤1 req/s per host, ≤12 req/asset, ≤150 req/program/day
   (config.yaml → limits). Verification re-fetches are budgeted through the
   same client; the js-mining fetch cap is 4/asset. A WAF block means STOP —
   never retry-loop.
4. **Safe Harbor respected.** `safe_harbor: none` programs get passive-only
   checks (zero active probes) and are heavily de-prioritized by selection.
5. **Identification.** Every request carries a User-Agent naming the hunter
   account and contact. No cache-busting, no evasion of robots for findings.
6. **Data handling.** Only ≤64 KiB response excerpts stored as evidence;
   secrets found in JS are stored redacted (prefix+length) and reported as
   "available on request". No bulk downloads, no data exfiltration.
7. **Report hygiene.** One report per vulnerability (dedupe_key gate), nothing
   reaches a platform unless it passed the deterministic verification gate
   (evidence replay + live re-confirm) — no LLM-only positives. Default
   `submit.mode: draft`: a human reviews and sends. `auto` additionally
   requires confidence ≥0.9 and Safe Harbor, and even then only writes a
   payload file for a browser-assisted flow that a human completes.

## Never do (out of scope for this tool, by design)

brute force, credential testing, directory fuzzing beyond the exact-path
allowlist, SQLi/XSS payload injection, SSRF/OAST canaries, DoS of any kind,
subdomain brute-forcing (ct.sh only), scanning out-of-scope assets found
"along the way" (report via security.txt contact instead), public disclosure
before triage resolution.

## v2 active testing — the grant model

Precedence, strongest first: **program policy (lint) > operator grant >
per-program risk_cap**. All three must allow a module before a single active
request leaves the box.

1. `risk_cap` per program: `off` (nothing, not even passive) < `passive`
   (v1 checks only) < `low` (low-risk probe modules: redirect/GraphQL/DOM-XSS)
   < `medium` (medium modules: reflected XSS, SQLi-error, SSTI, JWT) <
   `high` (deep modules: IDOR, SQLi-boolean, blind OAST, mass-assign — each
   additionally needs a `deep`-scope grant).
2. `policy_lint.py` keyword-lints the synced program policy; blocked modules
   are refused even by `hushhunt grant` (the CLI prints the matched line).
3. Grants are HMAC-signed (`HH_GRANT_SECRET`), expiring (`--hours`), and
   request-budgeted (`--max-requests`) — enforced in `HardenedClient` for
   every `post()` and every module run.
3b. **auto_grant mode** (operator opt-in in config.yaml): the pipeline mints
   its own grants each night with the same TTL/budget machinery. It does NOT
   bypass gates 1-2: policy-lint blocks still stand, risk_cap still bounds,
   demotion still silences noisy modules, and `deep: true` is a separate
   opt-in for blast-radius modules. Every auto-grant is logged to
   out/QUESTIONS.md (revoke any time with `hushhunt revoke <id>`). Grants
   expire daily, so a revoked/disabled module stays dead unless re-granted.

Active-module rules beyond v1's:
- Only crawl-observed URLs/params are testable (no invented surfaces —
  enforced by the planner validator AND the checks' `ctx.params` input).
- XSS evidence uses inert markers; no alert/stealer payloads, ever.
- SQLi proves an oracle (error fingerprint / TRUE-FALSE delta) — no data
  extraction, no time-based by default; OAST proves blind bugs via the
  target's own egress to our canary, nothing in-band.
- Session modules use ONLY throwaway accounts the operator registered
  (passwords in env vars only); IDOR reads only objects account A itself
  observed; mass-assign writes one field to our own profile and ROLLS BACK.
- Command injection (RCE) is proven OUT-OF-BAND ONLY: the injected command
  is an inert `curl` to our OAST canary — no destructive tokens are ever
  emitted (test-pinned), and with OAST disabled the module fires ZERO
  requests. RCE requires a `deep` grant + `high` cap; the LLM cannot
  trigger it.
- Deep findings verify by RE-RUNNING a PoC script in an AST sandbox
  (no imports except hushhunt, no file/socket/exec builtins, 12-request cap)
  — the exploit execution IS the deterministic positive gate.
- Noisy modules (precision <0.25 over ≥4 outcomes) auto-demote for 30 days;
  only `hushhunt undemote` brings them back.

Never do (v2 additions): GraphQL depth/aliasing abuse, race-condition
testing, file-upload probing, websocket fuzzing, anything against an auth
wall we didn't enter with our own registered account.

## Open questions / operator duties

- Verify per-program policy manually before first hunt (`hushhunt status`).
- HackerOne researcher-side submission API availability (OQ-1) — until
  verified, auto mode only writes `out/submit_payload.json`.
- Bugcrowd/H1 API terms: program metadata is for personal research use; do
  not republish scraped platform data.
