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

## Open questions / operator duties

- Verify per-program policy manually before first hunt (`hushhunt status`).
- HackerOne researcher-side submission API availability (OQ-1) — until
  verified, auto mode only writes `out/submit_payload.json`.
- Bugcrowd/H1 API terms: program metadata is for personal research use; do
  not republish scraped platform data.
