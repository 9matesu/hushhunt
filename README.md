# hushhunt

Low-noise, evidence-first bug bounty recon + AI triage + report generation.
HackerOne guidelines are the north star: scope is king, positives only,
quiet by construction. See **docs/SAFETY.md** — binding, enforced in code.

## Quickstart

```bash
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"
cp .env.example .env      # fill HH_H1_USER, HH_H1_API_TOKEN, HH_BC_TOKEN, HH_LLM_API_KEY
python -m pytest tests/ -q
python -m hushhunt run-nightly            # sync -> select -> probe -> triage -> verify -> report -> push(draft)
python -m hushhunt learn --finding 7 --outcome resolved   # feed reality back
python -m hushhunt status
```

Reports land in `out/reports/*.md` (HackerOne submission format) and the human
review queue in `out/PENDING.md`. `config.yaml -> submit.mode: auto` writes
`out/submit_payload_*.json` for the browser-assisted flow (confidence >= 0.9
and Safe Harbor programs only; researcher-side API submission pending OQ-1).

## How it stays quiet

- default-deny scope gate (unit-tested, e2e-asserted via `request_log ⊆ scope`)
- GET/HEAD only, ≤1 req/s per host, ≤12 req/asset, ≤150 req/program/day
- fetch-once-evaluate-many: baseline response feeds all checks
- passive-only mode for programs without Safe Harbor
- LLM triage is conservative by prompt + NA knowledge base short-circuit,
  and NOTHING is a finding until a deterministic verification gate
  (evidence replay + budgeted live re-confirm) says so — no LLM in that gate
- secrets are stored redacted; full values "available on request"

## Self-improvement loop

outcomes (`learn`) → per-check precision EWMA → target scoring + triage
prompt skepticism + `out/na_kb_proposed.json` (human-merged into the NA
corpus). The tool never rewrites its own rules silently.

## v2 — active pentesting modules (grant-gated)

The passive funnel is the base; active WSTG modules (XSS/SQLi/SSTI/IDOR/JWT/
redirect/GraphQL/blind-OAST/command-injection (RCE)/mass-assign) run ONLY
when ALL THREE gates pass:

1. **risk_cap** per program: `off` (nothing, not even passive) < `passive`
   (v1 checks only) < `low` (adds low-risk probe modules: redirect-chain,
   GraphQL, DOM-XSS) < `medium` (adds reflected XSS, SQLi-error, SSTI, JWT)
   < `high` (adds the deep blast-radius modules: IDOR, SQLi-boolean, blind
   OAST, mass-assign — each ALSO needs a `deep`-scope grant). — operator
   sets it in the DB: `UPDATE programs SET risk_cap='high' WHERE id='h1:x'`.
2. **policy lint** — program policy text is keyword-linted
   (`policy_lint.py`); blocked modules can't be granted at all (belt), and
3. **signed grant** — `hushhunt grant --program h1:x --module idor --scope
   deep --hours 48 --max-requests 150` (HMAC with `HH_GRANT_SECRET`;
   expiring, request-budgeted). Or flip `auto_grant.enabled: true` and the
   pipeline signs its own daily grants — policy and cap still gate it.
   Precedence: **policy > grant > cap**; a grant
   never widens the cap; the LLM planner can propose tests but the validator
   rejects anything grantless, out-of-scope, or invented-surface
   (`out/planner_rejected.log` is the audit trail).

Operator playbook: create throwaway accounts → register in
`seeds/accounts.yaml` (passwords via env only) → read the program policy YOURSELF
→ set cap → grant modules → `run-nightly` → review `out/PENDING.md` +
`planner_rejected.log` → `learn --outcome` after the platform answers.
Noisy modules auto-demote (precision <0.25 after ≥4 outcomes);
`hushhunt undemote <module>` brings one back.

Deep findings (sessions/OAST-based) verify ONLY through re-runnable PoC
scripts executed in an AST sandbox — the deterministic positive gate got
stronger: it re-RUNS the exploit.

Hermes cron wiring (optional):

```
cronjob action=create schedule="every day at 2am" name="hushhunt nightly"
  workdir="I:/hushhunt" script="..." or prompt="run python -m hushhunt
  run-nightly in I:/hushhunt, report the RUN line and any new PENDING items"
```
