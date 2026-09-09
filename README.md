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

## Hermes cron wiring (optional)

```
cronjob action=create schedule="every day at 2am" name="hushhunt nightly"
  workdir="I:/hushhunt" script="..." or prompt="run python -m hushhunt
  run-nightly in I:/hushhunt, report the RUN line and any new PENDING items"
```

## v2

Active-testing modules (rate-bounded, human-gated per program) are planned in
`.hermes/plans/` — see the v2 plan document; nothing there ships yet.
