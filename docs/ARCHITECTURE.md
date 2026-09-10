# HushHunt Architecture Specification

## 1. System Overview

HushHunt is an evidence-first, low-noise autonomous bug bounty recon and pentesting suite.
Architecture separates discovery, execution, verification, and reporting into isolated, strictly gated layers.

```
                    ┌────────────────────────┐
                    │   Platform Ingestion   │ (bbscope, HackerOne, Bugcrowd)
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │ Scope & Budget Sandbox │ (url_in_scope, HardenedClient)
                    └───────────┬────────────┘
                                │
         ┌──────────────────────┴──────────────────────┐
         │                                             │
┌────────▼─────────┐                         ┌─────────▼────────┐
│  Passive Recon   │                         │  Active Testing  │
│ (Headers, Files, │                         │ (XSS, SQLi, IDOR,│
│  CORS, JS, TLS)  │                         │  SSTI, CmdInject)│
└────────┬─────────┘                         └─────────┬────────┘
         │                                             │
         │      Triple Gate: Policy > Cap > Grant      │
         └──────────────────────┬──────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   AI Test Planner &    │ (9router: ag/gemini-3.8-flash)
                    │  Triage Engine + NA-KB │ (procedures memory)
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │ Deterministic Verifier │ (Evidence Replay +
                    │     & AST Sandbox      │  Python PoC Execution)
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │  Reporting & Feedback  │ (H1 Markdown, SARIF,
                    │  EWMA Learning Engine  │  Auto-Demotion, Analytics)
                    └────────────────────────┘
```

---

## 2. Seven-Layer Architecture

### Layer 1: Ingestion & Scope Hardening
- **Modules**: `src/hushhunt/adapters/`, `scope.py`, `http.py`
- **Responsibilities**:
  - Ingest scopes from platforms (`bbscope` 1200+ public programs with zero credentials, HackerOne API, Bugcrowd API).
  - Normalize targets into wildcard domains (`*.target.com`), exact hostnames (`app.target.com`), and URL prefixes.
  - Enforce default-deny in `scope.py:url_in_scope(url, includes, excludes)`.
  - Rate limiting & request quotas in `http.py:HardenedClient`: max 1 req/sec per host, 12 req/asset, 150-400 req/program/day. Out-of-scope requests raise `OutOfScope` before any network socket opens.

### Layer 2: Passive Reconnaissance & Discovery
- **Modules**: `crawl.py`, `ctlogs.py`, `checks/` (headers, files, cors, jsmining, tlsconfig)
- **Responsibilities**:
  - Certificate transparency log monitoring (`crt.sh`) to discover unindexed subdomains.
  - Shallow robots.txt and link crawling to extract seen URLs and query parameters (`params_seen` table).
  - Fetch-once-evaluate-many: one baseline GET response feeds all passive checks sharing `Ctx`.
  - Zero payload injection; only inspects existing server headers, files, certificates, and JS bundles.

### Layer 3: Active Pentest Engine (Grant-Gated)
- **Modules**: `checks/active/` (xss, domxss, sqli, ssti, idor, jwtchecks, redirect, graphql, blind, cmdinject, nuclei_check), `grants.py`, `policy_lint.py`
- **Responsibilities**:
  - Evaluates active WSTG test modules against parameters discovered during crawl (`params_seen`).
  - **Triple-Gate Enforcement**:
    1. `policy_lint.py`: Regex lints program policy text. If policy bans a technique (e.g. "no automated sql injection"), module is hard-blocked.
    2. `risk_cap`: Program risk ceiling (`off` < `passive` < `low` < `medium` < `high`).
    3. `grants.py`: HMAC-SHA256 signed tokens (`HH_GRANT_SECRET`) with mandatory TTL (e.g. 24h) and request budget (e.g. 150 reqs). In `auto_grant` mode, grants are minted only after Policy and Cap gates pass.
  - Safe payload design: marker-only reflection probes for XSS; error/boolean probes for SQLi; inert OAST callbacks for RCE/SSRF. No destructive commands or data extraction.

### Layer 4: AI Strategic Planner & Triage
- **Modules**: `planner.py`, `triage/engine.py`, `triage/prompts.py`, `triage/llm.py`, `procedures.py`
- **Responsibilities**:
  - Connects to 9router (`http://localhost:20128/v1`) using OpenAI-compatible protocol (`ag/gemini-3.8-flash` or `ag/claude-sonnet-4-6`).
  - **Planner (`plan`)**: Proposes up to 3 targeted tests on crawl-observed parameters. Validator rejects out-of-scope, ungranted, or invented surfaces before execution.
  - **Triage (`triage_asset`)**: Filters raw signals through `NaKb` (Not-Applicable Knowledge Base) first to drop known noise with zero LLM cost. LLM reviews remaining signals, assigning CVSS, severity, and `requires_poc: true`.
  - **Procedural Memory**: Queries `procedures` table to recall historical target behavior, bypasses, and tech-stack quirks.

### Layer 5: Sandbox Verification & PoC Execution
- **Modules**: `verify.py`, `poc.py`, `safecommands.py`
- **Responsibilities**:
  - **No LLM in the verification decision**: Hallucinated findings are dropped structurally.
  - Passive findings: Re-verified via evidence replay from disk + 1 budgeted live GET confirm.
  - Active findings (`requires_poc: true`): Synthesized Python PoC script parsed via AST visitor (`poc.py:_Checker`).
  - AST allowlist rejects all imports (except `hushhunt`), builtins like `open/eval/exec/__import__`, attribute access to private/dunder methods, and destructive commands (`safecommands.py:is_destructive`).
  - PoC must execute within locked `_ClientView` budget (<=12 requests) and assert `result["ok"] = True`.

### Layer 6: Report Generation & SARIF Export
- **Modules**: `report.py`, `sarif.py`, `push.py`, `templates/report.md.j2`
- **Responsibilities**:
  - Generates reproducible, high-quality HackerOne Markdown reports in `out/reports/<program>-<id>-<slug>.md`.
  - Includes exact CVSS v3.1 vector, CWE identifier, executive summary, business impact scenario, copy-paste curl command, sandboxed Python PoC, and contextual remediation.
  - Exports industry-standard SARIF 2.1.0 (`out/reports/findings.sarif`) for SIEM and CI/CD ingestion.
  - Enforces deduplication key: one report per root vulnerability.

### Layer 7: Analytics & Self-Improving Feedback Loop
- **Modules**: `learn.py`, `analytics.py`, `operator.py`
- **Responsibilities**:
  - `hushhunt learn --finding <id> --outcome <resolved|not-applicable|informative|duplicate>`: Human outcomes update per-module precision EWMA ($W_t = \alpha \cdot \text{outcome} + (1 - \alpha) \cdot W_{t-1}$).
  - Precision weights feed back into target selection (`select.py`) and triage prompt skepticism.
  - **Auto-Demotion**: Any module falling below 0.25 precision after $\ge 4$ evaluations is automatically silenced for 30 days.
  - **NA-KB Proposal**: Dismissed findings extract pattern rules into `out/na_kb_proposed.json` for human approval into the permanent noise filter.
  - **Analytics**: Calculates module yield (findings per request), token cost per verified bug, and target vulnerability surface indices.

---

## 3. Database Schema & State Machines

```
Finding Stages:
[Signal Added] -> (triaged) -> (verified) -> [Report Written] -> (draft / submitted)
                      │             │
                      ▼             ▼
                  (dropped)      (failed)
```

SQLite Tables (`var/hushhunt.db`):
- `programs`: Platform metadata, policy text, scope JSON, synced timestamp, risk cap.
- `assets`: In-scope domains, apexes, and origins.
- `request_log`: Audit log of every outbound HTTP request (ts, url, method, status, ms, kind).
- `signals`: Raw anomalies emitted by checks with linked evidence directories on disk.
- `findings`: Triaged candidate vulnerabilities with stage, confidence, outcome, and detail JSON.
- `grants`: HMAC-signed operator/auto grants with TTL and request headroom.
- `poc_scripts`: AST-sandboxed Python PoC code and execution success status.
- `demoted`: Modules currently silenced due to high noise / low precision.
- `params_seen`: Unique URLs, parameters, and sample values harvested during crawl.
- `weights`: Check precision EWMA and sample count $N$.
- `procedures`: AI procedural memory of effective testing patterns and target quirks.

---

## 4. Security & Safety Invariants

1. **Default-Deny Scope Wall**: No HTTP request leaves the machine without matching `url_in_scope`. Tested by invariant: `SELECT COUNT(*) FROM request_log WHERE url NOT IN scope == 0`.
2. **Read-Only by Default**: POST requests require active grant scope and specific check authorization. PUT, PATCH, DELETE are structurally forbidden in `HardenedClient`.
3. **AST PoC Sandboxing**: No untrusted code from LLM or external source can access the filesystem, OS environment, or subprocesses.
4. **Secret Redaction**: Credentials observed in JS bundles or responses are stored as `prefix + [REDACTED <len>]` on disk and in reports. Full secrets are never committed or echoed in plain text.
5. **Deterministic Proof**: Triage confidence alone never creates a finding; verifiable execution of PoC or evidence replay is mandatory.
