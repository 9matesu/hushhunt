# HushHunt Analytics & Algorithmic Self-Improvement

## 1. Precision-Weighted Scoring (EWMA)

Each module maintains a precision score estimating the probability that a emitted signal leads to a confirmed vulnerability.

$$
W_t = \alpha \cdot \text{Outcome}_t + (1 - \alpha) \cdot W_{t-1}
$$

- $\alpha \approx 0.3$ — recent outcomes dominate but old history retains influence.
- $\text{Outcome}_t \in \{1 \text{ (accepted/resolved)}, 0 \text{ (not-applicable/duplicate)}\}$.

### Feed Paths
- Target selection (`src/hushhunt/select.py`): `Score = Bounty \times Freshness \times AvgPrecision`.
- Triage prompt (`src/hushhunt/triage/prompts.py`): Per-check precision values included as `HISTORICAL PER-CHECK PRECISION` so the LLM judges signals skepticism proportionally.

---

## 2. Automated Module Demotion

Thresholds (`src/hushhunt/learn.py:auto_demote`):
- Minimum sample threshold $N \ge 4$ outcomes.
- Precision floor: $W_t < 0.25$.

Modules falling below the floor are inserted into `demoted` with:
```sql
INSERT INTO demoted(module, until, reason) VALUES(?, now() + 30d, ?)
```

Effects:
- `granted_modules()` refuses to run them.
- `planner.py:validate()` rejects AI proposals for them.
- `hushhunt undemote <module>` manually restores them after human confirms the root cause of noise is resolved.

---

## 3. Already-Known Noise (NA-KB)

Static JSON rules in `seeds/na_kb.json` define deterministic drop patterns that short-circuit LLM usage:

```json
[
  {"id": "robots-noise", "check_id": "exposed_files",
   "match": {"path": "/robots.txt"}, "why_rejected": "default crawler artifact"}
]
```

Dismissed LLM findings automatically propose harvested rules into `out/na_kb_proposed.json`, which a human merges into the permanent corpus (`seeds/na_kb.json`).

---

## 4. Efficiency & ROI Analytics

Tracked per check (`src/hushhunt/analytics.py`):
- **Yield**: $\text{Yield} = \frac{\text{Verified Findings}}{\text{Total HTTP Requests}}$
- **Cost**: $\text{CostPerBug} = \frac{\text{LLM Token Spend} + \text{HTTP Requests}}{\text{Verified Findings}}$
- **Time-To-Verify**: Median latency from signal capture to PoC proof.
- **False Positive Defense Rate**: $\frac{\text{Dropped Signals}}{\text{Total Triaged}}$

Surfaced via:
- `hushhunt status --analytics` CLI table.
- Nightly RUN log line: `yield=<x> cost_usd=<y> precision_avg=<z>`.

---

## 5. Target Surface Intelligence

For each program, analytics stores:
- Vulnerable parameter density: $\frac{\text{Signals}}{\text{Params Seen}}$
- Technology fingerprint heatmap (e.g. `X-Powered-By: Express` $\rightarrow$ higher SSTI prior).
- Triaged-program recall rate: $\frac{\text{Verified}}{\text{Triaged}}$.

Adaptive behavior:
- High-yield parameters are automatically promoted in future planner prompts (`procedures` memory).
- Dead-end targets ($\text{Yield} = 0$ over 2 consecutive cycles) are temporarily de-prioritized by `select.py`.
