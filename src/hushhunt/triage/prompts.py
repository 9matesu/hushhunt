from __future__ import annotations

SYSTEM_PROMPT = """You are a senior HackerOne triager. You are extremely conservative: you prefer a
false negative to a false positive. Given raw signals from PASSIVE reconnaissance,
decide which, if any, constitute a reportable security vulnerability per HackerOne
report-quality rules. Rules:
- Missing security headers, TLS nits, version disclosure, cookie flags WITHOUT an
  impact path, robots.txt, and DNS/whois trivia are NOT-applicable on their own.
  Do not report them unless a signal combination clearly enables real impact.
- Judge with this program's policy in mind (provided). Respect stated out-of-scope.
- Weight context: this tool's per-check historical precision is provided; trust
  low-precision checks skeptically.
- For every accepted finding produce CVSS v3.1 vector and one-sentence IMPACT.
- When the granted modules list is non-empty, you MAY request deeper testing:
  set "requires_poc": true on accepted findings whose impact you want proven
  by a re-runnable PoC script (the pipeline will synthesize + run it; failure
  drops the finding). NEVER list or request a module that is not granted.
- Output ONLY JSON: {"findings":[{"signal_ids":[..],"title":"..","severity":"low|medium|high|critical",
  "cvss":"CVSS:3.1/..","impact":"..","confidence":0.0-1.0,"reasoning":"..",
  "requires_poc":true|false,"dedupe_key":"short-stable-slug"}],
  "dismissed":[{"signal_ids":[..],"reason":"NA-PATTERN:<id>|<free>"}]}"""


def build_user_prompt(program: dict, signals: list[dict], weights: dict[str, float],
                      na_kb_ids: list[str], granted: list[str] | None = None,
                      focus: list[str] | None = None) -> str:
    import json
    policy = (program.get("policy_text") or "")[:2000]
    slim = [{"signal_id": s["id"], "check_id": s.get("check_id"),
             "asset": s.get("asset"), "severity_hint": s.get("severity_hint"),
             "wstg": s.get("wstg"),
             "payload": json.loads(s["payload_json"])} for s in signals]
    return (
        f"PROGRAM: {program['name']} ({program.get('platform','?')})\n"
        f"SAFE HARBOR: {program.get('safe_harbor')}\n"
        f"POLICY EXCERPT:\n{policy}\n\n"
        + (f"OPERATOR FOCUS DIRECTIVES (from the hunter running this):\n"
           + "\n".join(f"- {f}" for f in focus[:5]) + "\n\n" if focus else "")
        + f"HISTORICAL PER-CHECK PRECISION (0..1, from your owner's outcomes):\n"
        f"{json.dumps(weights, indent=1)}\n\n"
        f"ALREADY-NA-KNOWLEDGE (do not re-argue these):\n{json.dumps(na_kb_ids)}\n\n"
        f"GRANTED DEEP-TEST MODULES (empty = passive evidence only):\n"
        f"{json.dumps(granted or [])}\n\n"
        f"SIGNALS:\n{json.dumps(slim, indent=1)}\n"
    )
