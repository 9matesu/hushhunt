from __future__ import annotations

import json
from datetime import datetime, timezone

from .llm import TriageContractError
from .prompts import SYSTEM_PROMPT, build_user_prompt


def _insert_finding(conn, signal_ids: list[int], stage: str, confidence: float | None,
                    payload: dict) -> int:
    conn.execute(
        """INSERT INTO findings(signal_id,stage,confidence,report_path,outcome,
             detail_json,updated_at) VALUES(?,?,?,?,?,?,?)""",
        (signal_ids[0], stage, confidence, None,
         payload.get("reason") if stage == "dropped" else None,
         json.dumps(payload), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    return conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]


def triage_asset(conn, cfg, llm, program: dict, signals: list[dict], na_kb,
                 weights: dict[str, float], granted: list[str] | None = None,
                 focus: list[str] | None = None) -> list[int]:
    """One LLM call per (program, asset-batch). NA-KB matches first: free,
    deterministic, and it shrinks the prompt. Returns new finding ids
    (stage='triaged'). Raises TriageContractError without writing anything
    when the model breaks the JSON contract (fail-closed)."""
    if not signals:
        return []
    kept, na_dropped = [], []
    for s in signals:
        hit = na_kb.match(s["check_id"], s["payload_json"])
        (na_dropped if hit else kept).append((s, hit))
    na_kb_ids = [h["id"] for _, h in na_dropped if h]
    new_ids: list[int] = []
    for s, hit in na_dropped:
        if hit:
            _insert_finding(conn, [s["id"]], "dropped", None,
                            {"reason": f"NA-PATTERN:{hit['id']}",
                             "why": hit["why_rejected"]})
    if not kept:
        return new_ids  # everything was NA — never spend LLM tokens
    user = build_user_prompt(program, [s for s, _ in kept], weights, na_kb_ids,
                             granted=granted, focus=focus)
    reply = llm.complete_json(SYSTEM_PROMPT, user)
    if not isinstance(reply, dict):
        raise TriageContractError("reply is not a JSON object")
    findings = reply.get("findings")
    if not isinstance(findings, list):
        raise TriageContractError("missing 'findings' list")
    known = {s["id"] for s, _ in kept}
    min_conf = cfg["triage.min_confidence"]
    for f in findings:
        sids = [i for i in f.get("signal_ids", []) if i in known]
        conf = float(f.get("confidence", 0))
        if not sids:
            continue  # model invented signal ids -> contract breach, drop it
        if conf < min_conf:
            _insert_finding(conn, sids, "dropped", conf,
                            {"reason": "below_min_confidence", "title": f.get("title")})
            continue
        new_ids.append(_insert_finding(conn, sids, "triaged", conf, f))
    for d in reply.get("dismissed", []) or []:
        sids = [i for i in d.get("signal_ids", []) if i in known]
        if sids:
            _insert_finding(conn, sids, "dropped", 0.0,
                            {"reason": d.get("reason", "llm_dismissed")})
    return new_ids
