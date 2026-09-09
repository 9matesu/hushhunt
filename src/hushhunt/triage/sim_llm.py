"""Deterministic stand-in for the real LLM in --sim mode: mimics the triage
and PoC contracts exactly (so prompt-shape regressions still surface), but
without API keys or cost."""
from __future__ import annotations

import json
import re


class SimLlm:
    def __init__(self):
        self.usage = {"prompt": 0, "completion": 0, "cost_usd": 0.0, "calls": 0}

    def complete_json(self, system: str, user: str) -> dict:
        self.usage["calls"] += 1
        if "poc_script" in system:
            m = re.search(r'"asset":\s*"([^"]+)"', user)
            asset = (m.group(1) if m else "").split("?")[0]
            return {"poc_script": (
                f'r = client.fetch("{asset}?q=%3Cb%3Ehushx%3C%2Fb%3E")\n'
                'assert "<b>hushx</b>" in r.text\nresult["ok"] = True\n')}
        m = re.search(r"SIGNALS:\n(.*)$", user, re.S)
        sigs = json.loads(m.group(1))
        vuln = [s for s in sigs if s["check_id"] in
                ("xss_reflected", "ssti", "idor", "blind_oast")]
        findings = []
        if vuln:
            findings.append({
                "signal_ids": [s["signal_id"] for s in vuln],
                "title": f"{vuln[0]['check_id']} on {vuln[0]['asset'][:60]}",
                "severity": "high", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "impact": "Demonstrated by captured evidence.",
                "confidence": 0.9, "reasoning": "raw marker reflection",
                "requires_poc": True, "dedupe_key": "sim-" + vuln[0]["check_id"]})
        return {"findings": findings,
                "dismissed": [{"signal_ids": [s["signal_id"] for s in sigs
                                              if s not in vuln],
                               "reason": "NA-PATTERN:sim-noise"}]}
