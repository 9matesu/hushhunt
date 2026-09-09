from __future__ import annotations

import httpx


class TriageContractError(Exception):
    """LLM replied with something that is not the agreed JSON contract.
    Fail-closed: triage errors mark nothing as verified."""


class LlmClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def complete_json(self, system: str, user: str) -> dict:
        r = httpx.post(
            self.cfg["llm.base_url"].rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {self.cfg.secret('HH_LLM_API_KEY')}"},
            json={"model": self.cfg["llm.model"],
                  "temperature": self.cfg["llm.temperature"],
                  "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]},
            timeout=120)
        r.raise_for_status()
        import json as _json
        try:
            out = _json.loads(r.json()["choices"][0]["message"]["content"])
        except (KeyError, IndexError, ValueError) as e:
            raise TriageContractError(str(e)) from e
        if not isinstance(out, dict):
            raise TriageContractError("reply is not a JSON object")
        return out


class FakeLlm:
    def __init__(self, replies: list[dict]):
        self.replies = list(replies)
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, system: str, user: str) -> dict:
        self.calls.append((system, user))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply
