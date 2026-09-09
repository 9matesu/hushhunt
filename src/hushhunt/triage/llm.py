from __future__ import annotations

import httpx


class TriageContractError(Exception):
    """LLM replied with something that is not the agreed JSON contract.
    Fail-closed: triage errors mark nothing as verified."""


class LlmClient:
    """OpenAI-compatible chat + per-run cost meter (REDCELL port): usage is
    accumulated globally; hushhunt adds it to the RUN line and var/llm_cost.json
    so nightly spend is visible without a server. Prices in config.llm.prices
    (USD per 1M tokens, [in, out]); unknown model => cost 0, never a guess."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.usage = {"prompt": 0, "completion": 0, "cost_usd": 0.0, "calls": 0}

    def _cost(self, prompt_toks: int, completion_toks: int) -> float:
        model = str(self.cfg["llm.model"]).lower()
        family = model.rsplit("/", 1)[-1]
        prices = self.cfg.get("llm.prices", {}) or {}
        pair = prices.get(family)
        if pair is None:                       # family fallback
            for name, p in prices.items():
                if family.startswith(name.split("-")[0] + "-"):
                    pair = p
                    break
        if not pair:
            return 0.0
        return prompt_toks / 1e6 * pair[0] + completion_toks / 1e6 * pair[1]

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
        payload = r.json()
        usage = payload.get("usage") or {}
        self.usage["prompt"] += int(usage.get("prompt_tokens") or 0)
        self.usage["completion"] += int(usage.get("completion_tokens") or 0)
        self.usage["cost_usd"] += self._cost(int(usage.get("prompt_tokens") or 0),
                                             int(usage.get("completion_tokens") or 0))
        self.usage["calls"] += 1
        import json as _json
        try:
            out = _json.loads(payload["choices"][0]["message"]["content"])
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
