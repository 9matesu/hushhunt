from __future__ import annotations

import json
import re
from pathlib import Path


class NaKb:
    """Curated not-applicable corpus (grown from H1 community experience +
    the user's own outcomes). Matching a pattern short-circuits triage:
    zero LLM cost, zero noise. Entries are data — reviewed, human-merged."""

    def __init__(self, entries: list[dict]):
        self.entries = entries
        for e in self.entries:
            e["_rx"] = re.compile(e.get("regex", ""), re.I)

    @classmethod
    def load(cls, path: str | Path) -> "NaKb":
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise ValueError(f"corrupt NA knowledge base {p}: {e}") from e
        if not isinstance(data, list) or any("id" not in e for e in data):
            raise ValueError(f"invalid NA knowledge base schema in {p}")
        return cls(data)

    def match(self, check_id: str, payload_json: str) -> dict | None:
        for e in self.entries:
            ids = e.get("check_ids") or []
            if ids and check_id not in ids:
                continue
            if e["_rx"].search(payload_json) or e["_rx"].search(check_id):
                return {k: v for k, v in e.items() if not k.startswith("_")}
        return None
