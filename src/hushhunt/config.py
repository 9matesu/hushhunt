from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
import yaml


class Config:
    def __init__(self, data: dict, root: Path):
        self._d = data
        self.root = Path(root)
        load_dotenv(root / ".env")

    @classmethod
    def load(cls, root: str | Path = ".") -> "Config":
        root = Path(root).resolve()
        data = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))
        return cls(data, root)

    def __getitem__(self, path: str):
        cur = self._d
        for key in path.split("."):
            cur = cur[key]
        return cur

    def get(self, path: str, default=None):
        try:
            return self[path]
        except KeyError:
            return default

    def secret(self, name: str) -> str:
        val = os.environ.get(name, "")
        if not val:
            raise RuntimeError(f"missing env var {name} (copy .env.example to .env)")
        return val
