import json

import pytest

from hushhunt.triage.llm import LlmClient, TriageContractError


class _Cfg:
    def __init__(self, base_url="http://localhost:20128/v1", model="ag/gemini-3.8-flash"):
        self._d = {
            "llm.base_url": base_url,
            "llm.model": model,
            "llm.temperature": 0.0,
            "llm.prices": {"gemini-3.8-flash": [0.4, 1.6]},
        }

    def __getitem__(self, path):
        return self._d[path]

    def get(self, path, default=None):
        try:
            return self[path]
        except KeyError:
            return default

    def secret(self, name):
        return "test-key"


def _resp(payload: dict, monkeypatch):
    import httpx

    class _R:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    def fake_post(url, headers=None, json=None, timeout=None):
        assert json.get("stream") is False, "must force non-streaming (9router SSE default)"
        assert url.endswith("/chat/completions")
        return _R(payload)

    monkeypatch.setattr("hushhunt.triage.llm.httpx.post", fake_post)


def test_complete_json_sends_stream_false(monkeypatch):
    cfg = _Cfg()
    body = {
        "choices": [{"message": {"content": '{"findings": [], "dismissed": []}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    _resp(body, monkeypatch)
    out = LlmClient(cfg).complete_json("sys", "user")
    assert out == {"findings": [], "dismissed": []}


def test_complete_json_strips_code_fences(monkeypatch):
    cfg = _Cfg()
    fenced = '```json\n{"findings": [{"a": 1}]}\n```'
    body = {"choices": [{"message": {"content": fenced}}], "usage": {}}
    _resp(body, monkeypatch)
    out = LlmClient(cfg).complete_json("sys", "user")
    assert out == {"findings": [{"a": 1}]}


def test_complete_json_malformed_raises_contract(monkeypatch):
    cfg = _Cfg()
    body = {"choices": [{"message": {"content": "not json at all"}}], "usage": {}}
    _resp(body, monkeypatch)
    with pytest.raises(TriageContractError):
        LlmClient(cfg).complete_json("sys", "user")


def test_complete_json_retries_on_missing_choices(monkeypatch):
    cfg = _Cfg()
    calls = []

    class _R:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json)
        if len(calls) == 1:
            return _R({"status": "processing"})  # missing choices
        return _R({"choices": [{"message": {"content": '{"findings": []}'}}], "usage": {}})

    monkeypatch.setattr("hushhunt.triage.llm.httpx.post", fake_post)
    out = LlmClient(cfg).complete_json("sys", "user")
    assert out == {"findings": []}
    assert len(calls) == 2
