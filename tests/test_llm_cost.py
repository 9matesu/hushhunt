import httpx

from hushhunt.config import Config
from hushhunt.triage.llm import LlmClient


def _cfg(tmp_path, model="ag/glm-4.6"):
    return Config({"llm": {"base_url": "http://llm.test/v1", "model": model,
                           "temperature": 0.0,
                           "prices": {"glm-4.6": [0.4, 1.6]}}}, tmp_path)


def test_usage_accumulates_with_priced_model(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_LLM_API_KEY", "k")
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"findings": [], "dismissed": []}'}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 500}})
    import hushhunt.triage.llm as L
    monkeypatch.setattr(L.httpx, "post", lambda *a, **k: httpx.Client(
        transport=httpx.MockTransport(handler)).post(*a, **k))
    client = LlmClient(_cfg(tmp_path))
    client.complete_json("s", "u")
    client.complete_json("s", "u")
    assert client.usage == {"prompt": 2000, "completion": 1000, "calls": 2,
                            "cost_usd": 2 * (1000 / 1e6 * 0.4 + 500 / 1e6 * 1.6)}
    assert round(client.usage["cost_usd"], 6) == 0.0024


def test_unknown_model_costs_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_LLM_API_KEY", "k")

    def handler(req):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
    import hushhunt.triage.llm as L
    monkeypatch.setattr(L.httpx, "post", lambda *a, **k: httpx.Client(
        transport=httpx.MockTransport(handler)).post(*a, **k))
    client = LlmClient(_cfg(tmp_path, model="zzz/unknown-9"))
    client.complete_json("s", "u")
    assert client.usage["cost_usd"] == 0.0
    assert client.usage["calls"] == 1


def test_no_usage_key_is_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_LLM_API_KEY", "k")

    def handler(req):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "{}"}}]})
    import hushhunt.triage.llm as L
    monkeypatch.setattr(L.httpx, "post", lambda *a, **k: httpx.Client(
        transport=httpx.MockTransport(handler)).post(*a, **k))
    client = LlmClient(_cfg(tmp_path))
    client.complete_json("s", "u")
    assert client.usage == {"prompt": 0, "completion": 0, "cost_usd": 0.0,
                            "calls": 1}
