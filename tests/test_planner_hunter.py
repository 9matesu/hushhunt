import pytest

from hushhunt.planner import build_prompt


def test_build_prompt_includes_hunter_techniques_when_provided():
    hunter_block = "### HUNTER KNOWLEDGE BASE PLAYBOOKS:\n- Sam Curry: API Gateway 403/401 Override"
    system, user = build_prompt({"apis_seen": []}, memory_block="", hunter_block=hunter_block)
    assert "Sam Curry" in user
    assert "API Gateway" in user
