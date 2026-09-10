import pytest

from hushhunt.mutator import analyze_reflection_context, mutate_payload_for_context


def test_analyze_reflection_attribute_context():
    html = '<div><input name="q" value="hush123" class="search"></div>'
    ctx_type = analyze_reflection_context(html, "hush123")
    assert ctx_type == "html_attribute"


def test_analyze_reflection_script_context():
    html = '<script>var search = "hush123"; console.log(search);</script>'
    ctx_type = analyze_reflection_context(html, "hush123")
    assert ctx_type == "script_string"


def test_mutate_payload_for_context_fallback():
    # When LLM is None or fails, falls back to deterministic heuristic escape
    payload = mutate_payload_for_context("html_attribute", "hush123", llm=None)
    assert '">hush123"<' in payload or '"' in payload
