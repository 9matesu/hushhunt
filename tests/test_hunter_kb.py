import pytest

from hushhunt.hunter_kb import get_techniques_for_target, list_hunter_techniques


def test_list_hunter_techniques_contains_legends():
    techs = list_hunter_techniques()
    authors = {t["author"] for t in techs}
    assert "Sam Curry" in authors
    assert "James Kettle" in authors
    assert "Frans Rosén" in authors
    assert "Orange Tsai" in authors


def test_get_techniques_for_target_recommends_403_bypass_when_forbidden():
    target_info = {"status": 403, "url": "https://t.invalid/admin", "headers": {}}
    matched = get_techniques_for_target(target_info)
    matched_names = [m["name"] for m in matched]
    assert any("403" in name or "gateway" in name.lower() for name in matched_names)


def test_get_techniques_for_target_recommends_cache_poisoning_when_cached():
    target_info = {"status": 200, "url": "https://t.invalid/home", "headers": {"X-Cache": "HIT"}}
    matched = get_techniques_for_target(target_info)
    matched_names = [m["name"] for m in matched]
    assert any("cache" in name.lower() for name in matched_names)
