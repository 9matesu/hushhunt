from pathlib import Path

import pytest

from hushhunt.triage.na_kb import NaKb

SEED = Path(__file__).parent.parent / "seeds" / "na_kb.json"


def test_seed_loads_at_least_10():
    kb = NaKb.load(SEED)
    assert len(kb.entries) >= 10
    assert all(e["id"].startswith("NA-") for e in kb.entries)


def test_match_cookie_flag_pattern():
    kb = NaKb.load(SEED)
    hit = kb.match("passive_headers", '{"issue":"cookie_no_httponly","detail":"session cookie sid lacks HttpOnly"}')
    assert hit and hit["id"] == "NA-003"


def test_match_requires_check_id_membership():
    kb = NaKb.load(SEED)
    # regex of NA-003 is broad, but a check_id not listed must not match it
    assert kb.match("exposed_files", '{"issue":"cookie_no_httponly"}') is None


def test_no_match_returns_none():
    kb = NaKb.load(SEED)
    assert kb.match("cors_misconfig", '{"issue":"reflected_arbitrary_origin"}') is None


def test_corrupt_seed_fails_closed(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        NaKb.load(p)
    p.write_text('[{"no_id": 1}]', encoding="utf-8")
    with pytest.raises(ValueError):
        NaKb.load(p)
