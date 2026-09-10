import pytest

from hushhunt.db import open_db


def test_record_and_retrieve_procedure(tmp_path):
    from hushhunt.procedures import get_procedures_for_target, record_procedure
    conn = open_db(tmp_path / "test.db")
    record_procedure(conn, "xss_reflected", "t.invalid", "q", "json-break")
    procs = get_procedures_for_target(conn, "https://t.invalid/search")
    assert len(procs) == 1
    assert procs[0]["module"] == "xss_reflected"
    assert procs[0]["param"] == "q"


def test_success_count_increments_on_repeat(tmp_path):
    from hushhunt.procedures import get_procedures_for_target, record_procedure
    conn = open_db(tmp_path / "test.db")
    record_procedure(conn, "xss_reflected", "t.invalid", "q", "x")
    record_procedure(conn, "xss_reflected", "t.invalid", "q", "x")
    procs = get_procedures_for_target(conn, "https://t.invalid/search")
    assert procs[0]["success_count"] == 2


def test_format_procedures_for_prompt(tmp_path):
    from hushhunt.procedures import format_procedures_for_prompt
    procs = [{"module": "xss_reflected", "target_pattern": "t.invalid",
              "param": "q", "payload_template": "json-break",
              "success_count": 3, "notes": "WAF bypass"}]
    out = format_procedures_for_prompt(procs)
    assert "xss_reflected" in out
    assert "json-break" in out
