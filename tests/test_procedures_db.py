import pytest

from hushhunt.db import open_db


def test_procedures_schema_migration(tmp_path):
    conn = open_db(tmp_path / "test_proc.db")
    conn.execute(
        "INSERT INTO procedures(topic, target_pattern, payload_template, notes, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?)",
        ("xss_bypass", "*.target.com", "'>marker<", "Cloudflare WAF", "2026-09-10", "2026-09-10")
    )
    conn.commit()
    row = conn.execute("SELECT * FROM procedures WHERE topic='xss_bypass'").fetchone()
    assert row["target_pattern"] == "*.target.com"
    assert row["payload_template"] == "'>marker<"
    assert row["success_count"] == 1
