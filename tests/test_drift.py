import sqlite3
import pytest

from hushhunt.drift import check_drift, init_drift_table


def test_asset_drift_detection(tmp_path):
    db_path = tmp_path / "drift.db"
    conn = sqlite3.connect(db_path)
    init_drift_table(conn)

    # First observation (baseline)
    changed, note = check_drift(conn, "https://t.invalid/app", status=200, content="v1.0")
    assert changed is False
    assert note == "baseline"

    # Second observation (identical)
    changed, note = check_drift(conn, "https://t.invalid/app", status=200, content="v1.0")
    assert changed is False
    assert note == "unchanged"

    # Third observation (status changed)
    changed, note = check_drift(conn, "https://t.invalid/app", status=500, content="v1.0")
    assert changed is True
    assert "status changed" in note

    # Fourth observation (content hash changed)
    changed, note = check_drift(conn, "https://t.invalid/app", status=200, content="v2.0 deploy!")
    assert changed is True
    assert "content changed" in note
