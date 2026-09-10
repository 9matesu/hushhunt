"""Asset drift & change detection engine.

Tracks status codes, headers, and SHA256 content hashes of endpoints in SQLite
to immediately flag fresh deployments, changes, and route drift for targeted AI auditing.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time


def init_drift_table(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS asset_snapshots (
                url TEXT PRIMARY KEY,
                status INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                last_seen_at REAL NOT NULL
            )
        """)


def check_drift(conn: sqlite3.Connection, url: str, status: int,
                content: str) -> tuple[bool, str]:
    content_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    now = time.time()

    cur = conn.cursor()
    cur.execute("SELECT status, content_hash FROM asset_snapshots WHERE url = ?", (url,))
    row = cur.fetchone()

    if row is None:
        with conn:
            conn.execute(
                "INSERT INTO asset_snapshots (url, status, content_hash, last_seen_at) VALUES (?, ?, ?, ?)",
                (url, status, content_hash, now)
            )
        return False, "baseline"

    old_status, old_hash = row

    reasons = []
    if old_status != status:
        reasons.append(f"status changed from {old_status} to {status}")
    if old_hash != content_hash:
        reasons.append("content changed")

    if reasons:
        with conn:
            conn.execute(
                "UPDATE asset_snapshots SET status = ?, content_hash = ?, last_seen_at = ? WHERE url = ?",
                (status, content_hash, now, url)
            )
        return True, " and ".join(reasons)

    with conn:
        conn.execute("UPDATE asset_snapshots SET last_seen_at = ? WHERE url = ?", (now, url))
    return False, "unchanged"
