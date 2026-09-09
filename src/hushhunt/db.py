from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS programs(
  id TEXT PRIMARY KEY, platform TEXT, name TEXT, url TEXT,
  safe_harbor TEXT, max_bounty INTEGER, avg_resolution_h REAL,
  created_at_remote TEXT, policy_text TEXT, scope_json TEXT, synced_at TEXT);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT, asset_type TEXT,
  identifier TEXT, origin TEXT,
  UNIQUE(program_id, asset_type, identifier));
CREATE TABLE IF NOT EXISTS request_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT, ts TEXT,
  url TEXT, method TEXT, status INTEGER, ms INTEGER);
CREATE TABLE IF NOT EXISTS signals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT, asset TEXT,
  check_id TEXT, wstg TEXT, severity_hint TEXT, payload_json TEXT,
  evidence_dir TEXT, created_at TEXT,
  UNIQUE(asset, check_id, payload_json));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, signal_id INTEGER, stage TEXT,
  confidence REAL, report_path TEXT, outcome TEXT, detail_json TEXT,
  updated_at TEXT);
CREATE TABLE IF NOT EXISTS weights(
  check_id TEXT PRIMARY KEY, precision_ewma REAL, n INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS playbook(
  id INTEGER PRIMARY KEY CHECK(id=1), text TEXT, version INTEGER, updated_at TEXT);
"""

# v2 migrations, numbered via PRAGMA user_version (starts at 0 on fresh DBs).
MIGRATIONS = [
    """CREATE TABLE IF NOT EXISTS grants(
         id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT, module TEXT,
         scope TEXT, max_requests INTEGER, expires_at TEXT, signed TEXT);""",
    "ALTER TABLE request_log ADD COLUMN kind TEXT DEFAULT 'passive';",
    "ALTER TABLE programs ADD COLUMN risk_cap TEXT DEFAULT 'passive';",
    """CREATE TABLE IF NOT EXISTS poc_scripts(
         id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER, code TEXT,
         language TEXT DEFAULT 'python', ok_last_run INTEGER, ran_at TEXT);""",
    """CREATE TABLE IF NOT EXISTS demoted(
         module TEXT PRIMARY KEY, until TEXT, reason TEXT);""",
    """CREATE TABLE IF NOT EXISTS params_seen(
         program_id TEXT, url TEXT, param TEXT, source TEXT,
         UNIQUE(program_id, url, param));""",
    "ALTER TABLE params_seen ADD COLUMN sample_url TEXT;",
    "ALTER TABLE params_seen ADD COLUMN sample_value TEXT;",
]


def migrate(conn: sqlite3.Connection) -> None:
    v = conn.execute("PRAGMA user_version").fetchone()[0]
    while v < len(MIGRATIONS):
        try:
            conn.executescript(MIGRATIONS[v])
        except sqlite3.OperationalError:   # e.g. duplicate ADD COLUMN on racy open
            pass
        v += 1
        conn.execute(f"PRAGMA user_version={v}")
        conn.commit()


def open_db(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA_SQL)
    migrate(conn)
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_program(conn: sqlite3.Connection, p: dict) -> None:
    conn.execute(
        """INSERT INTO programs(id,platform,name,url,safe_harbor,max_bounty,
             avg_resolution_h,created_at_remote,policy_text,scope_json,synced_at)
           VALUES(:id,:platform,:name,:url,:safe_harbor,:max_bounty,
             :avg_resolution_h,:created_at_remote,:policy_text,:scope_json,:synced_at)
           ON CONFLICT(id) DO UPDATE SET
             name=excluded.name, url=excluded.url, safe_harbor=excluded.safe_harbor,
             max_bounty=excluded.max_bounty, avg_resolution_h=excluded.avg_resolution_h,
             created_at_remote=excluded.created_at_remote, policy_text=excluded.policy_text,
             scope_json=excluded.scope_json, synced_at=excluded.synced_at""",
        {**p, "synced_at": _now()})
    conn.commit()


def add_asset(conn: sqlite3.Connection, program_id: str, asset_type: str,
              identifier: str, origin: str) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO assets(program_id,asset_type,identifier,origin) VALUES(?,?,?,?)",
        (program_id, asset_type, identifier, origin))
    conn.commit()
    return cur.rowcount == 1


def log_request(conn: sqlite3.Connection, program_id: str, ts: str, url: str,
                method: str, status: int, ms: int, kind: str = "passive") -> None:
    conn.execute(
        "INSERT INTO request_log(program_id,ts,url,method,status,ms,kind) VALUES(?,?,?,?,?,?,?)",
        (program_id, ts, url, method, status, ms, kind))
    conn.commit()


def count_requests_today(conn: sqlite3.Connection, program_id: str,
                         kind: str | None = None) -> int:
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if kind is None:
        row = conn.execute(
            "SELECT COUNT(*) c FROM request_log WHERE program_id=? AND ts LIKE ?",
            (program_id, day + "%")).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) c FROM request_log WHERE program_id=? AND kind=? AND ts LIKE ?",
            (program_id, kind, day + "%")).fetchone()
    return row["c"]


def get_grant_module(conn: sqlite3.Connection, grant_id: int) -> str | None:
    row = conn.execute("SELECT module FROM grants WHERE id=?", (grant_id,)).fetchone()
    return row["module"] if row else None


def add_signal(conn: sqlite3.Connection, program_id: str, asset: str, check_id: str,
               wstg: str, severity_hint: str, payload_json: str, evidence_dir: str) -> int | None:
    cur = conn.execute(
        """INSERT OR IGNORE INTO signals(program_id,asset,check_id,wstg,severity_hint,
             payload_json,evidence_dir,created_at) VALUES(?,?,?,?,?,?,?,?)""",
        (program_id, asset, check_id, wstg, severity_hint, payload_json, evidence_dir, _now()))
    conn.commit()
    return cur.lastrowid if cur.rowcount == 1 else None


def set_stage(conn: sqlite3.Connection, finding_id: int, stage: str,
              confidence: float | None = None, report_path: str | None = None,
              outcome: str | None = None) -> None:
    conn.execute(
        """UPDATE findings SET stage=?,
             confidence=COALESCE(?,confidence),
             report_path=COALESCE(?,report_path),
             outcome=COALESCE(?,outcome), updated_at=? WHERE id=?""",
        (stage, confidence, report_path, outcome, _now(), finding_id))
    conn.commit()


def bump_weight(conn: sqlite3.Connection, check_id: str, accepted: bool) -> float:
    row = conn.execute("SELECT precision_ewma w FROM weights WHERE check_id=?",
                       (check_id,)).fetchone()
    old = row["w"] if row else 0.5
    new = round(0.8 * old + 0.2 * (1.0 if accepted else 0.0), 6)
    conn.execute(
        """INSERT INTO weights(check_id,precision_ewma,n,updated_at) VALUES(?,?,1,?)
           ON CONFLICT(check_id) DO UPDATE SET precision_ewma=?, n=n+1, updated_at=?""",
        (check_id, new, _now(), new, _now()))
    conn.commit()
    return new


def get_weights(conn: sqlite3.Connection) -> dict[str, float]:
    return {r["check_id"]: r["precision_ewma"]
            for r in conn.execute("SELECT check_id, precision_ewma FROM weights")}


def load_playbook(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT text, version, updated_at FROM playbook WHERE id=1").fetchone()
    return dict(row) if row else None


def save_playbook(conn: sqlite3.Connection, text: str) -> int:
    row = conn.execute("SELECT version FROM playbook WHERE id=1").fetchone()
    version = (row["version"] + 1) if row else 1
    conn.execute(
        """INSERT INTO playbook(id,text,version,updated_at) VALUES(1,?,?,?)
           ON CONFLICT(id) DO UPDATE SET text=excluded.text, version=excluded.version,
             updated_at=excluded.updated_at""",
        (text, version, _now()))
    conn.commit()
    return version
