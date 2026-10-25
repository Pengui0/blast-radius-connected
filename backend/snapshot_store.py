"""SQLite persistence for local dependency-graph snapshots."""

import json
import sqlite3
from typing import Any, Optional

from backend.config import SQLITE_DB_PATH


def _connect() -> sqlite3.Connection:
    SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(SQLITE_DB_PATH, timeout=10.0)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS graph_snapshots ("
        "name TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL "
        "DEFAULT CURRENT_TIMESTAMP)"
    )
    return connection


def read_snapshot(name: str) -> Optional[Any]:
    """Read a named snapshot, returning None when it has not been stored yet."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT payload FROM graph_snapshots WHERE name = ?", (name,)
        ).fetchone()
    return json.loads(row[0]) if row else None


def write_snapshot(name: str, snapshot: Any) -> None:
    """Atomically persist a snapshot under its cache filename."""
    payload = json.dumps(snapshot, separators=(",", ":"))
    with _connect() as connection:
        connection.execute(
            "INSERT INTO graph_snapshots (name, payload, updated_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(name) DO UPDATE SET "
            "payload = excluded.payload, updated_at = CURRENT_TIMESTAMP",
            (name, payload),
        )
