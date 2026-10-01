"""Independent persistent storage for the relay (one SQLite database).

The mirror lives entirely here -- the relay has no other durable state.  The
database is independent from the upstream gateway's database: nothing in this
package ever opens or writes gateway files.

Tables
------
meta        : key/value (trusted height, frontier, last trusted STH, ...)
leaves      : densely indexed verified mirror leaves (0..mirror_height-1)
tenants     : per-auditor isolated filter, cursor, active flag, own token
deliveries  : durable, byte-identical lease packages
events      : append-only observability/rejection log
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

SCHEMA_VERSION = "ar1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS leaves(
    leaf_index     INTEGER PRIMARY KEY,
    event_type     TEXT NOT NULL,
    event_key      TEXT NOT NULL UNIQUE,
    leaf_hash      TEXT NOT NULL,
    envelope_json  TEXT NOT NULL,
    incorporated_at TEXT NOT NULL,
    mirrored_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants(
    tenant_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    token_hash     TEXT NOT NULL,
    filter_json    TEXT NOT NULL,
    filter_version INTEGER NOT NULL DEFAULT 1,
    cursor         INTEGER NOT NULL DEFAULT 0,   /* first not-yet-acked seq */
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    disabled_at    TEXT
);

CREATE TABLE IF NOT EXISTS deliveries(
    delivery_id    TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    seq_start      INTEGER NOT NULL,
    seq_end        INTEGER NOT NULL,
    status         TEXT NOT NULL,                 /* open | acked */
    attempt        INTEGER NOT NULL DEFAULT 1,
    lease_holder   TEXT,
    lease_token_hash TEXT,
    lease_expires_at TEXT,
    payload_blob   BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL,
    sth_tree_size  INTEGER NOT NULL,
    filter_version INTEGER NOT NULL,
    match_count    INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    delivered_at   TEXT,
    acked_at       TEXT,
    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_tenant
    ON deliveries(tenant_id, status);

CREATE TABLE IF NOT EXISTS events(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    category  TEXT NOT NULL,
    kind      TEXT NOT NULL,
    tenant_id TEXT,
    detail_json TEXT NOT NULL
);
"""

META_HEIGHT = "mirror_height"
META_FRONTIER = "merkle_frontier"      # JSON list of hex hashes, descending widths
META_STH = "last_trusted_sth"          # JSON of the last verified tree head doc
META_STH_AT = "last_trusted_sth_at"
META_UPSTREAM = "upstream_state"       # JSON: status/failure bookkeeping
META_SYNC = "sync_cursor"              # always equals a fully committed height


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    if conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone() is None:
        conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                     (SCHEMA_VERSION,))
    if conn.execute("SELECT value FROM meta WHERE key=?", (META_HEIGHT,)).fetchone() is None:
        conn.execute("INSERT INTO meta(key, value) VALUES(?, '0')", (META_HEIGHT,))
    if conn.execute("SELECT value FROM meta WHERE key=?",
                    (META_FRONTIER,)).fetchone() is None:
        conn.execute("INSERT INTO meta(key, value) VALUES(?, '[]')",
                     (META_FRONTIER,))


# --------------------------------------------------------------------------- #
# tiny typed helpers
# --------------------------------------------------------------------------- #

class KV:
    """Typed key/value access over the meta table (JSON values)."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def set(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, sort_keys=True, ensure_ascii=False)))


def now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
