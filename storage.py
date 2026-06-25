"""SQLite-backed persistence for the IP checker (local, single-user).

Two responsibilities:
1. ``ip_cache`` - memoize IPQualityScore lookups with a TTL so re-scans don't
   burn the free-tier quota and are instant.
2. ``app_state`` - a tiny key/value store used to persist the last scan results
   so a page refresh or app restart restores the table.

SQLite runs in WAL mode with a busy timeout; all writes are serialised through
a process-wide lock to avoid "database is locked" under the scan thread pool.
"""

import json
import os
import sqlite3
import threading
import time

DB_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DB_DIR, "ipchecker.db")

_write_lock = threading.Lock()


def _connect():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def init_db():
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ip_cache ("
                "ip TEXT PRIMARY KEY, payload TEXT NOT NULL, checked_at REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS app_state ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS scans ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, created_at REAL, "
                "count INTEGER, records TEXT NOT NULL, raw TEXT NOT NULL)"
            )
            conn.commit()
        finally:
            conn.close()


# ----- IP lookup cache ---------------------------------------------------
def cache_get(ip, max_age_seconds):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload, checked_at FROM ip_cache WHERE ip = ?", (ip,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    payload, checked_at = row
    if max_age_seconds is not None and (time.time() - checked_at) > max_age_seconds:
        return None
    try:
        data = json.loads(payload)
        data["cached"] = True
        return data
    except (json.JSONDecodeError, TypeError):
        return None


def cache_put(ip, data):
    payload = json.dumps({k: v for k, v in data.items() if k != "cached"})
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO ip_cache (ip, payload, checked_at) VALUES (?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET payload = excluded.payload, "
                "checked_at = excluded.checked_at",
                (ip, payload, time.time()),
            )
            conn.commit()
        finally:
            conn.close()


def cache_clear():
    with _write_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM ip_cache")
            conn.commit()
        finally:
            conn.close()


def cache_count():
    conn = _connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM ip_cache").fetchone()[0]
    finally:
        conn.close()


# ----- API call counter --------------------------------------------------
def incr_api_calls(n):
    if not n:
        return
    with _write_lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT value FROM app_state WHERE key='api_calls'").fetchone()
            current = 0
            if row:
                try:
                    current = int(json.loads(row[0]))
                except (json.JSONDecodeError, TypeError, ValueError):
                    current = 0
            current += n
            conn.execute(
                "INSERT INTO app_state (key, value) VALUES ('api_calls', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps(current),),
            )
            conn.commit()
        finally:
            conn.close()


def get_api_calls():
    try:
        return int(load_state("api_calls", 0) or 0)
    except (TypeError, ValueError):
        return 0


# ----- scan history ------------------------------------------------------
HISTORY_LIMIT = 50


def save_scan(name, records, raw):
    with _write_lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "INSERT INTO scans (name, created_at, count, records, raw) VALUES (?, ?, ?, ?, ?)",
                (name, time.time(), len(records), json.dumps(records), json.dumps(raw)),
            )
            # Prune to the most recent HISTORY_LIMIT entries.
            conn.execute(
                "DELETE FROM scans WHERE id NOT IN "
                "(SELECT id FROM scans ORDER BY created_at DESC LIMIT ?)",
                (HISTORY_LIMIT,),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def list_scans():
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, name, created_at, count FROM scans ORDER BY created_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return [{"id": r[0], "name": r[1], "created_at": r[2], "count": r[3]} for r in rows]


def get_scan(scan_id):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT records, raw FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        return {"records": json.loads(row[0]), "raw": json.loads(row[1])}
    except (json.JSONDecodeError, TypeError):
        return None


def delete_scan(scan_id):
    with _write_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()


def clear_scans():
    with _write_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scans")
            conn.commit()
        finally:
            conn.close()


# ----- key/value app state ----------------------------------------------
def save_state(key, obj):
    value = json.dumps(obj)
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO app_state (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()


def load_state(key, default=None):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT value FROM app_state WHERE key = ?", (key,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return default


def clear_state(key):
    with _write_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM app_state WHERE key = ?", (key,))
            conn.commit()
        finally:
            conn.close()
