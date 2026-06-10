import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")


def _sanitize(text):
    """Remove invalid Unicode that cannot survive a UTF-8 round-trip."""
    return text.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def insert_incident(content):
    conn = sqlite3.connect(DB_PATH)
    safe = _sanitize(content)
    cursor = conn.execute(
        "INSERT INTO incidents (content) VALUES (?)",
        (safe,),
    )
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    return incident_id


def get_all_incidents():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, content, created_at FROM incidents ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        safe = _sanitize(d["content"])
        d["preview"] = safe[:100]
        d["content"] = safe
        results.append(d)
    return results


def get_incident_by_id(incident_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id, content, created_at FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    d["content"] = _sanitize(d["content"])
    return d
