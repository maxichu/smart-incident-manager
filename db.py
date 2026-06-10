import sqlite3
import os
import json

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
    # F4: add summary column if missing
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN summary TEXT")
    except sqlite3.OperationalError:
        pass
    # F5: add category column if missing
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN category TEXT")
    except sqlite3.OperationalError:
        pass
    # F6: add severity columns if missing
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN severity TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN severity_score INTEGER")
    except sqlite3.OperationalError:
        pass
    # F7: add recommendations column if missing
    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN recommendations TEXT")
    except sqlite3.OperationalError:
        pass
    # F3: FTS5 virtual table with trigram tokenizer (external content)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS incidents_fts USING fts5(
            content,
            content='incidents',
            content_rowid='id',
            tokenize='trigram'
        )
    """)
    # F3: migrate existing incidents into FTS (idempotent)
    conn.execute("""
        INSERT OR IGNORE INTO incidents_fts(rowid, content)
        SELECT id, content FROM incidents
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
    incident_id = cursor.lastrowid
    # F3: sync to FTS index
    conn.execute(
        "INSERT INTO incidents_fts(rowid, content) VALUES (?, ?)",
        (incident_id, safe),
    )
    conn.commit()
    conn.close()
    return incident_id


def update_summary(incident_id, summary):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE incidents SET summary = ? WHERE id = ?",
        (summary, incident_id),
    )
    conn.commit()
    conn.close()


# F5: persist the classification result
def update_category(incident_id, category):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE incidents SET category = ? WHERE id = ?",
        (category, incident_id),
    )
    conn.commit()
    conn.close()


# F6: persist severity level and numeric score
def update_severity(incident_id, severity, score):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE incidents SET severity = ?, severity_score = ? WHERE id = ?",
        (severity, score, incident_id),
    )
    conn.commit()
    conn.close()


# F7: persist recommendations as JSON array
def update_recommendations(incident_id, actions):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE incidents SET recommendations = ? WHERE id = ?",
        (json.dumps(actions), incident_id),
    )
    conn.commit()
    conn.close()


# F3: full-text search with FTS5 trigram, bm25 ranking, SQLite snippet highlighting
def search_incidents(query):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    safe = "".join(c for c in query if c.isalnum() or c.isspace()).strip()
    if not safe:
        conn.close()
        return []
    rows = conn.execute("""
        SELECT
            i.id, i.category, i.severity, i.created_at,
            snippet(incidents_fts, 0, '<mark>', '</mark>', '...', 40) AS snippet
        FROM incidents_fts f
        JOIN incidents i ON f.rowid = i.id
        WHERE incidents_fts MATCH ?
        ORDER BY bm25(incidents_fts)
        LIMIT 50
    """, (safe,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_incidents():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, content, category, severity, created_at FROM incidents ORDER BY created_at DESC"
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
        "SELECT id, content, summary, category, severity, severity_score, recommendations, created_at FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    d["content"] = _sanitize(d["content"])
    if d.get("summary"):
        d["summary"] = _sanitize(d["summary"])
    # F7: parse recommendations JSON back to list
    if d.get("recommendations"):
        try:
            d["recommendations"] = json.loads(d["recommendations"])
        except (json.JSONDecodeError, TypeError):
            d["recommendations"] = []
    else:
        d["recommendations"] = []
    return d
