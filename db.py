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
    for col, col_type in [
        ("summary", "TEXT"),
        ("category", "TEXT"),
        ("severity", "TEXT"),
        ("severity_score", "INTEGER"),
        ("recommendations", "TEXT"),
        # F10: audit metadata
        ("analyzed_at", "TIMESTAMP"),
        ("analysis_version", "TEXT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {col_type}")
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
    conn.execute(
        "INSERT INTO incidents_fts(rowid, content) VALUES (?, ?)",
        (incident_id, safe),
    )
    conn.commit()
    conn.close()
    return incident_id


# F10: centralized analysis persistence ¡ª single function replaces
# update_summary/update_category/update_severity/update_recommendations.
def save_analysis(incident_id, **kwargs):
    """Persist one or more analysis fields for an incident.  Sets analyzed_at."""
    allowed = {
        "summary", "category", "severity", "severity_score",
        "recommendations", "analysis_version",
    }
    fields = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not fields:
        return
    if "recommendations" in fields:
        fields["recommendations"] = json.dumps(fields["recommendations"])
    sets = [f"{k} = ?" for k in fields]
    values = list(fields.values())
    sets.append("analyzed_at = CURRENT_TIMESTAMP")
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?",
        values + [incident_id],
    )
    conn.commit()
    conn.close()


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
    if d.get("recommendations"):
        try:
            d["recommendations"] = json.loads(d["recommendations"])
        except (json.JSONDecodeError, TypeError):
            d["recommendations"] = []
    else:
        d["recommendations"] = []
    return d
