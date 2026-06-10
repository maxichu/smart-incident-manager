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
        ("analyzed_at", "TIMESTAMP"),
        ("analysis_version", "TEXT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass
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


# F12: aggregate trend statistics for the dashboard.
def get_trend_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    total = conn.execute("SELECT COUNT(*) AS cnt FROM incidents").fetchone()["cnt"]
    by_category = conn.execute(
        "SELECT COALESCE(category, 'Unknown') AS category, COUNT(*) AS cnt "
        "FROM incidents GROUP BY category ORDER BY cnt DESC"
    ).fetchall()
    by_severity = conn.execute(
        "SELECT COALESCE(severity, 'Unknown') AS severity, COUNT(*) AS cnt "
        "FROM incidents GROUP BY severity "
        "ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
        "WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
    ).fetchall()
    by_week = conn.execute("""
        SELECT strftime('%Y-W%W', created_at) AS week, COUNT(*) AS cnt
        FROM incidents GROUP BY week ORDER BY week
    """).fetchall()
    conn.close()
    return {
        "total": total,
        "by_category": [dict(r) for r in by_category],
        "by_severity": [dict(r) for r in by_severity],
        "by_week": [dict(r) for r in by_week],
    }


# F12: generate ~30 sample incidents spread over 30 days for demo trends.
def load_sample_trends():
    import random
    from datetime import datetime, timedelta

    conn = sqlite3.connect(DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    if count > 15:
        conn.close()
        return

    templates = [
        ("Network", "VPN connectivity issue reported by remote users.", "Medium"),
        ("Network", "Firewall blocking legitimate traffic after update.", "High"),
        ("Network", "DNS resolution failure affecting internal services.", "Medium"),
        ("Database", "Slow query performance on production database.", "Medium"),
        ("Database", "Database replication lag exceeding threshold.", "High"),
        ("Database", "Connection pool exhausted during peak hours.", "High"),
        ("Security", "Multiple failed login attempts from external IP.", "High"),
        ("Security", "Phishing email campaign targeting employees.", "Critical"),
        ("Security", "Unauthorized access to internal file server.", "Critical"),
        ("Infrastructure", "Server CPU usage spiking intermittently.", "Medium"),
        ("Infrastructure", "Disk space reaching critical levels on log server.", "High"),
        ("Infrastructure", "Memory leak detected in production container.", "High"),
        ("Application", "API response time degraded after deployment.", "Medium"),
        ("Application", "Web service returning 500 errors intermittently.", "High"),
        ("Application", "Frontend deployment rolled back due to bug.", "Medium"),
    ]

    sev_score = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    now = datetime.now()

    for i in range(30):
        t = random.choice(templates)
        days_ago = random.randint(0, 29)
        ts = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
        content = f"[{ts}] {t[1]}"

        cursor = conn.execute(
            "INSERT INTO incidents (content, category, severity, severity_score, summary, recommendations, created_at, analyzed_at, analysis_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                content, t[0], t[2], sev_score[t[2]],
                content[:100], "[]",
                ts, ts, "1.0",
            ),
        )
        conn.execute(
            "INSERT INTO incidents_fts(rowid, content) VALUES (?, ?)",
            (cursor.lastrowid, content),
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
