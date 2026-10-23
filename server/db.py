"""SQLite storage for alerts (stdlib only).

The columns we filter/sort on are real columns; the full alert (nested
source/target/details) is kept as JSON text in `data`, so what we hand back
is exactly the shape the sensor sent.
"""
import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        TEXT PRIMARY KEY,
    zone      TEXT NOT NULL,
    attack    TEXT NOT NULL,
    severity  TEXT NOT NULL,
    source_ip TEXT,
    timestamp TEXT NOT NULL,
    sensor    TEXT,
    country   TEXT,
    data      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_zone ON alerts(zone);
"""


def _to_alert(row) -> dict:
    alert = json.loads(row["data"])
    alert["country"] = row["country"]
    return alert


class Database:
    def __init__(self, path: str):
        self.path = path
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def insert(self, alert: dict, country=None):
        """Save an alert. Returns (alert, created). If this id was already
        stored (a sensor retrying), nothing is duplicated and created=False."""
        with self.conn() as c:
            cur = c.execute(
                """INSERT OR IGNORE INTO alerts
                   (id, zone, attack, severity, source_ip, timestamp, sensor, country, data)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (alert["id"], alert["zone"], alert["attack"], alert["severity"],
                 (alert.get("source") or {}).get("ip"), alert["timestamp"],
                 alert.get("sensor"), country, json.dumps(alert)),
            )
            created = cur.rowcount == 1
            row = c.execute("SELECT * FROM alerts WHERE id=?", (alert["id"],)).fetchone()
        return _to_alert(row), created

    def get(self, alert_id: str):
        with self.conn() as c:
            row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return _to_alert(row) if row else None

    def list(self, zone=None, severity=None, attack=None, limit=50, offset=0):
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        for col, val in (("zone", zone), ("severity", severity), ("attack", attack)):
            if val:
                q += f" AND {col}=?"
                args.append(val)
        q += " ORDER BY timestamp DESC, rowid DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self.conn() as c:
            return [_to_alert(r) for r in c.execute(q, args).fetchall()]

    def stats(self) -> dict:
        with self.conn() as c:
            total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by = lambda col: {r[0]: r[1] for r in c.execute(
                f"SELECT {col}, COUNT(*) FROM alerts GROUP BY {col}")}
            return {"total": total, "by_zone": by("zone"),
                    "by_severity": by("severity"), "by_attack": by("attack")}
