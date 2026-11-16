"""SQLite WAL storage and a bounded, durable sensor outbox."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from netguard.alerts import now, validate


class EventStore:
    def __init__(self, path, max_events=100000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_events = max_events
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, id TEXT UNIQUE, source TEXT, decision TEXT, run_id TEXT, stored_at TEXT, payload TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_run ON events(run_id, seq)")
        self.db.execute("CREATE TABLE IF NOT EXISTS quarantine (seq INTEGER PRIMARY KEY, received_at TEXT, source TEXT, reason TEXT, payload TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS diagnostics (sensor TEXT PRIMARY KEY, updated REAL, payload TEXT)")
        self.db.commit()

    def count(self, name, amount=1):
        with self.lock, self.db:
            self.db.execute("INSERT INTO counters VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (name, amount))

    def put(self, event):
        return self.put_many([event])[0]

    def put_many(self, events):
        if not isinstance(events, list) or not 1 <= len(events) <= 64:
            raise ValueError("Expected 1..64 normalized events")
        prepared = [(validate(event), json.dumps({**event, "processing_status": "stored"}, allow_nan=False))
                    for event in events]
        inserted = []
        with self.lock, self.db:
            for event, payload in prepared:
                cursor = self.db.execute(
                    "INSERT OR IGNORE INTO events(id, source, decision, run_id, stored_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
                    (event["alert_id"], event["event_source"], event["decision"], event["run_id"], now(), payload),
                )
                inserted.append(cursor.rowcount == 1)
            if any(inserted):
                deleted = self.db.execute(
                    "DELETE FROM events WHERE seq <= COALESCE((SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?), -1)",
                    (self.max_events,),
                ).rowcount
                if deleted:
                    self.db.execute("INSERT INTO counters VALUES ('retention_deleted', ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (deleted,))
        return inserted

    def quarantine(self, raw, source, reason):
        with self.lock, self.db:
            self.db.execute("INSERT INTO quarantine(received_at, source, reason, payload) VALUES (?, ?, ?, ?)",
                            (now(), source, reason, raw[:65507]))
            self.db.execute("DELETE FROM quarantine WHERE seq <= COALESCE((SELECT seq FROM quarantine ORDER BY seq DESC LIMIT 1 OFFSET ?), -1)", (1000,))
        self.count("quarantined")

    def query(self, limit=100, after=0, source=None, run_id=None, before=None):
        clauses, parameters = ["seq > ?"], [after]
        for name, value in (("source", source), ("run_id", run_id)):
            if value is not None:
                clauses.append(f"{name} = ?")
                parameters.append(value)
        if before is not None:
            clauses.append("seq < ?")
            parameters.append(int(before))
        parameters.append(max(1, min(int(limit), 1000)))
        with self.lock:
            rows = self.db.execute(f"SELECT seq, stored_at, payload FROM events WHERE {' AND '.join(clauses)} ORDER BY seq DESC LIMIT ?", parameters).fetchall()
        return [{"sequence": seq, "stored_at": timestamp, **json.loads(payload)} for seq, timestamp, payload in rows]

    def summary(self):
        with self.lock:
            counts = self.db.execute("SELECT source, decision, count(*) FROM events GROUP BY source, decision").fetchall()
            counters = dict(self.db.execute("SELECT name, value FROM counters"))
            diagnostics = {name: {"updated_unix": updated, **json.loads(payload)}
                           for name, updated, payload in self.db.execute("SELECT sensor, updated, payload FROM diagnostics")}
        return {"counts": [{"source": source, "decision": decision, "count": count} for source, decision, count in counts],
                "counters": counters, "sensors": diagnostics}

    def diagnostic(self, name, payload):
        with self.lock, self.db:
            self.db.execute("INSERT INTO diagnostics VALUES (?, ?, ?) ON CONFLICT(sensor) DO UPDATE SET updated=excluded.updated,payload=excluded.payload",
                            (name, time.time(), json.dumps(payload, allow_nan=False)))

    def close(self):
        with self.lock:
            self.db.close()


class Outbox:
    def __init__(self, path, max_events=10000):
        self.lock = threading.RLock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, payload TEXT)")
        self.db.commit()
        self.max_events = max_events

    def put(self, event):
        self.put_many([event])

    def put_many(self, events):
        if not isinstance(events, list) or not 1 <= len(events) <= 256:
            raise ValueError("Outbox batch must contain 1..256 events")
        identifiers = {event["alert_id"] for event in events}
        placeholders = ",".join("?" for _ in identifiers)
        prepared = [(event["alert_id"], json.dumps(event, allow_nan=False)) for event in events]
        with self.lock, self.db:
            existing = {row[0] for row in self.db.execute(f"SELECT id FROM pending WHERE id IN ({placeholders})", tuple(identifiers))}
            if self.db.execute("SELECT count(*) FROM pending").fetchone()[0] + len(identifiers - existing) > self.max_events:
                raise OverflowError("Durable outbox is full")
            self.db.executemany("INSERT OR IGNORE INTO pending VALUES (?, ?)", prepared)

    def pending(self, limit=100):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM pending ORDER BY rowid LIMIT ?", (limit,))]

    def ack(self, identifier):
        self.ack_many([identifier])

    def ack_many(self, identifiers):
        if not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 256:
            raise ValueError("Acknowledgment batch must contain 1..256 IDs")
        placeholders = ",".join("?" for _ in identifiers)
        with self.lock, self.db:
            self.db.execute(f"DELETE FROM pending WHERE id IN ({placeholders})", identifiers)

    def size(self):
        with self.lock:
            return self.db.execute("SELECT count(*) FROM pending").fetchone()[0]

    def close(self):
        with self.lock:
            self.db.close()
