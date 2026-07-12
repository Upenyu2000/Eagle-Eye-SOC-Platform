from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from eagle_eye.models import Incident
from eagle_eye.paths import data_dir


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or data_dir() / "eagle_eye.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    description TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_module ON incidents(module);
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            connection.commit()

    def add_incident(self, incident: Incident) -> int:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    module, title, severity, status, description, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.module,
                    incident.title,
                    incident.severity.lower(),
                    incident.status,
                    incident.description,
                    json.dumps(incident.evidence, ensure_ascii=False, default=str),
                    incident.created_at,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def update_incident_status(self, incident_id: int, status: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, incident_id),
            )
            connection.commit()

    def dashboard_stats(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            total = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_count = connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE lower(status) != 'closed'"
            ).fetchone()[0]
            high_count = connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE lower(severity) IN ('high', 'critical')"
            ).fetchone()[0]
            module_count = connection.execute(
                "SELECT COUNT(DISTINCT module) FROM incidents"
            ).fetchone()[0]
        return {
            "total": int(total),
            "open": int(open_count),
            "high": int(high_count),
            "modules": int(module_count),
        }

    def get_setting(self, key: str, default: str = "") -> str:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row[0]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            connection.commit()

    def log_activity(self, module: str, action: str, details: str = "") -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO activity (module, action, details) VALUES (?, ?, ?)",
                (module, action, details[:4000]),
            )
            connection.commit()
