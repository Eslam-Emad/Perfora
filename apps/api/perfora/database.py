from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock

from .domain import AuditRecord


class AuditStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def save(self, audit: AuditRecord) -> None:
        payload = audit.model_dump_json()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audits(id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (audit.id, payload, audit.updated_at.isoformat()),
            )

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM audits WHERE id = ?", (audit_id,)
            ).fetchone()
        return AuditRecord.model_validate(json.loads(row[0])) if row else None

    def list(self) -> list[AuditRecord]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM audits ORDER BY updated_at DESC"
            ).fetchall()
        return [AuditRecord.model_validate(json.loads(row[0])) for row in rows]
