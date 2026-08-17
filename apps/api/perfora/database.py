from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from .domain import AuditRecord


def _create_initial_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS audits_updated_at_idx ON audits(updated_at DESC)"
    )


MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...] = (
    (1, _create_initial_schema),
)
DATABASE_SCHEMA_VERSION = MIGRATIONS[-1][0]


class AuditStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _migrate(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            applied = {
                row[0]
                for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
            }
            unsupported = [version for version in applied if version > DATABASE_SCHEMA_VERSION]
            if unsupported:
                raise RuntimeError(
                    f"Database schema {max(unsupported)} is newer than this Perfora build"
                )
            for version, migrate in MIGRATIONS:
                if version in applied:
                    continue
                migrate(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(UTC).isoformat()),
                )

    @property
    def schema_version(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()
        return int(row[0])

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
