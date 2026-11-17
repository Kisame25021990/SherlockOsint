from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from app.api.schemas import ModuleResult, Scan, ScanSummary

_lock = threading.Lock()
_connection: sqlite3.Connection | None = None


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def get_connection() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        raise RuntimeError("La base de données n'est pas initialisée")
    return _connection


def init_db(path: Path) -> None:
    global _connection
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            modules TEXT NOT NULL,
            options TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS results (
            scan_id TEXT NOT NULL,
            module TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, module),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
        """
    )
    connection.commit()
    with _lock:
        _connection = connection


def create_scan(
    scan_id: str,
    target: str,
    modules: list[str],
    options: dict,
    status: str,
    created_at: str,
) -> None:
    with _lock:
        get_connection().execute(
            "INSERT INTO scans (id, target, modules, options, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                target,
                json.dumps(modules),
                json.dumps(options),
                status,
                created_at,
                created_at,
            ),
        )
        get_connection().commit()


def update_scan_status(scan_id: str, status: str) -> None:
    with _lock:
        get_connection().execute(
            "UPDATE scans SET status = ?, updated_at = ? WHERE id = ?",
            (status, utc_now(), scan_id),
        )
        get_connection().commit()


def recover_interrupted_scans() -> int:
    with _lock:
        connection = get_connection()
        rows = connection.execute(
            "SELECT scan_id, module, payload FROM results WHERE status = ?", ("running",)
        ).fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
            payload["status"] = "error"
            payload["error"] = "Scan interrompu au redémarrage du serveur"
            connection.execute(
                "UPDATE results SET status = ?, payload = ?, updated_at = ? "
                "WHERE scan_id = ? AND module = ?",
                ("error", json.dumps(payload), utc_now(), row["scan_id"], row["module"]),
            )
        cursor = connection.execute(
            "UPDATE scans SET status = ?, updated_at = ? WHERE status = ?",
            ("error", utc_now(), "running"),
        )
        connection.commit()
    return cursor.rowcount


def save_result(scan_id: str, result: ModuleResult) -> None:
    with _lock:
        get_connection().execute(
            "INSERT INTO results (scan_id, module, target, status, payload, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(scan_id, module) DO UPDATE SET "
            "target = excluded.target, status = excluded.status, "
            "payload = excluded.payload, updated_at = excluded.updated_at",
            (
                scan_id,
                result.module,
                result.target,
                result.status,
                result.model_dump_json(),
                utc_now(),
            ),
        )
        get_connection().commit()


def get_scan(scan_id: str) -> Scan | None:
    with _lock:
        scan_row = (
            get_connection().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        )
        if scan_row is None:
            return None
        result_rows = (
            get_connection()
            .execute(
                "SELECT payload FROM results WHERE scan_id = ? ORDER BY updated_at, module",
                (scan_id,),
            )
            .fetchall()
        )

    return Scan(
        id=scan_row["id"],
        target=scan_row["target"],
        modules=json.loads(scan_row["modules"]),
        options=json.loads(scan_row["options"]),
        status=scan_row["status"],
        created_at=scan_row["created_at"],
        updated_at=scan_row["updated_at"],
        results=[ModuleResult.model_validate_json(row["payload"]) for row in result_rows],
    )


def list_scans(limit: int = 50, offset: int = 0) -> list[ScanSummary]:
    with _lock:
        rows = (
            get_connection()
            .execute(
                "SELECT s.*, COUNT(r.module) AS results_count FROM scans s "
                "LEFT JOIN results r ON r.scan_id = s.id "
                "GROUP BY s.id ORDER BY s.created_at DESC, s.rowid DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            .fetchall()
        )
    return [
        ScanSummary(
            id=row["id"],
            target=row["target"],
            modules=json.loads(row["modules"]),
            status=row["status"],
            created_at=row["created_at"],
            results_count=row["results_count"],
        )
        for row in rows
    ]


def delete_scan(scan_id: str) -> bool:
    with _lock:
        cursor = get_connection().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        get_connection().commit()
    return cursor.rowcount > 0
