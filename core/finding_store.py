import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.findings import sort_findings
from core.models import Finding, FindingStatus, Severity


def initialize_database(db_path: str | Path) -> None:
    with connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                identity_id TEXT NOT NULL,
                resource_id TEXT,
                finding_type TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                attack_paths TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                owner TEXT,
                analyst_notes TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                risk_factors TEXT NOT NULL DEFAULT '[]',
                risk_explanation TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        ensure_column(connection, "status", "TEXT NOT NULL DEFAULT 'OPEN'")
        ensure_column(connection, "owner", "TEXT")
        ensure_column(connection, "analyst_notes", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(connection, "updated_at", "TEXT")
        ensure_column(connection, "risk_factors", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(connection, "risk_explanation", "TEXT NOT NULL DEFAULT ''")
        connection.execute(
            "UPDATE findings SET updated_at = created_at WHERE updated_at IS NULL"
        )


def save_findings(db_path: str | Path, findings: list[Finding]) -> None:
    initialize_database(db_path)

    with connect(db_path) as connection:
        for finding in findings:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO findings (
                    id,
                    title,
                    severity,
                    score,
                    identity_id,
                    resource_id,
                    finding_type,
                    description,
                    evidence,
                    recommendation,
                    attack_paths,
                    created_at,
                    status,
                    owner,
                    analyst_notes,
                    updated_at,
                    risk_factors,
                    risk_explanation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                finding_to_row(finding),
            )
            if cursor.rowcount == 1:
                insert_activity(
                    connection,
                    finding.id,
                    "CREATED",
                    "Finding created.",
                    finding.created_at,
                )


def load_findings(db_path: str | Path) -> list[Finding]:
    initialize_database(db_path)

    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                title,
                severity,
                score,
                identity_id,
                resource_id,
                finding_type,
                description,
                evidence,
                recommendation,
                attack_paths,
                created_at,
                status,
                owner,
                analyst_notes,
                updated_at,
                risk_factors,
                risk_explanation
            FROM findings
            """
        ).fetchall()

    return sort_findings([row_to_finding(row) for row in rows])


def finding_exists(db_path: str | Path, finding_id: str) -> bool:
    initialize_database(db_path)

    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()

    return row is not None


def update_finding_status(
    db_path: str | Path,
    finding_id: str,
    status: FindingStatus,
    updated_at: str | None = None,
) -> None:
    initialize_database(db_path)
    updated_at_value = get_updated_at(updated_at)

    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT status FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        connection.execute(
            """
            UPDATE findings
            SET status = ?, updated_at = ?
            WHERE id = ?
            """,
            (status.value, updated_at_value, finding_id),
        )
        if row is not None and row[0] != status.value:
            insert_activity(
                connection,
                finding_id,
                "STATUS_CHANGED",
                f"Status changed from {row[0]} to {status.value}.",
                updated_at_value,
            )


def assign_finding_owner(
    db_path: str | Path,
    finding_id: str,
    owner: str | None,
    updated_at: str | None = None,
) -> None:
    initialize_database(db_path)
    updated_at_value = get_updated_at(updated_at)

    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT owner FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        connection.execute(
            """
            UPDATE findings
            SET owner = ?, updated_at = ?
            WHERE id = ?
            """,
            (owner, updated_at_value, finding_id),
        )
        previous_owner = row[0] if row is not None else None
        if row is not None and previous_owner != owner:
            insert_activity(
                connection,
                finding_id,
                "OWNER_CHANGED",
                f"Owner changed from {previous_owner or 'Unassigned'} to {owner or 'Unassigned'}.",
                updated_at_value,
            )


def add_finding_note(
    db_path: str | Path,
    finding_id: str,
    note: str,
    updated_at: str | None = None,
) -> None:
    initialize_database(db_path)
    updated_at_value = get_updated_at(updated_at)

    findings_by_id = {finding.id: finding for finding in load_findings(db_path)}
    if finding_id not in findings_by_id:
        return

    analyst_notes = [*findings_by_id[finding_id].analyst_notes, note]
    with connect(db_path) as connection:
        connection.execute(
            """
            UPDATE findings
            SET analyst_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (json.dumps(analyst_notes), updated_at_value, finding_id),
        )
        insert_activity(
            connection,
            finding_id,
            "NOTE_ADDED",
            note,
            updated_at_value,
        )


def load_finding_activity(db_path: str | Path, finding_id: str) -> list[dict]:
    initialize_database(db_path)

    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT activity_type, message, created_at
            FROM finding_activity
            WHERE finding_id = ?
            ORDER BY created_at ASC, id ASC
            """,
            (finding_id,),
        ).fetchall()

    return [
        {
            "type": row[0],
            "message": row[1],
            "created_at": row[2],
        }
        for row in rows
    ]


def connect(db_path: str | Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(db_path))


def ensure_column(connection: sqlite3.Connection, column_name: str, definition: str) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(findings)").fetchall()
    }
    if column_name not in columns:
        connection.execute(f"ALTER TABLE findings ADD COLUMN {column_name} {definition}")


def insert_activity(
    connection: sqlite3.Connection,
    finding_id: str,
    activity_type: str,
    message: str,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO finding_activity (
            finding_id,
            activity_type,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (finding_id, activity_type, message, created_at),
    )


def finding_to_row(finding: Finding) -> tuple:
    return (
        finding.id,
        finding.title,
        finding.severity.value,
        finding.score,
        finding.identity_id,
        finding.resource_id,
        finding.finding_type,
        finding.description,
        json.dumps(finding.evidence),
        finding.recommendation,
        json.dumps(finding.attack_paths),
        finding.created_at,
        finding.status.value,
        finding.owner,
        json.dumps(finding.analyst_notes),
        finding.updated_at,
        json.dumps(finding.risk_factors),
        finding.risk_explanation,
    )


def row_to_finding(row: tuple) -> Finding:
    return Finding(
        id=row[0],
        title=row[1],
        severity=Severity(row[2]),
        score=row[3],
        identity_id=row[4],
        resource_id=row[5],
        finding_type=row[6],
        description=row[7],
        evidence=json.loads(row[8]),
        recommendation=row[9],
        attack_paths=json.loads(row[10]),
        created_at=row[11],
        status=FindingStatus(row[12]),
        owner=row[13],
        analyst_notes=json.loads(row[14]),
        updated_at=row[15],
        risk_factors=json.loads(row[16]),
        risk_explanation=row[17],
    )


def get_updated_at(updated_at: str | None) -> str:
    if updated_at is not None:
        return updated_at
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
