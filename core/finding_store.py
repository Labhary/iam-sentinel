import json
import sqlite3
from pathlib import Path

from core.findings import sort_findings
from core.models import Finding, Severity


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
                created_at TEXT NOT NULL
            )
            """
        )


def save_findings(db_path: str | Path, findings: list[Finding]) -> None:
    initialize_database(db_path)

    with connect(db_path) as connection:
        connection.executemany(
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
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [finding_to_row(finding) for finding in findings],
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
                created_at
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


def connect(db_path: str | Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(db_path))


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
    )
