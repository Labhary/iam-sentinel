import sqlite3

from core.finding_store import (
    finding_exists,
    initialize_database,
    load_findings,
    save_findings,
)
from core.models import Finding, Severity


def test_initialize_database_creates_findings_table(tmp_path) -> None:
    db_path = tmp_path / "findings.db"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'findings'"
        ).fetchone()

    assert row == ("findings",)


def test_save_and_load_findings_persists_finding_objects(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    loaded_findings = load_findings(db_path)

    assert loaded_findings == [finding]
    assert finding_exists(db_path, "finding-001") is True
    assert finding_exists(db_path, "finding-missing") is False


def test_save_findings_prevents_duplicate_ids(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    save_findings(db_path, [finding])

    assert load_findings(db_path) == [finding]


def test_load_findings_uses_deterministic_sort_order(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    findings = [
        make_finding("finding-low", Severity.LOW, 25, "user-001"),
        make_finding("finding-high-b", Severity.HIGH, 80, "user-002"),
        make_finding("finding-critical", Severity.CRITICAL, 95, "user-003"),
        make_finding("finding-high-a", Severity.HIGH, 80, "user-004"),
    ]

    save_findings(db_path, findings)
    loaded_findings = load_findings(db_path)

    assert [finding.id for finding in loaded_findings] == [
        "finding-critical",
        "finding-high-a",
        "finding-high-b",
        "finding-low",
    ]


def make_finding(
    finding_id: str,
    severity: Severity,
    score: int,
    identity_id: str,
) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity=severity,
        score=score,
        identity_id=identity_id,
        resource_id="res-001",
        finding_type="test",
        description="Test description.",
        evidence=["Test evidence."],
        recommendation="Test recommendation.",
        attack_paths=["User -> Role -> Resource"],
        created_at="2026-05-18T00:00:00Z",
    )
