import sqlite3

from core.finding_store import (
    add_finding_note,
    assign_finding_owner,
    finding_exists,
    initialize_database,
    load_finding_activity,
    load_finding_lifecycle_history,
    load_findings,
    save_findings,
    update_finding_status,
)
from core.models import Finding, FindingStatus, Severity


def test_initialize_database_creates_findings_table(tmp_path) -> None:
    db_path = tmp_path / "findings.db"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'findings'"
        ).fetchone()

    assert row == ("findings",)

    with sqlite3.connect(db_path) as connection:
        activity_row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'finding_activity'"
        ).fetchone()

    assert activity_row == ("finding_activity",)


def test_save_and_load_findings_persists_finding_objects(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    loaded_findings = load_findings(db_path)

    assert loaded_findings == [finding]
    assert finding_exists(db_path, "finding-001") is True
    assert finding_exists(db_path, "finding-missing") is False


def test_new_findings_use_default_workflow_fields() -> None:
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    assert finding.status == FindingStatus.OPEN
    assert finding.owner is None
    assert finding.analyst_notes == []
    assert finding.updated_at == finding.created_at
    assert finding.risk_factors == []
    assert finding.risk_explanation == ""


def test_save_and_load_findings_persists_risk_explanation_fields(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = Finding(
        id="finding-risk",
        title="Test finding",
        severity=Severity.HIGH,
        score=85,
        identity_id="user-001",
        resource_id="res-001",
        finding_type="test",
        description="Test description.",
        evidence=["Test evidence."],
        recommendation="Test recommendation.",
        attack_paths=["User -> Role -> Resource"],
        created_at="2026-05-18T00:00:00Z",
        risk_factors=["Missing MFA", "Sensitive resource access"],
        risk_explanation="Salma Benali was rated at this risk level because of missing MFA and sensitive access.",
    )

    save_findings(db_path, [finding])
    loaded_finding = load_findings(db_path)[0]

    assert loaded_finding.risk_factors == ["Missing MFA", "Sensitive resource access"]
    assert loaded_finding.risk_explanation == (
        "Salma Benali was rated at this risk level because of missing MFA and sensitive access."
    )


def test_save_findings_prevents_duplicate_ids(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    save_findings(db_path, [finding])

    assert load_findings(db_path) == [finding]
    assert load_finding_activity(db_path, "finding-001") == [
        {
            "type": "CREATED",
            "message": "Finding created.",
            "created_at": "2026-05-18T00:00:00Z",
        }
    ]


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


def test_update_finding_status_persists_status_and_updated_at(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    update_finding_status(
        db_path,
        "finding-001",
        FindingStatus.UNDER_REVIEW,
        note="Investigation started.",
        updated_at="2026-05-19T00:00:00Z",
    )

    loaded_finding = load_findings(db_path)[0]
    assert loaded_finding.status == FindingStatus.UNDER_REVIEW
    assert loaded_finding.analyst_notes == ["Investigation started."]
    assert loaded_finding.updated_at == "2026-05-19T00:00:00Z"
    assert load_finding_lifecycle_history(db_path, "finding-001") == [
        {
            "finding_id": "finding-001",
            "previous_status": "OPEN",
            "new_status": "UNDER_REVIEW",
            "note": "Investigation started.",
            "timestamp": "2026-05-19T00:00:00Z",
        }
    ]


def test_assign_finding_owner_persists_owner_and_updated_at(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    assign_finding_owner(
        db_path,
        "finding-001",
        "analyst@example.local",
        updated_at="2026-05-20T00:00:00Z",
    )

    loaded_finding = load_findings(db_path)[0]
    assert loaded_finding.owner == "analyst@example.local"
    assert loaded_finding.updated_at == "2026-05-20T00:00:00Z"


def test_add_finding_note_persists_notes_and_updated_at(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    add_finding_note(
        db_path,
        "finding-001",
        "Confirmed with identity owner.",
        updated_at="2026-05-21T00:00:00Z",
    )
    add_finding_note(
        db_path,
        "finding-001",
        "Access removal requested.",
        updated_at="2026-05-22T00:00:00Z",
    )

    loaded_finding = load_findings(db_path)[0]
    assert loaded_finding.analyst_notes == [
        "Confirmed with identity owner.",
        "Access removal requested.",
    ]
    assert loaded_finding.updated_at == "2026-05-22T00:00:00Z"


def test_finding_activity_records_workflow_changes(tmp_path) -> None:
    db_path = tmp_path / "findings.db"
    finding = make_finding("finding-001", Severity.HIGH, 85, "user-001")

    save_findings(db_path, [finding])
    update_finding_status(
        db_path,
        "finding-001",
        FindingStatus.UNDER_REVIEW,
        note="Investigation started.",
        updated_at="2026-05-19T00:00:00Z",
    )
    assign_finding_owner(
        db_path,
        "finding-001",
        "analyst@example.local",
        updated_at="2026-05-20T00:00:00Z",
    )
    add_finding_note(
        db_path,
        "finding-001",
        "Confirmed with identity owner.",
        updated_at="2026-05-21T00:00:00Z",
    )

    assert load_finding_activity(db_path, "finding-001") == [
        {
            "type": "CREATED",
            "message": "Finding created.",
            "created_at": "2026-05-18T00:00:00Z",
        },
        {
            "type": "STATUS_CHANGED",
            "message": "Status changed from OPEN to UNDER_REVIEW.",
            "created_at": "2026-05-19T00:00:00Z",
        },
        {
            "type": "OWNER_CHANGED",
            "message": "Owner changed from Unassigned to analyst@example.local.",
            "created_at": "2026-05-20T00:00:00Z",
        },
        {
            "type": "NOTE_ADDED",
            "message": "Confirmed with identity owner.",
            "created_at": "2026-05-21T00:00:00Z",
        },
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
