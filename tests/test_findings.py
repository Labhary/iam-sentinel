from core.findings import (
    group_findings_by_severity,
    sort_findings,
    summarize_findings,
)
from core.models import Finding, Severity


def test_sort_findings_is_deterministic() -> None:
    findings = [
        make_finding("finding-low", Severity.LOW, 25, "user-001"),
        make_finding("finding-high-b", Severity.HIGH, 80, "user-002"),
        make_finding("finding-critical", Severity.CRITICAL, 95, "user-003"),
        make_finding("finding-high-a", Severity.HIGH, 80, "user-004"),
        make_finding("finding-medium", Severity.MEDIUM, 50, "user-005"),
        make_finding("finding-high-c", Severity.HIGH, 90, "user-006"),
    ]

    sorted_findings = sort_findings(findings)

    assert [finding.id for finding in sorted_findings] == [
        "finding-critical",
        "finding-high-c",
        "finding-high-a",
        "finding-high-b",
        "finding-medium",
        "finding-low",
    ]


def test_group_findings_by_severity_groups_sorted_findings() -> None:
    findings = [
        make_finding("finding-low", Severity.LOW, 25, "user-001"),
        make_finding("finding-high-b", Severity.HIGH, 80, "user-002"),
        make_finding("finding-high-a", Severity.HIGH, 80, "user-003"),
    ]

    grouped = group_findings_by_severity(findings)

    assert [finding.id for finding in grouped[Severity.HIGH]] == [
        "finding-high-a",
        "finding-high-b",
    ]
    assert [finding.id for finding in grouped[Severity.LOW]] == ["finding-low"]
    assert grouped[Severity.CRITICAL] == []
    assert grouped[Severity.MEDIUM] == []


def test_summarize_findings_returns_deterministic_metrics() -> None:
    findings = [
        make_finding("finding-001", Severity.HIGH, 85, "user-001"),
        make_finding("finding-002", Severity.HIGH, 90, "user-001"),
        make_finding("finding-003", Severity.MEDIUM, 50, "user-002"),
    ]

    summary = summarize_findings(findings)

    assert summary["total_findings"] == 3
    assert summary["count_per_severity"] == {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 0,
    }
    assert summary["highest_score"] == 90
    assert summary["affected_identities_count"] == 2


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
        resource_id=None,
        finding_type="test",
        description="Test description.",
        evidence=["Test evidence."],
        recommendation="Test recommendation.",
        attack_paths=[],
        created_at="2026-05-18T00:00:00Z",
    )
