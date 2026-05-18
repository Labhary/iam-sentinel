from core.models import Finding, Severity
from core.scoring import calculate_risk_score, score_to_severity, severity_to_score


def test_severity_to_score_maps_known_severities() -> None:
    assert severity_to_score(Severity.LOW) == 25
    assert severity_to_score(Severity.MEDIUM) == 50
    assert severity_to_score(Severity.HIGH) == 75
    assert severity_to_score(Severity.CRITICAL) == 95


def test_calculate_risk_score_is_deterministic() -> None:
    first_score = calculate_risk_score(
        Severity.HIGH,
        sensitive_resource=True,
        external_identity=True,
        missing_mfa=True,
    )
    second_score = calculate_risk_score(
        Severity.HIGH,
        sensitive_resource=True,
        external_identity=True,
        missing_mfa=True,
    )

    assert first_score == 90
    assert second_score == first_score


def test_score_to_severity_uses_expected_ranges() -> None:
    assert score_to_severity(25) == Severity.LOW
    assert score_to_severity(40) == Severity.MEDIUM
    assert score_to_severity(70) == Severity.HIGH
    assert score_to_severity(90) == Severity.CRITICAL


def test_finding_object_creation() -> None:
    finding = Finding(
        id="finding-001",
        title="Dormant admin retains sensitive access",
        severity=Severity.HIGH,
        score=80,
        identity_id="user-005",
        resource_id="res-role-catalog",
        finding_type="governance",
        description="Dormant identity still has access to role management.",
        evidence=["Last login is older than 90 days.", "Identity has admin role."],
        recommendation="Review the identity and remove unnecessary privileged access.",
        attack_paths=[
            "Nadia Flores -> Platform Administrators -> Platform Admin -> Manage Roles -> Role Catalog"
        ],
        created_at="2026-05-18T00:00:00Z",
    )

    assert finding.identity_id == "user-005"
    assert finding.resource_id == "res-role-catalog"
    assert finding.severity == Severity.HIGH
    assert finding.attack_paths[0].startswith("Nadia Flores")
