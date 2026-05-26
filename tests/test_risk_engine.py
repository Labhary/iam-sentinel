from dataclasses import replace
from datetime import date
from pathlib import Path

from core.graph_builder import build_identity_graph
from core.loader import load_iam_data
from core.models import IAMData, Severity, User
from core.risk_engine import (
    detect_dormant_privileged_accounts,
    detect_external_identities_with_sensitive_access,
    detect_privileged_accounts_without_mfa,
    detect_service_accounts_with_sensitive_access,
    detect_toxic_permission_combinations,
    detect_wildcard_or_admin_permissions,
    run_all_detections,
)


SAMPLE_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
FIXED_ANALYSIS_DATE = date(2026, 5, 18)


def load_sample_context():
    iam_data = load_iam_data(SAMPLE_DATA_PATH)
    graph = build_identity_graph(iam_data)
    return iam_data, graph


def test_detect_privileged_accounts_without_mfa_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_privileged_accounts_without_mfa(iam_data, graph)

    assert [finding.id for finding in findings] == [
        "finding-mfa-user-005",
        "finding-mfa-user-007",
        "finding-mfa-user-011",
    ]
    findings_by_id = {finding.id: finding for finding in findings}
    finding = findings_by_id["finding-mfa-user-005"]
    assert finding.identity_id == "user-005"
    assert finding.severity == Severity.HIGH
    assert finding.score == 85
    assert "MFA is disabled." in finding.evidence
    assert any("Nadia El Fassi" in path for path in finding.attack_paths)


def test_detect_dormant_privileged_accounts_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_dormant_privileged_accounts(
        iam_data,
        graph,
        analysis_date=FIXED_ANALYSIS_DATE,
    )

    assert [finding.id for finding in findings] == [
        "finding-dormant-user-005",
        "finding-dormant-user-010",
    ]
    finding = findings[0]
    assert finding.id == "finding-dormant-user-005"
    assert finding.identity_id == "user-005"
    assert finding.score == 85
    assert "Identity has been dormant for 258 days." in finding.evidence
    assert finding.attack_paths


def test_detect_external_identities_with_sensitive_access_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_external_identities_with_sensitive_access(iam_data, graph)

    assert [finding.id for finding in findings] == [
        "finding-external-sensitive-user-004",
        "finding-external-sensitive-user-008",
    ]
    finding = findings[0]
    assert finding.id == "finding-external-sensitive-user-004"
    assert finding.identity_id == "user-004"
    assert finding.score == 90
    assert finding.resource_id == "res-customer-database"
    assert "Identity is marked as external." in finding.evidence
    assert any("Lucas Meyer" in path for path in finding.attack_paths)


def test_detect_service_accounts_with_sensitive_access_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_service_accounts_with_sensitive_access(iam_data, graph)

    assert [finding.id for finding in findings] == [
        "finding-service-sensitive-user-006",
        "finding-service-sensitive-user-009",
    ]
    finding = findings[0]
    assert finding.id == "finding-service-sensitive-user-006"
    assert finding.identity_id == "user-006"
    assert finding.resource_id == "res-payroll-system"
    assert finding.severity == Severity.HIGH
    assert finding.score == 85
    assert "Identity is marked as a service account." in finding.evidence
    assert any("Payroll Reconciliation Bot" in path for path in finding.attack_paths)
    assert any("Payroll Ledger System" in path for path in finding.attack_paths)


def test_detect_service_accounts_with_sensitive_access_escalates_privileged_access() -> None:
    iam_data = load_sample_with_service_account_admin_role()
    graph = build_identity_graph(iam_data)

    findings = detect_service_accounts_with_sensitive_access(iam_data, graph)

    assert len(findings) == 2
    finding = next(finding for finding in findings if finding.id == "finding-service-sensitive-user-006")
    assert finding.severity == Severity.CRITICAL
    assert finding.score == 100
    assert "Service account has privileged admin, manage, or administer capability." in finding.evidence


def test_detect_toxic_permission_combinations_generates_findings() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_toxic_permission_combinations(iam_data, graph)

    assert [finding.id for finding in findings] == [
        "finding-toxic-combo-user-003",
        "finding-toxic-combo-user-005",
        "finding-toxic-combo-user-007",
        "finding-toxic-combo-user-010",
        "finding-toxic-combo-user-011",
    ]
    assert all(finding.finding_type == "toxic_permission_combination" for finding in findings)
    assert "Toxic permission combinations found: read + manage" in findings[0].evidence[0]


def test_detect_toxic_permission_combinations_escalates_to_critical() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_toxic_permission_combinations(iam_data, graph)
    finding = findings[0]

    assert finding.identity_id == "user-003"
    assert finding.severity == Severity.CRITICAL
    assert finding.score == 100
    assert "Identity has privileged admin, manage, or administer capability." in finding.evidence


def test_detect_toxic_permission_combinations_includes_attack_paths() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_toxic_permission_combinations(iam_data, graph)
    finding = findings[0]

    assert finding.attack_paths
    assert any("Ananya Rao" in path for path in finding.attack_paths)
    assert any("Customer 360 Database" in path for path in finding.attack_paths)


def test_detect_wildcard_or_admin_permissions_generates_findings() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_wildcard_or_admin_permissions(iam_data, graph)

    assert [finding.id for finding in findings] == ["finding-wildcard-admin-user-002"]
    assert findings[0].finding_type == "wildcard_or_admin_permission"
    assert "perm-admin-all-production action=* resource=AtlasPay Production Portal" in findings[0].evidence[0]


def test_detect_wildcard_or_admin_permissions_escalates_sensitive_access() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_wildcard_or_admin_permissions(iam_data, graph)
    finding = findings[0]

    assert finding.identity_id == "user-002"
    assert finding.severity == Severity.CRITICAL
    assert finding.score == 100
    assert "Reachable sensitive resources:" in finding.evidence[1]


def test_detect_wildcard_or_admin_permissions_includes_readable_attack_paths() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_wildcard_or_admin_permissions(iam_data, graph)
    finding = findings[0]

    assert finding.attack_paths
    assert any("Omar Haddad" in path for path in finding.attack_paths)
    assert any("Production Breakglass Operator" in path for path in finding.attack_paths)
    assert any("AtlasPay Production Portal" in path for path in finding.attack_paths)


def test_run_all_detections_returns_deterministic_scores() -> None:
    iam_data, graph = load_sample_context()

    first_findings = run_all_detections(
        iam_data,
        graph,
        analysis_date=FIXED_ANALYSIS_DATE,
    )
    second_findings = run_all_detections(
        iam_data,
        graph,
        analysis_date=FIXED_ANALYSIS_DATE,
    )

    assert [finding.id for finding in first_findings] == [
        "finding-mfa-user-005",
        "finding-mfa-user-007",
        "finding-mfa-user-011",
        "finding-dormant-user-005",
        "finding-dormant-user-010",
        "finding-external-sensitive-user-004",
        "finding-external-sensitive-user-008",
        "finding-service-sensitive-user-006",
        "finding-service-sensitive-user-009",
        "finding-toxic-combo-user-003",
        "finding-toxic-combo-user-005",
        "finding-toxic-combo-user-007",
        "finding-toxic-combo-user-010",
        "finding-toxic-combo-user-011",
        "finding-wildcard-admin-user-002",
    ]
    assert [finding.score for finding in first_findings] == [
        85,
        85,
        85,
        85,
        80,
        90,
        85,
        85,
        85,
        100,
        100,
        100,
        100,
        100,
        100,
    ]
    assert second_findings == first_findings


def load_sample_with_service_account_admin_role() -> IAMData:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)
    users = [
        service_account_with_admin_role(user)
        if user.id == "user-006"
        else user
        for user in iam_data.users
    ]

    return replace(
        iam_data,
        users=users,
        users_by_id={user.id: user for user in users},
    )


def service_account_with_admin_role(user: User) -> User:
    return replace(
        user,
        roles=[*user.roles, "role-platform-admin"],
    )
