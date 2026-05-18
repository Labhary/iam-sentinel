from datetime import date
from pathlib import Path

from core.graph_builder import build_identity_graph
from core.loader import load_iam_data
from core.models import Severity
from core.risk_engine import (
    detect_dormant_privileged_accounts,
    detect_external_identities_with_sensitive_access,
    detect_privileged_accounts_without_mfa,
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

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "finding-mfa-user-005"
    assert finding.identity_id == "user-005"
    assert finding.severity == Severity.HIGH
    assert finding.score == 85
    assert "MFA is disabled." in finding.evidence
    assert any("Nadia Flores" in path for path in finding.attack_paths)


def test_detect_dormant_privileged_accounts_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_dormant_privileged_accounts(
        iam_data,
        graph,
        analysis_date=FIXED_ANALYSIS_DATE,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "finding-dormant-user-005"
    assert finding.identity_id == "user-005"
    assert finding.score == 85
    assert "Identity has been dormant for 258 days." in finding.evidence
    assert finding.attack_paths


def test_detect_external_identities_with_sensitive_access_generates_finding() -> None:
    iam_data, graph = load_sample_context()

    findings = detect_external_identities_with_sensitive_access(iam_data, graph)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "finding-external-sensitive-user-004"
    assert finding.identity_id == "user-004"
    assert finding.score == 90
    assert finding.resource_id == "res-customer-database"
    assert "Identity is marked as external." in finding.evidence
    assert any("Leo Martin" in path for path in finding.attack_paths)


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
        "finding-dormant-user-005",
        "finding-external-sensitive-user-004",
    ]
    assert [finding.score for finding in first_findings] == [85, 85, 90]
    assert second_findings == first_findings
