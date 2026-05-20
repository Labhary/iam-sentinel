from pathlib import Path

import pytest

from app import app
from core.finding_store import save_findings
from core.models import Finding, Severity


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "api_findings.db"
    app.config["TESTING"] = True
    app.config["FINDINGS_DB_PATH"] = db_path
    app.config["IAM_DATA_PATH"] = (
        Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
    )

    save_findings(
        db_path,
        [
            make_finding(
                "finding-low",
                Severity.LOW,
                25,
                "user-001",
                "res-payroll-system",
            ),
            make_finding(
                "finding-critical",
                Severity.CRITICAL,
                95,
                "user-002",
                "res-customer-database",
            ),
        ],
    )

    with app.test_client() as test_client:
        yield test_client


def test_get_findings_returns_deterministic_sorted_findings(client) -> None:
    response = client.get("/api/findings")

    assert response.status_code == 200
    assert [finding["id"] for finding in response.get_json()] == [
        "finding-critical",
        "finding-low",
    ]
    assert response.get_json()[0]["activity"] == [
        {
            "type": "CREATED",
            "message": "Finding created.",
            "created_at": "2026-05-18T00:00:00Z",
        }
    ]
    assert "risk_factors" in response.get_json()[0]
    assert "risk_explanation" in response.get_json()[0]


def test_get_dashboard_returns_page(client) -> None:
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"IAM Sentinel Dashboard" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert response.data.count(b'<footer id="footer" class="footer">') == 1
    assert response.data.count(b"</body>") == 1
    assert response.data.count(b"</html>") == 1
    assert b'id="run-analysis-button"' in response.data
    assert b'id="total-findings"' in response.data
    assert b'id="severity-distribution-chart"' in response.data
    assert b'id="status-distribution-chart"' in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" in response.data
    assert b"assets/js/iam-sentinel-findings.js" not in response.data
    assert b'id="findings-table-body"' not in response.data
    assert b'id="bulk-status-button"' not in response.data
    assert b'id="finding-detail-modal"' not in response.data


def test_get_findings_page_returns_workbench(client) -> None:
    response = client.get("/findings")

    assert response.status_code == 200
    assert b"IAM Sentinel Findings" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert response.data.count(b'<footer id="footer" class="footer">') == 1
    assert response.data.count(b"</body>") == 1
    assert response.data.count(b"</html>") == 1
    assert b'id="findings-search"' in response.data
    assert b'id="severity-filter"' in response.data
    assert b'id="status-filter"' in response.data
    assert b'id="owner-filter"' in response.data
    assert b'id="findings-sort"' in response.data
    assert response.data.count(b'id="export-csv-button"') == 1
    assert response.data.count(b'<th scope="col">') == 8
    assert b'colspan="8"' in response.data
    assert b'colspan="7"' not in response.data
    assert b"Open Investigation" in response.data
    assert b'id="finding-identity-link-marker"' in response.data
    assert response.data.count(b'id="finding-detail-links"') == 1
    assert b"Open Identity Open Resource" not in response.data
    assert b"Open Identity" not in response.data
    assert b"Open Resource" not in response.data
    assert response.data.count(b'id="select-all-findings"') == 1
    assert response.data.count(b'id="bulk-status-button"') == 1
    assert response.data.count(b'id="bulk-owner-button"') == 1
    assert response.data.count(b'id="finding-detail-activity"') == 1
    assert b'id="finding-risk-explanation-section"' in response.data
    assert b'id="finding-detail-risk-explanation"' in response.data
    assert b'id="finding-detail-risk-factors"' in response.data
    assert b"assets/js/iam-sentinel-findings.js" in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" not in response.data
    assert b'id="run-analysis-button"' not in response.data
    assert b'id="severity-distribution-chart"' not in response.data
    assert b'id="status-distribution-chart"' not in response.data


def test_get_identities_page_returns_workbench(client) -> None:
    response = client.get("/identities")

    assert response.status_code == 200
    assert b"IAM Sentinel Identities" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert b'id="identity-workbench"' in response.data
    assert b'id="identities-search"' in response.data
    assert b'id="mfa-filter"' in response.data
    assert b'id="external-filter"' in response.data
    assert b'id="service-account-filter"' in response.data
    assert b'id="total-identities"' in response.data
    assert b'id="external-identities"' in response.data
    assert b'id="service-accounts"' in response.data
    assert b'id="identities-without-mfa"' in response.data
    assert b'id="identities-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 9
    assert b'colspan="9"' in response.data
    assert b'id="identity-detail-link-marker"' in response.data
    assert b"assets/js/iam-sentinel-identities.js" in response.data
    assert b"assets/js/iam-sentinel-findings.js" not in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" not in response.data


def test_get_resources_page_returns_workbench(client) -> None:
    response = client.get("/resources")

    assert response.status_code == 200
    assert b"IAM Sentinel Resources" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert b'id="resource-workbench"' in response.data
    assert b'id="resources-search"' in response.data
    assert b'id="sensitive-filter"' in response.data
    assert b'id="external-access-filter"' in response.data
    assert b'id="service-account-access-filter"' in response.data
    assert b'id="total-resources"' in response.data
    assert b'id="sensitive-resources"' in response.data
    assert b'id="resources-with-external-access"' in response.data
    assert b'id="resources-with-service-account-access"' in response.data
    assert b'id="resources-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 8
    assert b'colspan="8"' in response.data
    assert b'id="resource-detail-link-marker"' in response.data
    assert b"assets/js/iam-sentinel-resources.js" in response.data
    assert b"assets/js/iam-sentinel-identities.js" not in response.data
    assert b"assets/js/iam-sentinel-findings.js" not in response.data


def test_get_access_paths_page_returns_workbench(client) -> None:
    response = client.get("/access-paths")

    assert response.status_code == 200
    assert b"IAM Sentinel Access Paths" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert b'id="access-paths-workbench"' in response.data
    assert b'id="access-paths-search"' in response.data
    assert b'id="access-path-sensitive-only"' in response.data
    assert b'id="access-path-identity-filter"' in response.data
    assert b'id="access-path-resource-filter"' in response.data
    assert b'id="total-access-paths"' in response.data
    assert b'id="sensitive-resource-paths"' in response.data
    assert b'id="external-identity-paths"' in response.data
    assert b'id="service-account-paths"' in response.data
    assert b'id="access-paths-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 6
    assert b'colspan="6"' in response.data
    assert b'id="access-path-detail-links"' in response.data
    assert b"assets/js/iam-sentinel-access-paths.js" in response.data
    assert b"assets/js/iam-sentinel-resources.js" not in response.data
    assert b"Access Paths" in response.data
    assert b'href="/access-paths"' in response.data


def test_get_finding_detail_page_returns_investigation_shell(client) -> None:
    response = client.get("/findings/finding-low")

    assert response.status_code == 200
    assert b"IAM Sentinel Investigation" in response.data
    assert response.data.count(b'<main id="main" class="main"') == 1
    assert response.data.count(b"</main>") == 1
    assert b'data-finding-id="finding-low"' in response.data
    assert b'id="finding-detail-content"' in response.data
    assert b'<a href="/dashboard">Dashboard</a>' not in response.data
    assert b'<a href="/findings">Findings</a>' in response.data
    assert b'finding-low' in response.data
    assert response.data.count(b'id="finding-detail-links"') == 1
    assert b"Identity and resource links" in response.data
    assert b"Open Identity Open Resource" not in response.data
    assert b'id="finding-not-found"' in response.data
    assert b'id="finding-risk-explanation-section"' in response.data
    assert b'id="finding-detail-risk-explanation"' in response.data
    assert b'id="finding-detail-risk-factors"' in response.data
    assert b"assets/js/iam-sentinel-finding-detail.js" in response.data
    assert b"assets/js/iam-sentinel-findings.js" not in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" not in response.data


def test_get_missing_finding_detail_page_returns_not_found_shell(client) -> None:
    response = client.get("/findings/finding-missing")

    assert response.status_code == 200
    assert b'data-finding-id="finding-missing"' in response.data
    assert b'id="finding-not-found"' in response.data
    assert b'data-testid="finding-not-found"' in response.data


def test_get_identity_detail_page_returns_identity_shell(client) -> None:
    response = client.get("/identities/user-004")

    assert response.status_code == 200
    assert b"IAM Sentinel Identity" in response.data
    assert response.data.count(b'<main id="main" class="main"') == 1
    assert response.data.count(b"</main>") == 1
    assert b'data-identity-id="user-004"' in response.data
    assert b'<a href="/dashboard">Dashboard</a>' not in response.data
    assert b'<a href="/identities">Identities</a>' in response.data
    assert b'user-004' in response.data
    assert b'id="identity-detail-content"' in response.data
    assert b'id="identity-detail-roles"' in response.data
    assert b'id="identity-detail-groups"' in response.data
    assert b'id="identity-related-findings"' in response.data
    assert b'id="identity-finding-link-marker"' in response.data
    assert b'id="identity-not-found"' in response.data
    assert b"assets/js/iam-sentinel-identity-detail.js" in response.data
    assert b"assets/js/iam-sentinel-identities.js" not in response.data


def test_get_missing_identity_detail_page_returns_not_found_shell(client) -> None:
    response = client.get("/identities/user-missing")

    assert response.status_code == 200
    assert b'data-identity-id="user-missing"' in response.data
    assert b'id="identity-not-found"' in response.data
    assert b'data-testid="identity-not-found"' in response.data


def test_get_resource_detail_page_returns_resource_shell(client) -> None:
    response = client.get("/resources/res-payroll-system")

    assert response.status_code == 200
    assert b"IAM Sentinel Resource" in response.data
    assert response.data.count(b'<main id="main" class="main"') == 1
    assert response.data.count(b"</main>") == 1
    assert b'data-resource-id="res-payroll-system"' in response.data
    assert b'<a href="/dashboard">Dashboard</a>' not in response.data
    assert b'<a href="/resources">Resources</a>' in response.data
    assert b'res-payroll-system' in response.data
    assert b'id="resource-detail-content"' in response.data
    assert b'id="resource-accessible-identities"' in response.data
    assert b'id="resource-external-identities"' in response.data
    assert b'id="resource-service-accounts"' in response.data
    assert b'id="resource-related-findings"' in response.data
    assert b'id="resource-identity-link-marker"' in response.data
    assert b'id="resource-finding-link-marker"' in response.data
    assert b'id="resource-not-found"' in response.data
    assert b"assets/js/iam-sentinel-resource-detail.js" in response.data
    assert b"assets/js/iam-sentinel-resources.js" not in response.data


def test_get_missing_resource_detail_page_returns_not_found_shell(client) -> None:
    response = client.get("/resources/res-missing")

    assert response.status_code == 200
    assert b'data-resource-id="res-missing"' in response.data
    assert b'id="resource-not-found"' in response.data
    assert b'data-testid="resource-not-found"' in response.data


def test_get_findings_summary_returns_summary_metrics(client) -> None:
    response = client.get("/api/findings/summary")

    assert response.status_code == 200
    assert response.get_json() == {
        "total_findings": 2,
        "count_per_severity": {
            "LOW": 1,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 1,
        },
        "highest_score": 95,
        "affected_identities_count": 2,
    }


def test_get_identities_returns_identity_fields(client) -> None:
    response = client.get("/api/identities")

    assert response.status_code == 200
    identities = response.get_json()
    assert identities
    assert {
        "id",
        "name",
        "email",
        "type",
        "mfa_enabled",
        "external_user",
        "service_account",
        "groups",
        "roles",
    }.issubset(identities[0])


def test_get_identities_includes_service_and_external_flags(client) -> None:
    response = client.get("/api/identities")

    assert response.status_code == 200
    identities_by_id = {
        identity["id"]: identity
        for identity in response.get_json()
    }
    assert identities_by_id["user-004"]["external_user"] is True
    assert identities_by_id["user-004"]["service_account"] is False
    assert identities_by_id["user-006"]["service_account"] is True
    assert identities_by_id["user-006"]["external_user"] is False


def test_get_resources_returns_resource_fields(client) -> None:
    response = client.get("/api/resources")

    assert response.status_code == 200
    resources = response.get_json()
    assert resources
    assert {
        "id",
        "name",
        "type",
        "sensitive",
        "accessible_by",
        "accessible_by_count",
        "external_access_count",
        "service_account_access_count",
        "related_findings_count",
    }.issubset(resources[0])


def test_get_resources_includes_access_and_finding_counts(client) -> None:
    response = client.get("/api/resources")

    assert response.status_code == 200
    resources_by_id = {
        resource["id"]: resource
        for resource in response.get_json()
    }
    customer_database = resources_by_id["res-customer-database"]
    payroll_system = resources_by_id["res-payroll-system"]

    assert customer_database["sensitive"] is True
    assert "user-004" in customer_database["accessible_by"]
    assert customer_database["external_access_count"] == 1
    assert payroll_system["service_account_access_count"] == 1
    assert payroll_system["related_findings_count"] == 1


def test_get_access_paths_returns_required_fields(client) -> None:
    response = client.get("/api/access-paths")

    assert response.status_code == 200
    access_paths = response.get_json()
    assert access_paths
    assert {
        "identity_id",
        "identity_name",
        "resource_id",
        "resource_name",
        "resource_sensitive",
        "path_nodes",
        "path_display",
        "path_length",
    }.issubset(access_paths[0])
    assert access_paths[0]["resource_sensitive"] is True
    assert access_paths[0]["identity_id"] <= access_paths[-1]["identity_id"]
    assert access_paths[0]["path_nodes"][0].startswith("user-")
    assert access_paths[0]["path_nodes"][-1].startswith("res-")
    assert " -> " in access_paths[0]["path_display"]
    assert access_paths[0]["path_length"] == len(access_paths[0]["path_nodes"]) - 1


def test_get_access_paths_filters_by_identity_id(client) -> None:
    response = client.get("/api/access-paths?identity_id=user-004")

    assert response.status_code == 200
    access_paths = response.get_json()
    assert access_paths
    assert {path["identity_id"] for path in access_paths} == {"user-004"}


def test_get_access_paths_filters_by_resource_id(client) -> None:
    response = client.get("/api/access-paths?resource_id=res-payroll-system")

    assert response.status_code == 200
    access_paths = response.get_json()
    assert access_paths
    assert {path["resource_id"] for path in access_paths} == {"res-payroll-system"}


def test_get_access_paths_filters_sensitive_only(client) -> None:
    response = client.get("/api/access-paths?sensitive_only=true")

    assert response.status_code == 200
    access_paths = response.get_json()
    assert access_paths
    assert all(path["resource_sensitive"] is True for path in access_paths)
    assert "res-source-repositories" not in {
        path["resource_id"]
        for path in access_paths
    }


def test_post_analysis_run_executes_and_persists_findings(tmp_path) -> None:
    db_path = tmp_path / "analysis_api_findings.db"
    app.config["TESTING"] = True
    app.config["FINDINGS_DB_PATH"] = db_path
    app.config["IAM_DATA_PATH"] = (
        Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
    )

    with app.test_client() as test_client:
        response = test_client.post("/api/analysis/run")
        findings_response = test_client.get("/api/findings")

    assert response.status_code == 200
    body = response.get_json()
    assert body["total_findings"] == 7
    assert body["execution_timestamp"]
    assert len(body["findings"]) == 7
    assert findings_response.status_code == 200
    assert len(findings_response.get_json()) == 7


def test_patch_finding_status_updates_status(client) -> None:
    response = client.patch(
        "/api/findings/finding-low/status",
        json={"status": "IN_PROGRESS"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "IN_PROGRESS"
    assert response.get_json()["activity"][-1]["type"] == "STATUS_CHANGED"


def test_patch_finding_owner_assigns_owner(client) -> None:
    response = client.patch(
        "/api/findings/finding-low/owner",
        json={"owner": "analyst@example.local"},
    )

    assert response.status_code == 200
    assert response.get_json()["owner"] == "analyst@example.local"


def test_post_finding_note_appends_note(client) -> None:
    response = client.post(
        "/api/findings/finding-low/notes",
        json={"note": "Reviewed with application owner."},
    )

    assert response.status_code == 201
    assert response.get_json()["analyst_notes"] == [
        "Reviewed with application owner."
    ]


def test_api_returns_error_for_missing_finding(client) -> None:
    response = client.patch(
        "/api/findings/finding-missing/status",
        json={"status": "RESOLVED"},
    )

    assert response.status_code == 404
    assert response.get_json() == {"error": "Finding not found."}


def test_api_returns_error_for_invalid_status(client) -> None:
    response = client.patch(
        "/api/findings/finding-low/status",
        json={"status": "INVALID"},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid finding status."}


def test_api_returns_error_for_missing_payload_fields(client) -> None:
    status_response = client.patch("/api/findings/finding-low/status", json={})
    owner_response = client.patch("/api/findings/finding-low/owner", json={})
    note_response = client.post("/api/findings/finding-low/notes", json={})

    assert status_response.status_code == 400
    assert owner_response.status_code == 400
    assert note_response.status_code == 400
    assert status_response.get_json() == {"error": "Missing required field: status"}
    assert owner_response.get_json() == {"error": "Missing required field: owner"}
    assert note_response.get_json() == {"error": "Missing required field: note"}


def make_finding(
    finding_id: str,
    severity: Severity,
    score: int,
    identity_id: str,
    resource_id: str = "res-001",
) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity=severity,
        score=score,
        identity_id=identity_id,
        resource_id=resource_id,
        finding_type="test",
        description="Test description.",
        evidence=["Test evidence."],
        recommendation="Test recommendation.",
        attack_paths=["User -> Role -> Resource"],
        created_at="2026-05-18T00:00:00Z",
    )
