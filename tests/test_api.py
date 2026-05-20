from pathlib import Path
import sqlite3

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


@pytest.mark.parametrize(
    ("route", "expected_title", "expected_script", "loading_id", "loading_text"),
    [
        ("/dashboard", b"IAM Sentinel Dashboard", b"assets/js/iam-sentinel-dashboard.js", b'id="dashboard-loading"', b"Loading dashboard..."),
        ("/findings", b"IAM Sentinel Findings", b"assets/js/iam-sentinel-findings.js", b'id="findings-loading"', b"Loading findings..."),
        ("/findings/finding-low", b"IAM Sentinel Investigation", b"assets/js/iam-sentinel-finding-detail.js", b'id="finding-detail-loading"', b"Loading finding..."),
        ("/identities", b"IAM Sentinel Identities", b"assets/js/iam-sentinel-identities.js", b'id="identities-loading"', b"Loading identities..."),
        ("/identities/user-004", b"IAM Sentinel Identity", b"assets/js/iam-sentinel-identity-detail.js", b'id="identity-detail-loading"', b"Loading identity..."),
        ("/resources", b"IAM Sentinel Resources", b"assets/js/iam-sentinel-resources.js", b'id="resources-loading"', b"Loading resources..."),
        ("/resources/res-payroll-system", b"IAM Sentinel Resource", b"assets/js/iam-sentinel-resource-detail.js", b'id="resource-detail-loading"', b"Loading resource..."),
        ("/access-paths", b"IAM Sentinel Access Paths", b"assets/js/iam-sentinel-access-paths.js", b'id="access-paths-loading"', b"Loading access paths..."),
        ("/access-reviews", b"IAM Sentinel Access Reviews", b"assets/js/iam-sentinel-access-reviews.js", b'id="access-reviews-loading"', b"Loading access reviews..."),
        ("/reports", b"IAM Sentinel Reports", b"assets/js/iam-sentinel-reports.js", b'id="reports-loading"', b"Loading governance summary..."),
    ],
)
def test_ui_routes_return_consistent_shell(
    client,
    route,
    expected_title,
    expected_script,
    loading_id,
    loading_text,
) -> None:
    response = client.get(route)

    assert response.status_code == 200
    assert expected_title in response.data
    assert response.data.count(b'<main id="main" class="main') == 1
    assert response.data.count(b"</main>") == 1
    assert response.data.count(b'<div class="pagetitle">') == 1
    assert response.data.count(b"<h1>") == 1
    assert response.data.count(b'role="status"') == 1
    assert response.data.count(loading_id) == 1
    assert response.data.count(loading_text) == 1
    assert b"Loading dashboard data..." not in response.data
    assert b"Loading findings data..." not in response.data
    assert b"Loading identity data..." not in response.data
    assert b"Loading resource data..." not in response.data
    assert b"Loading access path data..." not in response.data
    assert b"Loading access review data..." not in response.data
    product_css = b"assets/css/iam-sentinel-polish.css"
    niceadmin_css = b"assets/css/style.css"
    assert response.data.count(product_css) == 1
    assert response.data.index(niceadmin_css) < response.data.index(product_css)
    shared_helper = b"assets/js/iam-sentinel-ui.js"
    assert response.data.count(shared_helper) == 1
    assert response.data.count(expected_script) == 1
    assert response.data.index(shared_helper) < response.data.index(expected_script)


@pytest.mark.parametrize(
    ("route", "not_found_marker"),
    [
        ("/findings/finding-missing", b'id="finding-not-found"'),
        ("/identities/user-missing", b'id="identity-not-found"'),
        ("/resources/res-missing", b'id="resource-not-found"'),
    ],
)
def test_missing_detail_pages_render_not_found_state(client, route, not_found_marker) -> None:
    response = client.get(route)

    assert response.status_code == 200
    assert response.data.count(b'<main id="main" class="main') == 1
    assert response.data.count(b'<div class="pagetitle">') == 1
    assert not_found_marker in response.data
    assert b'data-testid="' in response.data


@pytest.mark.parametrize(
    "script_path",
    [
        "static/assets/js/iam-sentinel-reports.js",
        "static/assets/js/iam-sentinel-access-reviews.js",
    ],
)
def test_helper_refactored_scripts_do_not_reintroduce_local_wrappers(script_path) -> None:
    script = (Path(__file__).resolve().parents[1] / script_path).read_text()

    for wrapper_name in [
        "escapeHtml",
        "setText",
        "showLoading",
        "showError",
        "showFeedback",
        "fetchJson",
    ]:
        assert f"function {wrapper_name}" not in script
    assert "window.IamSentinelUI" in script
    assert "ui.fetchJson" in script


@pytest.mark.parametrize(
    ("script_path", "expected_chart_creations"),
    [
        ("static/assets/js/iam-sentinel-dashboard.js", 1),
        ("static/assets/js/iam-sentinel-access-reviews.js", 1),
    ],
)
def test_chart_scripts_have_single_safe_chart_creation_path(
    script_path,
    expected_chart_creations,
) -> None:
    script = (Path(__file__).resolve().parents[1] / script_path).read_text()

    assert script.count("new Chart(") == expected_chart_creations
    assert "if (!window.Chart || !canvas)" in script


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
    assert b'id="access-paths-feedback"' in response.data
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


def test_get_access_reviews_page_returns_workbench(client) -> None:
    response = client.get("/access-reviews")

    assert response.status_code == 200
    assert b"IAM Sentinel Access Reviews" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert b'id="access-reviews-workbench"' in response.data
    assert b'id="total-access-reviews"' in response.data
    assert b'id="open-access-reviews"' in response.data
    assert b'id="completed-access-reviews"' in response.data
    assert b'id="revoke-access-reviews"' in response.data
    assert b'id="access-review-analytics-cards"' in response.data
    assert b'id="in-review-access-reviews"' in response.data
    assert b'id="stale-access-reviews"' in response.data
    assert b'id="needs-follow-up-access-reviews"' in response.data
    assert b'id="unique-access-reviewers"' in response.data
    assert b'id="access-review-analytics"' in response.data
    assert b'id="access-review-decision-chart"' in response.data
    assert b'id="access-review-status-chart"' in response.data
    assert b'id="access-review-analytics-tables"' in response.data
    assert b'id="top-reviewed-resources-table"' in response.data
    assert b'id="top-reviewed-identities-table"' in response.data
    assert b'id="reviewer-workload-table"' in response.data
    assert b'id="access-reviews-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 7
    assert b'colspan="7"' in response.data
    assert b'id="access-review-actions-marker"' in response.data
    assert b"assets/js/iam-sentinel-access-reviews.js" in response.data
    assert b"Access Reviews" in response.data
    assert b'href="/access-reviews"' in response.data


def test_get_reports_page_returns_workbench(client) -> None:
    response = client.get("/reports")

    assert response.status_code == 200
    assert b"IAM Sentinel Reports" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert b'id="reports-workbench"' in response.data
    assert b'id="governance-summary-cards"' in response.data
    assert b'id="report-total-findings"' in response.data
    assert b'id="report-critical-findings"' in response.data
    assert b'id="report-high-findings"' in response.data
    assert b'id="report-risky-external-identities"' in response.data
    assert b'id="report-stale-reviews"' in response.data
    assert b'id="report-revoke-decisions"' in response.data
    assert b'id="report-open-access-reviews"' in response.data
    assert b'id="report-completed-access-reviews"' in response.data
    assert b'id="governance-summary-tables"' in response.data
    assert b'id="top-risky-resources-table"' in response.data
    assert b'id="top-risky-identities-table"' in response.data
    assert b'id="export-governance-json"' in response.data
    assert b'id="export-governance-csv"' in response.data
    assert b"assets/js/iam-sentinel-reports.js" in response.data
    assert b"Reports" in response.data
    assert b'href="/reports"' in response.data


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
    assert customer_database["external_access_count"] == 2
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


def test_create_access_review(client) -> None:
    response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )

    assert response.status_code == 201
    review = response.get_json()
    assert review["identity_id"] == "user-004"
    assert review["resource_id"] == "res-customer-database"
    assert review["status"] == "OPEN"
    assert review["decision"] == "UNDECIDED"
    assert review["reviewer"] is None
    assert review["notes"] == ""
    assert review["created_at"]
    assert review["updated_at"]


def test_duplicate_active_access_review_is_prevented(client) -> None:
    payload = {
        "identity_id": "user-004",
        "resource_id": "res-customer-database",
    }

    first_response = client.post("/api/access-reviews", json=payload)
    duplicate_response = client.post("/api/access-reviews", json=payload)

    assert first_response.status_code == 201
    assert duplicate_response.status_code == 409
    assert duplicate_response.get_json() == {
        "error": "Active access review already exists."
    }


def test_update_access_review(client) -> None:
    create_response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-006",
            "resource_id": "res-payroll-system",
        },
    )
    review_id = create_response.get_json()["id"]

    response = client.patch(
        f"/api/access-reviews/{review_id}",
        json={
            "status": "COMPLETED",
            "reviewer": "analyst@example.local",
            "decision": "REVOKE",
            "notes": "Payroll service account access should be removed.",
        },
    )

    assert response.status_code == 200
    review = response.get_json()
    assert review["status"] == "COMPLETED"
    assert review["reviewer"] == "analyst@example.local"
    assert review["decision"] == "REVOKE"
    assert review["notes"] == "Payroll service account access should be removed."


def test_list_access_reviews(client) -> None:
    client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )
    client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-006",
            "resource_id": "res-payroll-system",
        },
    )

    response = client.get("/api/access-reviews")

    assert response.status_code == 200
    reviews = response.get_json()
    assert len(reviews) == 2
    assert {
        "id",
        "identity_id",
        "resource_id",
        "status",
        "reviewer",
        "decision",
        "notes",
        "created_at",
        "updated_at",
    }.issubset(reviews[0])


def test_access_review_metrics_returns_expected_fields(client) -> None:
    client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )

    response = client.get("/api/access-review-metrics")

    assert response.status_code == 200
    metrics = response.get_json()
    assert {
        "total_reviews",
        "open_reviews",
        "in_review_reviews",
        "completed_reviews",
        "approve_decisions",
        "revoke_decisions",
        "needs_follow_up_decisions",
        "undecided_reviews",
        "stale_open_reviews",
        "unique_reviewers",
        "reviews_per_reviewer",
        "most_reviewed_resources",
        "most_reviewed_identities",
    }.issubset(metrics)
    assert metrics["total_reviews"] == 1
    assert metrics["open_reviews"] == 1
    assert metrics["undecided_reviews"] == 1


def test_access_review_metrics_calculates_stale_reviews(client) -> None:
    create_response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )
    review_id = create_response.get_json()["id"]
    with sqlite3.connect(app.config["FINDINGS_DB_PATH"]) as connection:
        connection.execute(
            "UPDATE access_reviews SET updated_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", review_id),
        )

    response = client.get("/api/access-review-metrics")
    reviews_response = client.get("/api/access-reviews")

    assert response.status_code == 200
    assert response.get_json()["stale_open_reviews"] == 1
    assert reviews_response.get_json()[0]["stale"] is True


def test_access_review_metrics_uses_deterministic_ordering(client) -> None:
    first = client.post(
        "/api/access-reviews",
        json={"identity_id": "user-010", "resource_id": "res-z"},
    ).get_json()
    second = client.post(
        "/api/access-reviews",
        json={"identity_id": "user-001", "resource_id": "res-z"},
    ).get_json()
    third = client.post(
        "/api/access-reviews",
        json={"identity_id": "user-002", "resource_id": "res-a"},
    ).get_json()
    client.patch(
        f"/api/access-reviews/{first['id']}",
        json={"reviewer": "analyst-b@example.local", "decision": "APPROVE"},
    )
    client.patch(
        f"/api/access-reviews/{second['id']}",
        json={"reviewer": "analyst-a@example.local", "decision": "REVOKE"},
    )
    client.patch(
        f"/api/access-reviews/{third['id']}",
        json={"reviewer": "analyst-a@example.local", "decision": "NEEDS_FOLLOW_UP"},
    )

    response = client.get("/api/access-review-metrics")

    assert response.status_code == 200
    metrics = response.get_json()
    assert metrics["most_reviewed_resources"] == [
        {"resource_id": "res-z", "count": 2},
        {"resource_id": "res-a", "count": 1},
    ]
    assert metrics["most_reviewed_identities"] == [
        {"identity_id": "user-001", "count": 1},
        {"identity_id": "user-002", "count": 1},
        {"identity_id": "user-010", "count": 1},
    ]
    assert metrics["reviews_per_reviewer"] == [
        {"reviewer": "analyst-a@example.local", "count": 2},
        {"reviewer": "analyst-b@example.local", "count": 1},
    ]


def test_governance_summary_report_returns_required_fields(client) -> None:
    response = client.get("/api/reports/governance-summary")

    assert response.status_code == 200
    report = response.get_json()
    assert {
        "generated_at",
        "total_findings",
        "critical_findings",
        "high_findings",
        "risky_external_identities",
        "stale_reviews",
        "revoke_decisions",
        "top_risky_resources",
        "top_risky_identities",
        "open_access_reviews",
        "completed_access_reviews",
    }.issubset(report)
    assert report["total_findings"] == 2
    assert report["critical_findings"] == 1
    assert report["top_risky_resources"]
    assert report["top_risky_identities"]


def test_governance_summary_csv_export_content_type(client) -> None:
    response = client.get("/api/reports/governance-summary?format=csv")

    assert response.status_code == 200
    assert response.content_type.startswith("text/csv")
    assert b"generated_at,total_findings,critical_findings" in response.data
    assert b"top_risky_resources,top_risky_identities" in response.data


def test_governance_summary_uses_deterministic_top_list_ordering(tmp_path) -> None:
    db_path = tmp_path / "report_findings.db"
    app.config["TESTING"] = True
    app.config["FINDINGS_DB_PATH"] = db_path
    app.config["IAM_DATA_PATH"] = (
        Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
    )
    save_findings(
        db_path,
        [
            make_finding("finding-z", Severity.HIGH, 80, "user-010", "res-z"),
            make_finding("finding-a", Severity.HIGH, 70, "user-001", "res-a"),
            make_finding("finding-z-2", Severity.CRITICAL, 95, "user-001", "res-z"),
            make_finding("finding-b", Severity.LOW, 25, "user-002", "res-b"),
        ],
    )

    with app.test_client() as test_client:
        response = test_client.get("/api/reports/governance-summary")

    assert response.status_code == 200
    report = response.get_json()
    assert report["top_risky_resources"] == [
        {"resource_id": "res-z", "finding_count": 2, "highest_score": 95},
        {"resource_id": "res-a", "finding_count": 1, "highest_score": 70},
        {"resource_id": "res-b", "finding_count": 1, "highest_score": 25},
    ]
    assert report["top_risky_identities"] == [
        {"identity_id": "user-001", "finding_count": 2, "highest_score": 95},
        {"identity_id": "user-002", "finding_count": 1, "highest_score": 25},
        {"identity_id": "user-010", "finding_count": 1, "highest_score": 80},
    ]


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
    assert body["total_findings"] == 15
    assert body["execution_timestamp"]
    assert len(body["findings"]) == 15
    assert findings_response.status_code == 200
    assert len(findings_response.get_json()) == 15


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
