from pathlib import Path
import ast
import re
import sqlite3

import pytest

from app import app, access_review_to_dict
from core.access_review_store import row_to_review
from core.finding_store import save_findings
from core.models import (
    AccessReview,
    AccessReviewDecision,
    AccessReviewRemediationStatus,
    AccessReviewStatus,
    Finding,
    Severity,
)


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "api_findings.db"
    app.config["TESTING"] = True
    app.config["FINDINGS_DB_PATH"] = db_path
    app.config["IAM_DATA_PATH"] = (
        Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
    )
    app.config["REPORT_GENERATED_AT"] = "2026-05-24T00:00:00+00:00"

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
    app.config.pop("REPORT_GENERATED_AT", None)


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
        ("/attack-graph", b"IAM Sentinel Attack Graph", b"assets/js/iam-sentinel-attack-graph.js", b'id="attack-graph-loading"', b"Loading attack graph..."),
        ("/remediation-audit", b"IAM Sentinel Remediation Audit", b"assets/js/iam-sentinel-remediation-audit.js", b'id="remediation-audit-loading"', b"Loading remediation audit..."),
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


def test_dashboard_script_has_single_analysis_flow() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static/assets/js/iam-sentinel-dashboard.js"
    ).read_text()

    assert "getTopRiskFindingsLegacy" not in script
    assert script.count("function getTopRiskFindings(") == 1
    assert script.count('"/api/analysis/run"') + script.count("'/api/analysis/run'") == 1
    assert script.count("await refreshDashboard();") == 1
    assert "renderLastAnalysisRun(result.execution_timestamp)" in script
    assert "function formatAnalysisTimestamp(timestamp)" in script
    assert "new Intl.DateTimeFormat('en-US'" in script
    assert "timeZone: 'UTC'" in script


def test_shared_timestamp_formatter_is_available_and_used_for_finding_detail() -> None:
    project_root = Path(__file__).resolve().parents[1]
    helper_script = (project_root / "static/assets/js/iam-sentinel-ui.js").read_text()
    detail_script = (
        project_root / "static/assets/js/iam-sentinel-finding-detail.js"
    ).read_text()

    assert "function formatTimestamp(timestamp)" in helper_script
    assert "new Intl.DateTimeFormat('en-US'" in helper_script
    assert "timeZone: 'UTC'" in helper_script
    assert "Number.isNaN(date.getTime())" in helper_script
    assert "formatTimestamp," in helper_script
    assert "const formatTimestamp = ui.formatTimestamp || ((timestamp) => timestamp)" in detail_script
    assert "formatTimestamp(finding.created_at)" in detail_script
    assert "formatTimestamp(finding.updated_at)" in detail_script
    assert "formatTimestamp(safeEntry.created_at)" in detail_script


def test_finding_detail_script_has_one_clean_render_path() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static/assets/js/iam-sentinel-finding-detail.js"
    ).read_text()

    required_functions = [
        "getElement",
        "escapeHtml",
        "setText",
        "setHtml",
        "setInputValue",
        "getInputValue",
        "showAlert",
        "showLoading",
        "showNotFound",
        "fetchJson",
        "normalizeItems",
        "renderList",
        "renderLinks",
        "renderActivityList",
        "renderLifecycleHistory",
        "renderFinding",
        "refreshFinding",
        "updateFinding",
        "wireEvents",
        "initFindingDetail",
    ]

    assert script.count("(() => {") == 1
    assert script.count("})();") == 1
    assert script.count("const ui = window.IamSentinelUI || {};") == 1
    assert script.count("const formatTimestamp = ui.formatTimestamp || ((timestamp) => timestamp);") == 1
    for function_name in required_functions:
        assert script.count(f"function {function_name}(") == 1
    assert "function renderSection(" not in script
    assert "console.error(`Finding detail render failed for ${section}`, error);" not in script
    assert "function safeTimestamp(" not in script
    assert "document.getElementById('finding-detail-title').textContent" not in script
    assert "document.getElementById('finding-detail-created-at').textContent" not in script
    assert "document.getElementById('finding-status-select').value" not in script
    assert "document.getElementById('save-status-button').addEventListener" not in script


def test_finding_detail_runtime_initialization_contract() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-finding-detail.js").read_text()
    template = (project_root / "templates/finding_detail.html").read_text()

    assert 'id="finding-investigation-page" data-finding-id="{{ finding_id }}"' in template
    assert "const page = getElement('finding-investigation-page');" in script
    assert "state.findingId = page.dataset.findingId;" in script
    assert "} finally {" in script
    assert "showLoading(false);" in script
    assert "Array.isArray(findings)" in script
    assert "findings && findings.value" in script
    assert "console.error('Finding detail page root is missing.');" in script
    assert "console.error('Finding detail findingId is missing.');" in script
    assert "console.error('Finding detail fetch failed.', error);" in script
    assert "console.error('Finding detail finding not found.', state.findingId);" in script
    assert "console.error('Finding detail render failed.', error);" in script


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
    assert response.get_json()[0]["identity_name"] == "Omar Haddad"


def test_findings_script_searches_and_displays_identity_names() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-findings.js"
    ).read_text()

    assert "finding.identity_name" in script
    assert "finding-identity-name" in script
    assert "formatIdentityLabel(finding.identity_name, finding.identity_id)" in script
    assert "finding.identity_name || finding.identity_id" not in script
    assert "finding-accepted-risk-reason" in script
    assert "ACCEPT_RISK" in script


def test_get_dashboard_returns_page(client) -> None:
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"IAM Sentinel Dashboard" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert response.data.count(b"</main>") == 1
    assert response.data.count(b'<footer id="footer" class="footer">') == 1
    assert response.data.count(b"</body>") == 1
    assert response.data.count(b"</html>") == 1
    assert response.data.count(b'id="run-analysis-button"') == 1
    assert response.data.count(b'id="last-analysis-run"') == 1
    assert b"Last analysis run: Not run in this session" in response.data
    assert b'id="total-findings"' in response.data
    assert b'id="severity-distribution-chart"' in response.data
    assert b'id="status-distribution-chart"' in response.data
    assert b"Top Risk Findings" in response.data
    assert b'id="top-risk-findings-table"' in response.data
    assert b"Preparing top risk findings table..." in response.data
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
    assert b'id="findings-page-size"' in response.data
    assert b'<option value="10" selected>10</option>' in response.data
    assert b'<option value="25">25</option>' in response.data
    assert b'<option value="50">50</option>' in response.data
    assert b'id="findings-pagination-summary"' in response.data
    assert b'id="findings-pagination-controls"' in response.data
    assert b'id="findings-prev-page"' in response.data
    assert b'id="findings-next-page"' in response.data
    assert b"Showing 0 of 0 findings" in response.data
    assert response.data.count(b'id="export-csv-button"') == 1
    assert response.data.count(b'<th scope="col">') == 8
    assert b'colspan="8"' in response.data
    assert b'colspan="7"' not in response.data
    assert b"Investigate" in response.data
    assert b"Open Investigation" not in response.data
    assert b'id="finding-identity-link-marker"' in response.data
    assert response.data.count(b'id="finding-detail-links"') == 1
    assert b"Open Identity Open Resource" not in response.data
    assert b"Open Identity" not in response.data
    assert b"Open Resource" not in response.data
    assert response.data.count(b'id="select-all-findings"') == 1
    assert response.data.count(b'id="bulk-status-button"') == 1
    assert response.data.count(b'id="bulk-owner-button"') == 1
    assert b"Open Full Investigation" in response.data
    assert b'id="open-full-investigation-link"' in response.data
    assert b'id="finding-triage-risk-factors"' in response.data
    assert b'id="finding-triage-evidence"' in response.data
    assert b'id="finding-detail-evidence"' not in response.data
    assert b'id="finding-detail-attack-paths"' not in response.data
    assert b'id="finding-detail-activity"' not in response.data
    assert b'id="finding-detail-notes"' not in response.data
    assert b'id="finding-risk-explanation-section"' in response.data
    assert b'id="finding-detail-risk-explanation"' in response.data
    assert b"assets/js/iam-sentinel-findings.js" in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" not in response.data
    assert b'id="run-analysis-button"' not in response.data
    assert b'id="severity-distribution-chart"' not in response.data
    assert b'id="status-distribution-chart"' not in response.data


def test_findings_workbench_script_keeps_pagination_and_compact_modal_boundaries() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-findings.js").read_text()

    assert "pageSize: 10" in script
    assert "state.filteredFindings.slice" in script
    assert "state.filteredFindings.map((finding)" in script
    assert "state.paginatedFindings.forEach" in script
    assert "findings-page-size" in script
    assert "findings-prev-page" in script
    assert "findings-next-page" in script
    assert "finding-detail-attack-paths" not in script
    assert "finding-detail-activity" not in script
    assert "finding-detail-notes" not in script


def test_finding_detail_script_required_ids_exist_in_template() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-finding-detail.js").read_text()
    template = (project_root / "templates/finding_detail.html").read_text()

    required_ids = [
        "finding-detail-title",
        "finding-detail-meta",
        "finding-detail-links",
        "finding-detail-severity",
        "finding-detail-score",
        "finding-detail-status",
        "finding-detail-owner",
        "finding-detail-created-at",
        "finding-detail-updated-at",
        "finding-detail-description",
        "finding-detail-risk-explanation",
        "finding-detail-recommendation",
        "finding-status-select",
        "finding-lifecycle-note-input",
        "finding-owner-input",
        "finding-note-input",
        "finding-detail-evidence",
        "finding-detail-risk-factors",
        "finding-detail-attack-paths",
        "finding-detail-notes",
        "finding-detail-activity",
        "finding-lifecycle-history",
        "finding-action-feedback",
        "finding-detail-loading",
        "finding-not-found",
        "finding-detail-content",
    ]

    for element_id in required_ids:
        assert element_id in script
        assert f'id="{element_id}"' in template


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
    assert b'id="identities-page-size"' in response.data
    assert b'<option value="10" selected>10</option>' in response.data
    assert b'<option value="25">25</option>' in response.data
    assert b'<option value="50">50</option>' in response.data
    assert b'id="identities-pagination-summary"' in response.data
    assert b'id="identities-pagination-controls"' in response.data
    assert b'id="identities-prev-page"' in response.data
    assert b'id="identities-next-page"' in response.data
    assert b'id="total-identities"' in response.data
    assert b'id="external-identities"' in response.data
    assert b'id="service-accounts"' in response.data
    assert b'id="identities-without-mfa"' in response.data
    assert b'id="identities-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 9
    assert b'colspan="9"' in response.data
    assert b'id="identity-detail-link-marker"' in response.data
    assert b"assets/js/iam-sentinel-pagination.js" in response.data
    assert b"assets/js/iam-sentinel-identities.js" in response.data
    assert response.data.index(b"assets/js/iam-sentinel-pagination.js") < response.data.index(b"assets/js/iam-sentinel-identities.js")
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
    assert b'id="resources-page-size"' in response.data
    assert b'<option value="10" selected>10</option>' in response.data
    assert b'<option value="25">25</option>' in response.data
    assert b'<option value="50">50</option>' in response.data
    assert b'id="resources-pagination-summary"' in response.data
    assert b'id="resources-pagination-controls"' in response.data
    assert b'id="resources-prev-page"' in response.data
    assert b'id="resources-next-page"' in response.data
    assert b'id="total-resources"' in response.data
    assert b'id="sensitive-resources"' in response.data
    assert b'id="resources-with-external-access"' in response.data
    assert b'id="resources-with-service-account-access"' in response.data
    assert b'id="resources-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 8
    assert b'colspan="8"' in response.data
    assert b'id="resource-detail-link-marker"' in response.data
    assert b"assets/js/iam-sentinel-pagination.js" in response.data
    assert b"assets/js/iam-sentinel-resources.js" in response.data
    assert response.data.index(b"assets/js/iam-sentinel-pagination.js") < response.data.index(b"assets/js/iam-sentinel-resources.js")
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
    assert b'id="access-paths-page-size"' in response.data
    assert b'<option value="5" selected>5</option>' in response.data
    assert b'<option value="10" selected>10</option>' not in response.data
    assert b'<option value="10">10</option>' in response.data
    assert b'<option value="25">25</option>' in response.data
    assert b'<option value="50">50</option>' in response.data
    assert b'id="access-paths-pagination-summary"' in response.data
    assert b'id="access-paths-pagination-controls"' in response.data
    assert b'id="access-paths-prev-page"' in response.data
    assert b'id="access-paths-next-page"' in response.data
    assert b'id="total-access-paths"' in response.data
    assert b'id="sensitive-resource-paths"' in response.data
    assert b'id="external-identity-paths"' in response.data
    assert b'id="service-account-paths"' in response.data
    assert b'id="access-paths-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 6
    assert b'colspan="6"' in response.data
    assert b'table table-sm table-hover align-middle access-paths-table' in response.data
    assert b'id="access-path-detail-links"' in response.data
    assert b"assets/js/iam-sentinel-pagination.js" in response.data
    assert b"assets/js/iam-sentinel-access-paths.js" in response.data
    assert response.data.index(b"assets/js/iam-sentinel-pagination.js") < response.data.index(b"assets/js/iam-sentinel-access-paths.js")
    assert b"assets/js/iam-sentinel-resources.js" not in response.data
    assert b"Access Paths" in response.data
    assert b'href="/access-paths"' in response.data


def test_get_attack_graph_page_returns_workbench(client) -> None:
    response = client.get("/attack-graph")

    assert response.status_code == 200
    assert b"IAM Sentinel Attack Graph" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert b'id="attack-graph-workbench"' in response.data
    assert b'id="attack-graph-container"' in response.data
    assert b'id="attack-graph-svg"' in response.data
    assert b'id="attack-graph-detail"' in response.data
    assert b'id="attack-graph-path-list"' in response.data
    assert b'id="attack-graph-filter-controls"' in response.data
    assert b'data-filter-mode="all"' in response.data
    assert b'data-filter-mode="critical-high"' in response.data
    assert b'data-filter-mode="sensitive"' in response.data
    assert b"All paths" in response.data
    assert b"Critical/High only" in response.data
    assert b"Sensitive resources only" in response.data
    assert b"assets/js/iam-sentinel-attack-graph.js" in response.data
    assert b"assets/js/iam-sentinel-access-paths.js" not in response.data
    assert response.data.count(b"assets/js/iam-sentinel-attack-graph.js") == 1
    assert response.data.count(b'href="/attack-graph"') == 1
    assert b"Attack Graph" in response.data
    assert b'href="/attack-graph"' in response.data


def test_attack_graph_source_has_no_dead_access_paths_return_after_access_reviews_page() -> None:
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    access_reviews_page_match = re.search(
        r"def access_reviews_page\(\):(?P<body>.*?)(?:\n\n@app\.get|\Z)",
        source,
        re.S,
    )

    assert access_reviews_page_match is not None
    assert 'return render_template("access_reviews.html")' in access_reviews_page_match.group("body")
    assert "return jsonify(access_paths)" not in access_reviews_page_match.group("body")


def test_attack_graph_assets_are_declared_once() -> None:
    project_root = Path(__file__).resolve().parents[1]
    base_template = (project_root / "templates" / "base.html").read_text()
    graph_template = (project_root / "templates" / "attack_graph.html").read_text()
    styles = (
        project_root / "static" / "assets" / "css" / "iam-sentinel-polish.css"
    ).read_text()

    assert base_template.count('href="/attack-graph"') == 1
    assert base_template.count("<span>Attack Graph</span>") == 1
    assert graph_template.count("iam-sentinel-attack-graph.js") == 1
    assert styles.count(".attack-graph-card .card-body") == 1
    assert styles.count(".attack-graph-container") == 1
    assert styles.count(".attack-graph-node rect") == 1
    assert styles.count(".attack-graph-path-list") == 1


def test_attack_graph_readability_classes_and_filter_logic_exist() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (
        project_root / "static" / "assets" / "js" / "iam-sentinel-attack-graph.js"
    ).read_text()
    styles = (
        project_root / "static" / "assets" / "css" / "iam-sentinel-polish.css"
    ).read_text()

    assert "filterMode: 'all'" in script
    assert "function getFilteredPaths()" in script
    assert "state.filterMode === 'critical-high'" in script
    assert "state.filterMode === 'sensitive'" in script
    assert "state.filteredPaths = getFilteredPaths();" in script
    assert "getVisibleNodes()" in script
    assert "getVisibleEdges()" in script
    assert "attack-graph-focus-mode" in script
    assert "attack-graph-node-faded" in script
    assert "attack-graph-edge-faded" in script
    assert "attack-graph-path-critical" in script
    assert "attack-graph-path-high" in script
    assert "attack-graph-path-neutral" in script
    assert ".attack-graph-focus-mode .attack-graph-edge-selected" in styles
    assert ".attack-graph-edge-faded" in styles
    assert ".attack-graph-node-faded" in styles
    assert ".attack-graph-path-critical path" in styles
    assert ".attack-graph-path-high path" in styles
    assert ".attack-graph-path-neutral path" in styles


def test_attack_graph_js_has_single_state_and_selection_paths() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-attack-graph.js"
    ).read_text()
    state_match = re.search(
        r"const state = \{(?P<body>.*?)\n  \};\n  const columns",
        script,
        re.S,
    )
    selected_path_body = extract_js_function_body(script, "getSelectedPath")
    selected_node_body = extract_js_function_body(script, "getSelectedNode")

    assert state_match is not None
    assert state_match.group("body").count("selectedPathId:") == 1
    assert selected_path_body.count("return ") == 1
    assert selected_node_body.count("return ") == 1
    assert "state.graph.paths.find" not in selected_path_body
    assert "state.graph.nodes.find" not in selected_node_body


def test_attack_graph_template_has_single_legend_and_filter_controls() -> None:
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "attack_graph.html"
    ).read_text()

    assert template.count('id="attack-graph-filter-controls"') == 1
    assert template.count('class="attack-graph-legend"') == 1
    assert template.count('data-filter-mode="all"') == 1
    assert template.count('data-filter-mode="critical-high"') == 1
    assert template.count('data-filter-mode="sensitive"') == 1


def test_identity_remediation_uses_controlled_role_and_group_rendering() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-identity-detail.js"
    ).read_text()
    action_labels_body = extract_js_const_object_body(script, "actionLabels")

    assert "identity.available_roles" in script
    assert "identity.available_groups" in script
    assert "identity-remediation-new-role" in script
    assert "const actionLabels = {" in script
    assert "ACCEPT_RISK: 'Accept risk'" in script
    assert "new_role_id = document.getElementById('identity-remediation-new-role').value" in script
    assert "new_role_id = document.getElementById('identity-remediation-new-role').value.trim()" not in script
    assert "ADD_TO_GROUP" in script
    assert "CHANGE_GROUP" in script
    assert "formatStateChange(result.audit_event)" in script
    assert "fetchJson('/api/remediation-actions/preview'" in script
    assert "renderImpactPreview(preview)" in script
    assert "renderVerifiedImpactSummary(previewBeforeApply)" in script
    for action_type in [
        "ENABLE_MFA",
        "DISABLE_ACCOUNT",
        "REENABLE_ACCOUNT",
        "ADD_TO_GROUP",
        "CHANGE_GROUP",
        "REMOVE_FROM_GROUP",
        "REPLACE_ROLE",
        "ACCEPT_RISK",
    ]:
        assert action_labels_body.count(f"{action_type}:") == 1


def test_remediation_api_routes_do_not_keep_old_return_paths() -> None:
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    get_findings_source = extract_python_function_source(source, "get_findings")
    get_identities_source = extract_python_function_source(source, "get_identities")

    assert source.count("def identity_to_dict(") == 1
    assert get_findings_source.count("return jsonify") == 1
    assert "load_effective_iam_data()" in get_findings_source
    assert "finding_to_dict(finding, iam_data.users_by_id)" in get_findings_source
    assert "finding_to_dict(finding) for finding in findings" not in get_findings_source
    assert get_identities_source.count("return jsonify") == 1
    assert "identity_to_dict(user, iam_data)" in get_identities_source
    assert "identity_to_dict(user) for user in iam_data.users" not in get_identities_source


def test_identity_remediation_template_has_no_legacy_controls() -> None:
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "identity_detail.html"
    ).read_text()

    assert template.count('id="identity-remediation-old-group"') == 1
    assert template.count('id="identity-remediation-new-group"') == 1
    assert template.count('id="identity-remediation-old-role"') == 1
    assert template.count('id="identity-remediation-new-role"') == 1
    assert template.count('class="col-lg-2 col-md-6 identity-remediation-field"') == 4
    assert template.count('<div class="col-lg-2 col-md-6">') == 0
    assert 'id="identity-remediation-old-group-field"' in template
    assert 'id="identity-remediation-new-group-field"' in template
    assert 'id="identity-remediation-old-role-field"' in template
    assert 'id="identity-remediation-new-role-field"' in template
    assert not re.search(
        r'<div class="col-lg-2 col-md-6">\s*<div id="identity-remediation-[^"]+-field"',
        template,
    )
    assert 'id="identity-remediation-group"' not in template
    assert '<input id="identity-remediation-new-role"' not in template
    assert '<select id="identity-remediation-new-role"' in template
    assert 'id="identity-remediation-preview"' in template
    assert 'id="identity-remediation-verified-impact"' in template
    assert "No impact preview yet" in template


def test_identity_remediation_js_has_single_clean_action_flow() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-identity-detail.js"
    ).read_text()
    action_body = extract_js_function_body(script, "applyRemediationAction")

    assert script.count("async function fetchJson(") == 1
    assert script.count("function renderRemediationOptions(") == 1
    assert script.count("function updateRemediationFieldVisibility(") == 1
    assert script.count("async function applyRemediationAction(") == 1
    assert script.count("const groupSelect") == 0
    assert script.count("oldGroupSelect") >= 1
    assert script.count("newGroupSelect") >= 1
    assert "const actionFieldMap = {" in script
    assert "ENABLE_MFA: []" in script
    assert "DISABLE_ACCOUNT: []" in script
    assert "REENABLE_ACCOUNT: []" in script
    assert "ACCEPT_RISK: []" in script
    assert "ADD_TO_GROUP: ['new-group']" in script
    assert "REMOVE_FROM_GROUP: ['old-group']" in script
    assert "CHANGE_GROUP: ['old-group', 'new-group']" in script
    assert "REPLACE_ROLE: ['old-role', 'new-role']" in script
    assert "classList.toggle('d-none', !visibleFields.has(fieldName))" in script
    assert "updateRemediationFieldVisibility();" in script
    assert "refreshImpactPreview();" in script
    assert action_body.count("if (actionType === 'ADD_TO_GROUP')") == 1
    assert action_body.count("if (actionType === 'CHANGE_GROUP')") == 1
    assert action_body.count("if (actionType === 'REMOVE_FROM_GROUP')") == 1
    assert action_body.count("if (actionType === 'REPLACE_ROLE')") == 1
    assert (
        "payload.group_id = document.getElementById('identity-remediation-new-group').value;"
        in action_body
    )
    assert (
        "payload.group_id = document.getElementById('identity-remediation-old-group').value;"
        in action_body
    )
    assert (
        "payload.old_group_id = document.getElementById('identity-remediation-old-group').value;"
        in action_body
    )
    assert (
        "payload.new_group_id = document.getElementById('identity-remediation-new-group').value;"
        in action_body
    )
    assert action_body.count("payload.new_role_id =") == 1
    assert (
        "payload.new_role_id = document.getElementById('identity-remediation-new-role').value;"
        in action_body
    )
    assert "document.getElementById('identity-remediation-group')" not in action_body
    assert "Remediation action simulated." not in action_body
    assert action_body.count("showFeedback(`${actionLabels[actionType] || actionType} simulated.") == 1


def test_identity_detail_js_renders_preview_and_verified_impact() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-identity-detail.js"
    ).read_text()

    assert "function renderImpactPreview(preview)" in script
    assert "function renderVerifiedImpactSummary(preview)" in script
    assert "identity-remediation-preview" in script
    assert "identity-remediation-verified-impact" in script
    assert "Impact preview" in script
    assert "Verified impact" in script
    assert "Warning: this preview does not reduce access paths" in script
    assert "before.access_paths_count} &rarr; ${after.access_paths_count}" in script
    assert "preview.impact.before.access_paths_count} &rarr; ${accessPaths.length}" in script


def test_remediation_audit_page_exists_and_assets_are_single() -> None:
    project_root = Path(__file__).resolve().parents[1]
    base_template = (project_root / "templates" / "base.html").read_text()
    template = (project_root / "templates" / "remediation_audit.html").read_text()

    assert base_template.count('href="/remediation-audit"') == 1
    assert base_template.count("<span>Remediation Audit</span>") == 1
    assert template.count("iam-sentinel-remediation-audit.js") == 1
    assert 'id="remediation-audit-table-body"' in template
    assert 'id="remediation-audit-count"' in template


def test_remediation_audit_script_renders_newest_first() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "js"
        / "iam-sentinel-remediation-audit.js"
    ).read_text()
    action_labels_body = extract_js_const_object_body(script, "actionLabels")
    render_body = extract_js_function_body(script, "renderAudit")
    rendered_row_match = re.search(
        r"sortedEvents\.map\(\(event\) => `(?P<row>.*?)`\)\.join",
        render_body,
        re.S,
    )
    format_action_body = extract_js_function_body(script, "formatAction")
    format_state_body = extract_js_function_body(script, "formatState")

    assert "const sortedEvents = [...events].sort" in script
    assert "String(right.timestamp).localeCompare(String(left.timestamp))" in script
    assert "const formatTimestamp = ui.formatTimestamp" in script
    assert "formatTimestamp(event.timestamp)" in script
    assert "const actionLabels = {" in script
    assert "ENABLE_MFA: 'Enable MFA'" in script
    assert "ACCEPT_RISK: 'Accept risk'" in script
    assert "formatState(event.before)" in script
    assert "formatState(event.after)" in script
    assert 'class="remediation-audit-state-row"' in script
    assert 'class="remediation-audit-state-key"' in script
    assert 'class="remediation-audit-state-value"' in script
    assert "JSON.stringify" not in script
    for action_type in [
        "ENABLE_MFA",
        "DISABLE_ACCOUNT",
        "REENABLE_ACCOUNT",
        "ADD_TO_GROUP",
        "CHANGE_GROUP",
        "REMOVE_FROM_GROUP",
        "REPLACE_ROLE",
        "ACCEPT_RISK",
    ]:
        assert action_labels_body.count(f"{action_type}:") == 1
    assert rendered_row_match is not None
    rendered_row = rendered_row_match.group("row")
    assert rendered_row.count("<td") == 7
    assert "${escapeHtml(formatTimestamp(event.timestamp))}" in rendered_row
    assert "${escapeHtml(event.timestamp)}" not in rendered_row
    assert "${escapeHtml(formatTargetType(event.target_type))}" in rendered_row
    assert "${escapeHtml(event.target_type)}" not in rendered_row
    assert rendered_row.count("event.target_id") == 1
    assert rendered_row.count("remediation-audit-reason") == 1
    assert rendered_row.count("event.reason") == 1
    assert format_action_body.count("return ") == 1
    assert "return actionLabels[actionType] || String(actionType || '').replaceAll('_', ' ');" in format_action_body
    assert "return String(actionType || '').replaceAll('_', ' ');" not in format_action_body
    assert format_state_body.count('class="remediation-audit-state"') == 1
    assert "Object.entries(state).map" not in format_state_body
    assert '<div><span class="text-muted">' not in format_state_body


def test_attack_graph_css_blocks_are_balanced_and_not_duplicate_properties() -> None:
    styles = (
        Path(__file__).resolve().parents[1]
        / "static"
        / "assets"
        / "css"
        / "iam-sentinel-polish.css"
    ).read_text()
    guarded_properties = {
        "min-width",
        "max-width",
        "font-size",
        "padding",
        "stroke",
        "stroke-width",
    }

    assert styles.count("{") == styles.count("}")
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", styles):
        if "attack-graph" not in selector:
            continue
        properties = [
            line.split(":", 1)[0].strip()
            for line in body.splitlines()
            if ":" in line and not line.strip().startswith("/*")
        ]
        guarded = [
            property_name
            for property_name in properties
            if property_name in guarded_properties
        ]
        assert len(guarded) == len(set(guarded))


@pytest.mark.parametrize(
    ("script_path", "page_size_id", "prev_id", "next_id"),
    [
        ("static/assets/js/iam-sentinel-identities.js", "identities-page-size", "identities-prev-page", "identities-next-page"),
        ("static/assets/js/iam-sentinel-resources.js", "resources-page-size", "resources-prev-page", "resources-next-page"),
        ("static/assets/js/iam-sentinel-access-paths.js", "access-paths-page-size", "access-paths-prev-page", "access-paths-next-page"),
    ],
)
def test_workbench_scripts_use_shared_table_pagination(script_path, page_size_id, prev_id, next_id) -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / script_path).read_text()
    helper = (project_root / "static/assets/js/iam-sentinel-pagination.js").read_text()

    assert "window.IamSentinelPagination.createTablePager" in script
    assert ".paginate(state.filtered" in script
    assert ".resetPage();" in script
    assert ".wireEvents(" in script
    assert page_size_id in script
    assert prev_id in script
    assert next_id in script
    assert "function createTablePager(options)" in helper
    assert "items.slice(start, start + state.pageSize)" in helper
    assert "Showing ${start}\\u2013${end} of ${state.totalItems}" in helper


def test_shared_ui_formats_backend_status_labels() -> None:
    project_root = Path(__file__).resolve().parents[1]
    helper = (project_root / "static/assets/js/iam-sentinel-ui.js").read_text()

    for raw_status, label in {
        "UNDER_REVIEW": "Under Review",
        "OPEN": "Open",
        "REMEDIATED": "Remediated",
        "FALSE_POSITIVE": "False Positive",
        "CLOSED": "Closed",
    }.items():
        assert f"{raw_status}: '{label}'" in helper

    assert "function formatStatus(status)" in helper
    assert "function formatIdentityLabel(" in helper
    assert "function formatResourceLabel(" in helper
    assert "`${name} (${id})`" in helper
    assert "SUPPRESSED: 'Suppressed'" in helper
    assert ".split('_')" in helper
    assert "formatStatus," in helper
    assert "formatIdentityLabel," in helper
    assert "formatResourceLabel," in helper


def test_finding_status_dropdowns_keep_values_but_use_readable_labels() -> None:
    project_root = Path(__file__).resolve().parents[1]
    template_paths = [
        project_root / "templates/findings.html",
        project_root / "templates/finding_detail.html",
    ]
    templates_text = "\n".join(path.read_text() for path in template_paths)

    for value, label in {
        "OPEN": "Open",
        "UNDER_REVIEW": "Under Review",
        "REMEDIATED": "Remediated",
        "FALSE_POSITIVE": "False Positive",
        "SUPPRESSED": "Suppressed",
    }.items():
        assert f'<option value="{value}">{label}</option>' in templates_text
        assert f'<option value="{value}">{value}</option>' not in templates_text

    for template_path in template_paths:
        template = template_path.read_text()
        assert '<option value="OPEN">OPEN</option>' not in template
        assert '<option value="REMEDIATED">REMEDIATED</option>' not in template
        assert '<option value="SUPPRESSED">SUPPRESSED</option>' not in template


def test_finding_status_dropdowns_do_not_duplicate_status_options() -> None:
    project_root = Path(__file__).resolve().parents[1]
    expected_options = [
        ('OPEN', 'Open'),
        ('UNDER_REVIEW', 'Under Review'),
        ('REMEDIATED', 'Remediated'),
        ('FALSE_POSITIVE', 'False Positive'),
        ('SUPPRESSED', 'Suppressed'),
    ]

    for relative_path in [
        "templates/findings.html",
        "templates/finding_detail.html",
    ]:
        template = (project_root / relative_path).read_text()
        status_selects = re.findall(
            r'<select[^>]*id="(?:status-filter|bulk-status-select|finding-status-select)"[^>]*>(.*?)</select>',
            template,
            flags=re.DOTALL,
        )

        assert status_selects
        for select_markup in status_selects:
            for value, label in expected_options:
                assert select_markup.count(f'<option value="{value}">{label}</option>') == 1
                assert f'<option value="{value}">{value}</option>' not in select_markup


@pytest.mark.parametrize(
    ("script_path", "expected_usage"),
    [
        ("static/assets/js/iam-sentinel-findings.js", "formatStatus(finding.status)"),
        ("static/assets/js/iam-sentinel-finding-detail.js", "formatStatus(finding.status)"),
        ("static/assets/js/iam-sentinel-identity-detail.js", "formatStatus(finding.status)"),
        ("static/assets/js/iam-sentinel-resource-detail.js", "formatStatus(finding.status)"),
    ],
)
def test_finding_status_render_paths_use_readable_status_labels(script_path, expected_usage) -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / script_path).read_text()

    assert "const formatStatus = ui.formatStatus || ((status) => status);" in script
    assert expected_usage in script
    assert "${escapeHtml(finding.status)}</td>" not in script
    assert "textContent = finding.status" not in script
    assert "setText('finding-detail-status', finding.status);" not in script


def test_access_paths_workbench_uses_compact_analyst_table_polish() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-access-paths.js").read_text()
    styles = (project_root / "static/assets/css/iam-sentinel-polish.css").read_text()

    assert 'class="access-path-row"' in script
    assert 'class="access-path-name"' in script
    assert "formatIdentityLabel(accessPath.identity_name, accessPath.identity_id)" in script
    assert "formatResourceLabel(accessPath.resource_name, accessPath.resource_id)" in script
    assert 'class="table-truncate access-path-display" title="${pathDisplay}"' in script
    assert 'btn-group btn-group-sm access-path-actions' in script
    assert "btn-outline-success create-review-button" not in script
    assert "btn-outline-secondary create-review-button" in script
    assert "data-identity-id" in script
    assert "data-resource-id" in script
    assert ".access-paths-table .access-path-actions" in styles
    assert "flex-wrap: nowrap;" in styles
    assert "font-size: 0.76rem;" in styles
    assert "border-color: #0d6efd;" in styles
    assert "font-weight: 600;" in styles
    assert ".access-paths-table .access-path-id" not in styles
    assert ".access-paths-table .access-path-display" in styles


def test_access_paths_row_template_has_one_of_each_action() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-access-paths.js").read_text()
    action_match = re.search(
        r'<div class="btn-group btn-group-sm access-path-actions"[^>]*>(.*?)</div>',
        script,
        flags=re.DOTALL,
    )

    assert action_match
    action_markup = action_match.group(1)
    assert action_markup.count('>Identity</a>') == 1
    assert action_markup.count('>Resource</a>') == 1
    assert action_markup.count('>Create Review</button>') == 1
    assert action_markup.count('href="/identities/${encodeURIComponent(accessPath.identity_id)}"') == 1
    assert action_markup.count('href="/resources/${encodeURIComponent(accessPath.resource_id)}"') == 1
    assert action_markup.count('class="btn btn-outline-secondary create-review-button"') == 1
    assert action_markup.count('create-review-button') == 1
    assert action_markup.count('/identities/${encodeURIComponent(accessPath.identity_id)}') == 1


def test_identity_workbench_uses_readable_table_labels_and_truncation() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-identities.js").read_text()
    styles = (project_root / "static/assets/css/iam-sentinel-polish.css").read_text()

    for raw_type, label in {
        "normal_user": "Normal User",
        "external_contractor": "External Contractor",
        "service_account": "Service Account",
        "dormant_user": "Dormant User",
        "admin": "Admin",
        "developer": "Developer",
        "security_admin": "Security Admin",
    }.items():
        assert f"{raw_type}: '{label}'" in script

    assert "formatIdentityType(identity.type)" in script
    assert 'class="table-truncate table-email" title="${email}"' in script
    assert 'class="table-nowrap"' in script
    assert 'href="/identities/${encodeURIComponent(identity.id)}">View</a>' in script
    assert '>${escapeHtml(identity.id)}</a>' not in script
    assert ".table .table-truncate" in styles
    assert "text-overflow: ellipsis;" in styles
    assert ".table .table-nowrap" in styles


def test_identity_detail_related_findings_use_investigation_action_label() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-identity-detail.js").read_text()

    assert 'href="/findings/${encodeURIComponent(finding.id)}">Open Investigation</a>' in script
    assert '>${escapeHtml(finding.id)}</a>' not in script


def test_resource_workbench_uses_readable_type_labels_and_view_actions() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-resources.js").read_text()

    for raw_type, label in {
        "document_store": "Document Store",
        "code_repository": "Code Repository",
        "application": "Application",
        "database": "Database",
        "identity_store": "Identity Store",
        "iam_configuration": "IAM Configuration",
        "business_application": "Business Application",
        "log_archive": "Log Archive",
        "security_application": "Security Application",
        "data_warehouse": "Data Warehouse",
    }.items():
        assert f"{raw_type}: '{label}'" in script

    assert "function formatResourceType(type)" in script
    assert "formatResourceType(resource.type)" in script
    assert ".split('_')" in script
    assert 'class="table-nowrap"' in script
    assert 'href="/resources/${encodeURIComponent(resource.id)}">View</a>' in script
    assert '>${escapeHtml(resource.id)}</a>' not in script


def test_resource_detail_related_findings_use_investigation_action_label() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-resource-detail.js").read_text()

    assert 'href="/findings/${encodeURIComponent(finding.id)}">Open Investigation</a>' in script
    assert '>${escapeHtml(finding.id)}</a>' not in script


def test_resource_detail_uses_readable_type_labels() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-resource-detail.js").read_text()

    for raw_type, label in {
        "document_store": "Document Store",
        "code_repository": "Code Repository",
        "application": "Application",
        "database": "Database",
        "identity_store": "Identity Store",
        "iam_configuration": "IAM Configuration",
        "business_application": "Business Application",
        "log_archive": "Log Archive",
        "security_application": "Security Application",
        "data_warehouse": "Data Warehouse",
    }.items():
        assert f"{raw_type}: '{label}'" in script

    assert "function formatResourceType(type)" in script
    assert "setText('resource-detail-type', formatResourceType(resource.type));" in script
    assert "setText('resource-detail-type', resource.type);" not in script
    assert ".split('_')" in script


def test_get_access_reviews_page_returns_workbench(client) -> None:
    response = client.get("/access-reviews")

    assert response.status_code == 200
    assert b"IAM Sentinel Access Reviews" in response.data
    assert response.data.count(b'<main id="main" class="main">') == 1
    assert b'id="access-reviews-workbench"' in response.data
    assert response.data.count(b'access-review-metric-card') == 10
    assert response.data.count(b'id="access-review-decision-chart"') == 1
    assert response.data.count(b'id="access-review-status-chart"') == 1
    assert response.data.count(b'id="access-reviews-count"') == 1
    assert response.data.count(b'class="table table-sm table-hover align-middle access-reviews-table"') == 1
    assert b'id="total-access-reviews"' in response.data
    assert b'id="open-access-reviews"' in response.data
    assert b'id="completed-access-reviews"' in response.data
    assert b'id="revoke-access-reviews"' in response.data
    assert b'id="access-review-analytics-cards"' in response.data
    assert b'id="in-review-access-reviews"' in response.data
    assert b'id="stale-access-reviews"' in response.data
    assert b'id="needs-follow-up-access-reviews"' in response.data
    assert b'id="unique-access-reviewers"' in response.data
    assert b'id="pending-remediations"' in response.data
    assert b'id="completed-remediations"' in response.data
    assert b'id="access-review-analytics"' in response.data
    assert b'id="access-review-decision-chart"' in response.data
    assert b'id="access-review-decision-summary"' in response.data
    assert b'id="access-review-status-chart"' in response.data
    assert b'id="access-review-status-summary"' in response.data
    assert b'id="access-review-analytics-tables"' in response.data
    assert b'id="top-reviewed-resources-table"' in response.data
    assert b'id="top-reviewed-identities-table"' in response.data
    assert b'id="reviewer-workload-table"' in response.data
    assert b'id="access-reviews-page-size"' in response.data
    assert b'id="access-review-current-analyst"' in response.data
    assert b'<option value="5" selected>5</option>' in response.data
    assert b'<option value="10">10</option>' in response.data
    assert b'<option value="25">25</option>' in response.data
    assert b'id="access-reviews-pagination-summary"' in response.data
    assert b'id="access-reviews-pagination-controls"' in response.data
    assert b'id="access-reviews-prev-page"' in response.data
    assert b'id="access-reviews-next-page"' in response.data
    assert b'id="access-reviews-table-body"' in response.data
    assert response.data.count(b'<th scope="col">') == 9
    assert b'colspan="9"' in response.data
    assert b'colspan="8"' not in response.data
    assert b'Identity' in response.data
    assert b'Resource' in response.data
    assert b'Status' in response.data
    assert b'Reviewer' in response.data
    assert b'Decision' in response.data
    assert b'Remediation' in response.data
    assert b'Updated' in response.data
    assert b'Notes' in response.data
    assert b'Actions' in response.data
    assert b'table table-sm table-hover align-middle access-reviews-table' in response.data
    assert b'id="access-review-actions-marker"' in response.data
    assert b'id="access-review-history-modal"' in response.data
    assert b'id="access-review-history-table"' in response.data
    assert b"assets/js/iam-sentinel-access-reviews.js" in response.data
    assert b"Access Reviews" in response.data
    assert b'href="/access-reviews"' in response.data


def test_access_review_store_insert_statements_have_one_values_clause_and_matching_placeholders() -> None:
    project_root = Path(__file__).resolve().parents[1]
    source = (project_root / "core/access_review_store.py").read_text()
    insert_statements = re.findall(
        r"INSERT INTO\s+\w+\s*\((.*?)\)\s*VALUES\s*\((.*?)\)",
        source,
        flags=re.DOTALL,
    )

    assert len(insert_statements) == source.count("INSERT INTO")
    for columns_sql, placeholders_sql in insert_statements:
        statement_start = source.index(columns_sql) + len(columns_sql)
        statement_tail = source[statement_start:source.index('"""', statement_start)]
        assert statement_tail.count("VALUES") == 1

        columns = [
            column.strip()
            for column in columns_sql.split(",")
            if column.strip()
        ]
        placeholders = re.findall(r"\?", placeholders_sql)
        assert len(placeholders) == len(columns)


def test_access_review_store_has_single_remediation_column_schema_path() -> None:
    project_root = Path(__file__).resolve().parents[1]
    source = (project_root / "core/access_review_store.py").read_text()
    create_table_match = re.search(
        r"CREATE TABLE IF NOT EXISTS access_reviews \((.*?)\)",
        source,
        flags=re.DOTALL,
    )

    assert create_table_match
    assert create_table_match.group(1).count("remediation_status TEXT NOT NULL") == 1
    assert source.count("ALTER TABLE access_reviews ADD COLUMN remediation_status") == 1


def test_access_review_row_to_review_maps_selected_columns_in_order() -> None:
    review = row_to_review((
        "review-123",
        "user-001",
        "res-payroll-system",
        "IN_REVIEW",
        "analyst@example.local",
        "REVOKE",
        "PENDING",
        "Remove stale access.",
        "2026-05-01T00:00:00+00:00",
        "2026-05-02T00:00:00+00:00",
    ))

    assert review.id == "review-123"
    assert review.identity_id == "user-001"
    assert review.resource_id == "res-payroll-system"
    assert review.status == AccessReviewStatus.IN_REVIEW
    assert review.reviewer == "analyst@example.local"
    assert review.decision == AccessReviewDecision.REVOKE
    assert review.remediation_status == AccessReviewRemediationStatus.PENDING
    assert review.notes == "Remove stale access."
    assert review.created_at == "2026-05-01T00:00:00+00:00"
    assert review.updated_at == "2026-05-02T00:00:00+00:00"


def test_access_review_serialization_includes_remediation_status() -> None:
    review = AccessReview(
        id="review-123",
        identity_id="user-001",
        resource_id="res-payroll-system",
        status=AccessReviewStatus.COMPLETED,
        reviewer="analyst@example.local",
        decision=AccessReviewDecision.REVOKE,
        remediation_status=AccessReviewRemediationStatus.COMPLETED,
        notes="Access removed.",
        created_at="2026-05-01T00:00:00+00:00",
        updated_at="2026-05-02T00:00:00+00:00",
    )

    assert access_review_to_dict(review)["remediation_status"] == "COMPLETED"


def test_access_review_load_backfills_stored_remediation_status(client) -> None:
    revoke_review = client.post(
        "/api/access-reviews",
        json={"identity_id": "user-004", "resource_id": "res-customer-database"},
    ).get_json()
    follow_up_review = client.post(
        "/api/access-reviews",
        json={"identity_id": "user-006", "resource_id": "res-payroll-system"},
    ).get_json()

    with sqlite3.connect(app.config["FINDINGS_DB_PATH"]) as connection:
        connection.execute(
            "UPDATE access_reviews SET decision = ?, remediation_status = ? WHERE id = ?",
            ("REVOKE", "NOT_REQUIRED", revoke_review["id"]),
        )
        connection.execute(
            "UPDATE access_reviews SET decision = ?, remediation_status = ? WHERE id = ?",
            ("NEEDS_FOLLOW_UP", "NOT_REQUIRED", follow_up_review["id"]),
        )

    response = client.get("/api/access-reviews")

    assert response.status_code == 200
    reviews_by_id = {
        review["id"]: review
        for review in response.get_json()
    }
    assert reviews_by_id[revoke_review["id"]]["decision"] == "REVOKE"
    assert reviews_by_id[revoke_review["id"]]["remediation_status"] == "PENDING"
    assert reviews_by_id[follow_up_review["id"]]["decision"] == "NEEDS_FOLLOW_UP"
    assert reviews_by_id[follow_up_review["id"]]["remediation_status"] == "PENDING"


def test_access_reviews_template_has_no_duplicate_metric_card_wrappers() -> None:
    project_root = Path(__file__).resolve().parents[1]
    template = (project_root / "templates/access_reviews.html").read_text()

    assert template.count('<div class="card info-card access-review-metric-card">') == 10
    assert template.count('colspan="9"') == 1
    assert 'colspan="8"' not in template
    assert '<div class="card info-card">\n          <div class="card info-card access-review-metric-card">' not in template
    assert '<div class="card info-card access-review-metric-card">\n          <div class="card info-card">' not in template


def test_access_reviews_script_uses_compact_charts_pagination_and_readable_labels() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-access-reviews.js").read_text()
    styles = (project_root / "static/assets/css/iam-sentinel-polish.css").read_text()

    assert "pageSize: 5" in script
    assert script.count("statusChart: null") == 1
    assert "getPaginatedReviews()" in script
    assert "renderPaginationControls(visibleReviews)" in script
    assert "access-reviews-page-size" in script
    assert "access-reviews-prev-page" in script
    assert "access-reviews-next-page" in script
    assert "Showing ${start}\\u2013${end} of ${totalReviews} reviews" in script
    assert "maintainAspectRatio: false" in script
    assert "cutout: '68%'" in script
    assert "access-review-decision-summary" in script
    assert "access-review-status-summary" in script
    assert "ui.formatTimestamp(review.updated_at)" in script
    assert "state.reviews.map" not in script
    assert "review.updated_at}</" not in script
    assert "${ui.escapeHtml(review.updated_at)}" not in script
    assert "<textarea" not in script
    assert "const notesStateClass = review.notes ? 'access-review-notes-filled' : 'access-review-notes-empty';" in script
    assert script.count('class="form-control form-control-sm table-truncate access-review-notes ${notesStateClass} review-notes"') == 1
    assert script.count("row.querySelector('.review-notes').value") == 1
    assert script.count('class="form-control form-control-sm table-truncate access-review-reviewer review-reviewer"') == 1
    assert script.count("row.querySelector('.review-reviewer').value") == 1
    assert "const statusOptions = ['OPEN', 'IN_REVIEW', 'COMPLETED'];" in script
    assert "const decisionOptions = ['UNDECIDED', 'APPROVE', 'REVOKE', 'NEEDS_FOLLOW_UP'];" in script
    assert "statusOptions.map((status) => option(status, review.status, formatReviewStatus(status))).join('')" in script
    assert "decisionOptions.map((decision) => option(decision, review.decision, formatReviewDecision(decision))).join('')" in script
    assert "formatReviewStatus(status)" in script
    assert "formatReviewDecision(decision)" in script
    assert "function formatRemediationStatus(status)" in script
    assert "NOT_REQUIRED: 'Not Required'" in script
    assert "PENDING: 'Pending'" in script
    assert "formatRemediationStatus(review.remediation_status)" in script
    assert "complete-remediation-button" in script
    assert 'class="table-truncate access-review-identity"' in script
    assert 'title="${identityId}"' in script
    assert '>${identityId}</a>' in script
    assert '>${ui.escapeHtml(review.identity_id)}</a>' not in script
    assert 'class="table-truncate access-review-resource"' in script
    assert 'title="${resourceId}"' in script
    assert '>${resourceId}</a>' in script
    assert '>${ui.escapeHtml(review.resource_id)}</a>' not in script
    assert script.count("event.target.closest('.complete-remediation-button')") == 1
    assert script.count("completeRemediation(row);") == 1
    assert "function completeRemediation(row)" in script
    assert "ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}/remediation`" in script
    assert "pending-remediations" in script
    assert "completed-remediations" in script
    assert "review-history-button" in script
    assert "const analystStorageKey = 'iamSentinelAccessReviewAnalyst';" in script
    assert "function getCurrentAnalyst()" in script
    assert "function loadCurrentAnalyst()" in script
    assert "function saveCurrentAnalyst()" in script
    assert "localStorage.getItem(analystStorageKey)" in script
    assert "localStorage.setItem(analystStorageKey, getCurrentAnalyst())" in script
    assert "actor: getCurrentAnalyst()" in script
    assert "function showReviewHistory(row)" in script
    assert "const identity = row.querySelector('.access-review-identity')?.getAttribute('title') || '';" in script
    assert "const resource = row.querySelector('.access-review-resource')?.getAttribute('title') || '';" in script
    assert "historyMeta.innerHTML" in script
    assert "${ui.escapeHtml(identity)} &rarr; ${ui.escapeHtml(resource)}" in script
    assert "Review ID: ${ui.escapeHtml(reviewId)}" in script
    assert "ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}/history`)" in script
    assert "ui.formatTimestamp(event.timestamp)" in script
    assert "event.actor || 'Unassigned Analyst'" in script
    assert "formatHistoryValue(event.changed_field, event.old_value)" in script
    assert "formatHistoryValue(event.changed_field, event.new_value)" in script
    history_field_match = re.search(
        r"function formatHistoryField\(field\) \{\s+return \{(.*?)\s+\}\[field\]",
        script,
        flags=re.DOTALL,
    )
    assert history_field_match
    history_field_map = history_field_match.group(1)
    assert history_field_map.count("remediation_status:") == 1
    assert history_field_map.count("remediation_completed:") == 1
    assert "remediation_status: 'Remediation Status'" in history_field_map
    assert "remediation_completed: 'Remediation Completion'" in history_field_map
    assert "remediation_status: 'Remediation'," not in history_field_map
    assert "remediation_completed: 'Remediation Completed'" not in history_field_map
    assert "IN_REVIEW: 'In Review'" in script
    assert "COMPLETED: 'Completed'" in script
    assert "COMPLET: 'Completed'" in script
    assert "UNDECIDED: 'Undecided'" in script
    assert "NEEDS_FOLLOW_UP: 'Needs Follow-up'" in script
    assert "NEEDS_FOLLOW: 'Needs Follow-up'" in script
    for hardcoded_status_option in [
        "option('OPEN', review.status, formatReviewStatus('OPEN'))",
        "option('IN_REVIEW', review.status, formatReviewStatus('IN_REVIEW'))",
        "option('COMPLETED', review.status, formatReviewStatus('COMPLETED'))",
    ]:
        assert hardcoded_status_option not in script
    for hardcoded_decision_option in [
        "option('UNDECIDED', review.decision, formatReviewDecision('UNDECIDED'))",
        "option('APPROVE', review.decision, formatReviewDecision('APPROVE'))",
        "option('REVOKE', review.decision, formatReviewDecision('REVOKE'))",
        "option('NEEDS_FOLLOW_UP', review.decision, formatReviewDecision('NEEDS_FOLLOW_UP'))",
    ]:
        assert hardcoded_decision_option not in script
    assert ".access-review-chart-card" in styles
    assert ".access-review-chart-summary" in styles
    assert ".access-reviews-table {\n  table-layout: fixed;\n  width: 100%;" in styles
    assert ".access-reviews-table .review-decision" in styles
    assert "min-width: min(8rem, 100%);" in styles
    assert ".access-reviews-table td:nth-child(6)" in styles
    assert ".access-reviews-table td:nth-child(7) .table-nowrap" in styles
    assert ".access-reviews-table .save-review-button" in styles
    assert ".access-reviews-table .access-review-identity" in styles
    assert ".access-reviews-table .access-review-resource" in styles
    assert "max-width: 100%;" in styles
    assert 'btn-link text-secondary review-history-button' in script
    assert "access-review-actions" in script
    assert ".access-reviews-table .access-review-actions" in styles
    assert ".access-reviews-table .review-history-button" in styles
    assert "text-decoration: none;" in styles
    assert styles.count("{") == styles.count("}")
    for selector, body in re.findall(r"([^{}]+)\{([^{}]+)\}", styles):
        if ".access-reviews-table" not in selector:
            continue
        properties = [
            line.split(":", 1)[0].strip()
            for line in body.splitlines()
            if ":" in line
        ]
        for property_name in ["min-width", "max-width", "font-size", "padding"]:
            assert properties.count(property_name) <= 1
    assert ".access-review-metric-card .card-body" in styles
    assert "min-height: 92px;" in styles
    assert ".reviewer-workload-label" in styles
    assert ".reviewer-workload-count" in styles
    assert "id === 'reviewer-workload-table'" in script
    assert 'class="table-truncate reviewer-workload-label" title="${label}"' in script
    assert 'class="text-end reviewer-workload-count"' in script
    assert ".access-reviews-table .access-review-notes-empty" in styles
    assert ".access-reviews-table .access-review-notes-filled" in styles
    assert script.count('colspan="9"') == 1
    assert 'colspan="8"' not in script


def test_access_reviews_row_template_renders_one_notes_input() -> None:
    project_root = Path(__file__).resolve().parents[1]
    script = (project_root / "static/assets/js/iam-sentinel-access-reviews.js").read_text()
    row_match = re.search(
        r'<tr data-review-id="\$\{ui\.escapeHtml\(review\.id\)\}">(.*?)</tr>',
        script,
        flags=re.DOTALL,
    )

    assert row_match
    row_template = row_match.group(1)
    assert row_template.count('href="/identities/${encodeURIComponent(review.identity_id)}"') == 1
    assert row_template.count('access-review-identity') == 1
    assert row_template.count('title="${identityId}"') == 1
    assert row_template.count('>${identityId}</a>') == 1
    assert '<td><a href="/identities/${encodeURIComponent(review.identity_id)}">${ui.escapeHtml(review.identity_id)}</a></td>' not in row_template
    assert row_template.count('href="/resources/${encodeURIComponent(review.resource_id)}"') == 1
    assert row_template.count('access-review-resource') == 1
    assert row_template.count('title="${resourceId}"') == 1
    assert row_template.count('>${resourceId}</a>') == 1
    assert '<td><a href="/resources/${encodeURIComponent(review.resource_id)}">${ui.escapeHtml(review.resource_id)}</a></td>' not in row_template
    assert row_template.count('save-review-button') == 1
    assert row_template.count('review-history-button') == 1
    assert row_template.count('<div class="d-inline-flex gap-1 access-review-actions">') == 1
    assert '<div class="d-inline-flex gap-1">' not in row_template
    assert 'btn btn-sm btn-outline-secondary review-history-button' not in row_template
    assert 'btn btn-sm btn-link text-secondary review-history-button' in row_template
    assert row_template.count('review-notes"') == 1
    assert row_template.count('access-review-notes ${notesStateClass} review-notes') == 1
    assert '<textarea' not in row_template
    assert '${notesStateClass}' in row_template


def test_access_review_history_events_append_for_changed_fields(client) -> None:
    create_response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )
    review_id = create_response.get_json()["id"]

    response = client.patch(
        f"/api/access-reviews/{review_id}",
        json={
            "status": "COMPLETED",
            "reviewer": "analyst@example.local",
            "decision": "REVOKE",
            "notes": "Removed stale access.",
            "actor": "Maya Analyst <maya@example.local>",
        },
    )
    history_response = client.get(f"/api/access-reviews/{review_id}/history")

    assert response.status_code == 200
    assert history_response.status_code == 200
    history = history_response.get_json()
    assert len(history) == 5
    assert {event["changed_field"] for event in history} == {
        "status",
        "reviewer",
        "decision",
        "remediation_status",
        "notes",
    }
    assert all(event["review_id"] == review_id for event in history)
    assert all(event["actor"] == "Maya Analyst <maya@example.local>" for event in history)
    assert all(event["timestamp"] for event in history)
    events_by_field = {
        event["changed_field"]: event
        for event in history
    }
    assert events_by_field["status"]["old_value"] == "OPEN"
    assert events_by_field["status"]["new_value"] == "COMPLETED"
    assert events_by_field["reviewer"]["old_value"] is None
    assert events_by_field["reviewer"]["new_value"] == "analyst@example.local"
    assert events_by_field["decision"]["old_value"] == "UNDECIDED"
    assert events_by_field["decision"]["new_value"] == "REVOKE"
    assert events_by_field["remediation_status"]["old_value"] == "NOT_REQUIRED"
    assert events_by_field["remediation_status"]["new_value"] == "PENDING"
    assert events_by_field["notes"]["old_value"] == ""
    assert events_by_field["notes"]["new_value"] == "Removed stale access."

    second_response = client.patch(
        f"/api/access-reviews/{review_id}",
        json={
            "status": "COMPLETED",
            "reviewer": "analyst@example.local",
            "decision": "REVOKE",
            "notes": "Confirmed with owner.",
            "actor": "Maya Analyst <maya@example.local>",
        },
    )
    second_history_response = client.get(f"/api/access-reviews/{review_id}/history")

    assert second_response.status_code == 200
    second_history = second_history_response.get_json()
    assert len(second_history) == 6
    assert second_history[0]["changed_field"] == "notes"
    assert second_history[0]["actor"] == "Maya Analyst <maya@example.local>"
    assert second_history[0]["old_value"] == "Removed stale access."
    assert second_history[0]["new_value"] == "Confirmed with owner."


def test_access_review_remediation_completion_flow(client) -> None:
    create_response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )
    review_id = create_response.get_json()["id"]

    revoke_response = client.patch(
        f"/api/access-reviews/{review_id}",
        json={
            "decision": "REVOKE",
            "actor": "Maya Analyst <maya@example.local>",
        },
    )
    metrics_after_revoke = client.get("/api/access-review-metrics").get_json()

    assert revoke_response.status_code == 200
    assert revoke_response.get_json()["decision"] == "REVOKE"
    assert revoke_response.get_json()["remediation_status"] == "PENDING"
    assert metrics_after_revoke["pending_remediations"] == 1
    assert metrics_after_revoke["completed_remediations"] == 0

    complete_response = client.patch(
        f"/api/access-reviews/{review_id}/remediation",
        json={"actor": "Maya Analyst <maya@example.local>"},
    )
    history_response = client.get(f"/api/access-reviews/{review_id}/history")
    metrics_after_complete = client.get("/api/access-review-metrics").get_json()

    assert complete_response.status_code == 200
    assert complete_response.get_json()["remediation_status"] == "COMPLETED"
    assert metrics_after_complete["pending_remediations"] == 0
    assert metrics_after_complete["completed_remediations"] == 1

    history = history_response.get_json()
    assert history[0]["changed_field"] == "remediation_completed"
    assert history[0]["old_value"] == "PENDING"
    assert history[0]["new_value"] == "COMPLETED"
    assert history[0]["actor"] == "Maya Analyst <maya@example.local>"
    remediation_status_events = [
        event
        for event in history
        if event["changed_field"] == "remediation_status"
    ]
    assert any(
        event["old_value"] == "NOT_REQUIRED" and event["new_value"] == "PENDING"
        for event in remediation_status_events
    )
    assert any(
        event["old_value"] == "PENDING" and event["new_value"] == "COMPLETED"
        for event in remediation_status_events
    )


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
    assert b'id="export-governance-pdf"' in response.data
    assert b'id="export-evidence-csv"' in response.data
    assert response.data.count(b"Export JSON") == 1
    assert response.data.count(b"Export PDF") == 1
    assert response.data.count(b"Export Evidence CSV") == 1
    assert b'id="export-governance-csv"' not in response.data
    assert b'id="export-findings-csv"' not in response.data
    assert b'id="export-access-reviews-csv"' not in response.data
    assert b'id="export-remediation-csv"' not in response.data
    assert b"Summary CSV" not in response.data
    assert b"Findings CSV" not in response.data
    assert b"Reviews CSV" not in response.data
    assert b"Remediation CSV" not in response.data
    assert b"Export CSV" not in response.data
    assert b"assets/js/iam-sentinel-reports.js" in response.data
    assert b"Reports" in response.data
    assert b'href="/reports"' in response.data


def test_report_template_has_no_duplicate_export_labels() -> None:
    template = (
        Path(__file__).resolve().parents[1] / "templates" / "reports.html"
    ).read_text()

    assert template.count("Export JSON") == 1
    assert template.count("Export PDF") == 1
    assert template.count("Export Evidence CSV") == 1
    assert "Summary CSV" not in template
    assert "Findings CSV" not in template
    assert "Reviews CSV" not in template
    assert "Remediation CSV" not in template
    assert "Export CSV" not in template


def test_demo_reset_script_is_scoped_to_local_sqlite_state() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "reset_demo_state.ps1"
    ).read_text()

    assert "data" in script
    assert "findings.db" in script
    assert "findings.db-wal" in script
    assert "findings.db-shm" in script
    assert "Remove-Item -LiteralPath $fullPath" in script
    assert "run_analysis()" in script
    assert "sample_iam.json" not in script
    assert "Remove-Item -Recurse" not in script
    assert "Refusing to remove path outside data directory" in script


def test_governance_summary_report_has_no_duplicate_literal_keys() -> None:
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    module = ast.parse(source)
    report_function = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "build_governance_summary_report"
    )

    for node in ast.walk(report_function):
        if not isinstance(node, ast.Dict):
            continue
        literal_keys = [
            key.value
            for key in node.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        assert len(literal_keys) == len(set(literal_keys))


def test_get_finding_detail_page_returns_investigation_shell(client) -> None:
    response = client.get("/findings/finding-low")

    assert response.status_code == 200
    assert b"IAM Sentinel Investigation" in response.data
    assert response.data.count(b'<main id="main" class="main"') == 1
    assert response.data.count(b"</main>") == 1
    assert b'data-finding-id="finding-low"' in response.data
    assert b'id="finding-detail-content"' in response.data
    assert b'id="finding-lifecycle-note-input"' in response.data
    assert b'id="finding-lifecycle-history"' in response.data
    assert b"Lifecycle History" in response.data
    assert b"False Positive" in response.data
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
    assert b'id="finding-detail-evidence"' in response.data
    assert b'id="finding-detail-attack-paths"' in response.data
    assert b'id="finding-detail-activity"' in response.data
    assert b'id="finding-detail-notes"' in response.data
    assert b"Analyst Actions" in response.data
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
    assert b'id="identity-remediation-action"' in response.data
    assert b'id="identity-remediation-reason"' in response.data
    assert b'id="identity-remediation-apply"' in response.data
    assert b'id="identity-remediation-new-role"' in response.data
    assert b'<input id="identity-remediation-new-role"' not in response.data
    assert b'id="identity-remediation-old-group"' in response.data
    assert b'id="identity-remediation-new-group"' in response.data
    assert b'id="identity-remediation-preview"' in response.data
    assert b'id="identity-remediation-verified-impact"' in response.data
    assert b"No impact preview yet" in response.data
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


def test_api_detail_payloads_include_display_labels(client) -> None:
    identity = client.get("/api/identities/user-003").get_json()
    resource = client.get("/api/resources/res-customer-database").get_json()
    finding = {
        item["id"]: item
        for item in client.get("/api/findings").get_json()
    }["finding-critical"]

    assert identity["label"] == "Ananya Rao (user-003)"
    assert resource["label"] == "Customer 360 Database (res-customer-database)"
    assert finding["identity_label"] == "Omar Haddad (user-002)"
    assert finding["resource_label"] == "Customer 360 Database (res-customer-database)"


def test_get_identity_detail_returns_effective_identity_fields(client) -> None:
    remediation_response = client.post(
        "/api/remediation-actions",
        json={"action_type": "ENABLE_MFA", "identity_id": "user-007"},
    )

    response = client.get("/api/identities/user-007")

    assert remediation_response.status_code == 201
    assert response.status_code == 200
    identity = response.get_json()
    assert identity["id"] == "user-007"
    assert identity["mfa_enabled"] is True
    assert {
        "name",
        "email",
        "type",
        "external_user",
        "service_account",
        "groups",
        "roles",
        "available_groups",
        "available_roles",
    }.issubset(identity)


def test_get_missing_identity_detail_returns_json_404(client) -> None:
    response = client.get("/api/identities/missing")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Identity not found."}


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


def test_get_resource_detail_returns_resource_fields(client) -> None:
    response = client.get("/api/resources/res-payroll-system")

    assert response.status_code == 200
    resource = response.get_json()
    assert resource["id"] == "res-payroll-system"
    assert resource["sensitive"] is True
    assert {
        "name",
        "type",
        "accessible_by",
        "accessible_by_count",
        "external_access_count",
        "service_account_access_count",
        "related_findings_count",
    }.issubset(resource)


def test_get_missing_resource_detail_returns_json_404(client) -> None:
    response = client.get("/api/resources/missing")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Resource not found."}


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


def test_get_attack_graph_returns_nodes_edges_and_paths(client) -> None:
    response = client.get("/api/attack-graph")

    assert response.status_code == 200
    graph = response.get_json()
    assert {"nodes", "edges", "paths"}.issubset(graph)
    assert graph["nodes"]
    assert graph["edges"]
    assert graph["paths"]
    assert {
        "id",
        "label",
        "type",
        "risky",
        "external_identity",
        "service_account",
        "privileged_role",
        "sensitive_resource",
        "critical_high_finding",
        "related_finding_count",
    }.issubset(graph["nodes"][0])
    assert {"id", "source", "target", "relationship"}.issubset(graph["edges"][0])
    assert {
        "id",
        "identity_id",
        "resource_id",
        "resource_sensitive",
        "path_nodes",
        "path_display",
        "path_length",
        "related_finding_count",
        "finding_severity",
    }.issubset(graph["paths"][0])
    assert graph["paths"][0]["path_length"] == len(graph["paths"][0]["path_nodes"]) - 1
    assert {path["finding_severity"] for path in graph["paths"]} & {"CRITICAL", "HIGH"}


def test_attack_graph_metadata_highlights_risky_elements(client) -> None:
    response = client.get("/api/attack-graph")

    assert response.status_code == 200
    nodes_by_id = {
        node["id"]: node
        for node in response.get_json()["nodes"]
    }
    assert nodes_by_id["user-004"]["external_identity"] is True
    assert nodes_by_id["user-006"]["service_account"] is True
    assert nodes_by_id["role-platform-admin"]["privileged_role"] is True
    assert nodes_by_id["res-customer-database"]["sensitive_resource"] is True
    assert nodes_by_id["res-customer-database"]["critical_high_finding"] is True
    assert nodes_by_id["res-customer-database"]["related_finding_count"] >= 1


def test_remediation_preview_returns_before_after_state_for_enable_mfa(client) -> None:
    response = client.post(
        "/api/remediation-actions/preview",
        json={"action_type": "ENABLE_MFA", "identity_id": "user-007"},
    )

    assert response.status_code == 200
    preview = response.get_json()
    assert preview["identity_id"] == "user-007"
    assert preview["action_type"] == "ENABLE_MFA"
    assert preview["before"]["mfa_enabled"] is False
    assert preview["after"]["mfa_enabled"] is True
    assert preview["before"]["disabled"] is False
    assert preview["after"]["disabled"] is False
    assert "access_paths_count" in preview["impact"]["before"]
    assert "access_paths_count" in preview["impact"]["after"]
    assert "affected_findings" in preview["impact"]


def test_remediation_preview_returns_path_counts_for_disable_account(client) -> None:
    response = client.post(
        "/api/remediation-actions/preview",
        json={"action_type": "DISABLE_ACCOUNT", "identity_id": "user-004"},
    )

    assert response.status_code == 200
    preview = response.get_json()
    assert preview["before"]["disabled"] is False
    assert preview["after"]["disabled"] is True
    assert preview["impact"]["before"]["access_paths_count"] > 0
    assert preview["impact"]["after"]["access_paths_count"] == 0
    assert preview["impact"]["before"]["sensitive_resources_count"] > 0
    assert preview["impact"]["after"]["sensitive_resources_count"] == 0
    assert preview["impact"]["risk_reduction"] is True


def test_remediation_preview_group_and_role_changes_do_not_mutate_state(client) -> None:
    change_group_response = client.post(
        "/api/remediation-actions/preview",
        json={
            "action_type": "CHANGE_GROUP",
            "identity_id": "user-001",
            "old_group_id": "grp-finance-readers",
            "new_group_id": "grp-engineering",
        },
    )
    replace_role_response = client.post(
        "/api/remediation-actions/preview",
        json={
            "action_type": "REPLACE_ROLE",
            "identity_id": "user-002",
            "old_role_id": "role-production-breakglass",
            "new_role_id": "role-finance-viewer",
        },
    )
    identities = {
        identity["id"]: identity
        for identity in client.get("/api/identities").get_json()
    }

    assert change_group_response.status_code == 200
    assert change_group_response.get_json()["before"]["groups"] == ["grp-finance-readers"]
    assert change_group_response.get_json()["after"]["groups"] == ["grp-engineering"]
    assert replace_role_response.status_code == 200
    assert "role-production-breakglass" in replace_role_response.get_json()["before"]["roles"]
    assert "role-finance-viewer" in replace_role_response.get_json()["after"]["roles"]
    assert identities["user-001"]["groups"] == ["grp-finance-readers"]
    assert "role-production-breakglass" in identities["user-002"]["roles"]
    assert "role-finance-viewer" not in identities["user-002"]["roles"]
    assert client.get("/api/remediation-audit").get_json() == []


def test_invalid_remediation_preview_payload_returns_json_error(client) -> None:
    missing_action = client.post("/api/remediation-actions/preview", json={})
    invalid_identity = client.post(
        "/api/remediation-actions/preview",
        json={"action_type": "ENABLE_MFA", "identity_id": "missing"},
    )
    invalid_change = client.post(
        "/api/remediation-actions/preview",
        json={"action_type": "CHANGE_GROUP", "identity_id": "user-001"},
    )

    assert missing_action.status_code == 400
    assert missing_action.get_json() == {"error": "Missing required field: action_type"}
    assert invalid_identity.status_code == 404
    assert invalid_identity.get_json() == {"error": "Identity not found."}
    assert invalid_change.status_code == 400
    assert invalid_change.get_json() == {
        "error": "Missing required fields: old_group_id and new_group_id"
    }


def test_enable_disable_and_reenable_identity_remediation_actions(client) -> None:
    enable_response = client.post(
        "/api/remediation-actions",
        json={"action_type": "ENABLE_MFA", "identity_id": "user-004"},
    )
    duplicate_response = client.post(
        "/api/remediation-actions",
        json={"action_type": "ENABLE_MFA", "identity_id": "user-004"},
    )
    disable_response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "DISABLE_ACCOUNT",
            "identity_id": "user-004",
            "reason": "Contractor access no longer approved.",
        },
    )
    paths_after_disable = client.get("/api/access-paths?identity_id=user-004")
    reenable_response = client.post(
        "/api/remediation-actions",
        json={"action_type": "REENABLE_ACCOUNT", "identity_id": "user-004"},
    )
    paths_after_reenable = client.get("/api/access-paths?identity_id=user-004")

    assert enable_response.status_code == 201
    assert enable_response.get_json()["identity"]["mfa_enabled"] is True
    assert duplicate_response.status_code == 409
    assert disable_response.status_code == 201
    assert disable_response.get_json()["identity"]["disabled"] is True
    assert paths_after_disable.status_code == 200
    assert paths_after_disable.get_json() == []
    assert reenable_response.status_code == 201
    assert reenable_response.get_json()["identity"]["disabled"] is False
    assert paths_after_reenable.status_code == 200
    assert paths_after_reenable.get_json()


def test_remove_identity_from_group_remediation_action(client) -> None:
    missing_reason = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "REMOVE_FROM_GROUP",
            "identity_id": "user-004",
            "group_id": "grp-engineering",
        },
    )
    response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "REMOVE_FROM_GROUP",
            "identity_id": "user-004",
            "group_id": "grp-engineering",
            "reason": "Contractor no longer belongs in engineering.",
        },
    )
    identity_response = client.get("/api/identities")

    assert missing_reason.status_code == 400
    assert response.status_code == 201
    identities_by_id = {
        identity["id"]: identity
        for identity in identity_response.get_json()
    }
    assert "grp-engineering" not in identities_by_id["user-004"]["groups"]


def test_replace_risky_role_remediation_action(client) -> None:
    response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "REPLACE_ROLE",
            "identity_id": "user-002",
            "old_role_id": "role-production-breakglass",
            "new_role_id": "role-finance-viewer",
            "reason": "Breakglass access replaced with read-only access.",
        },
    )
    identities = client.get("/api/identities").get_json()
    identities_by_id = {identity["id"]: identity for identity in identities}

    assert response.status_code == 201
    assert "role-production-breakglass" not in identities_by_id["user-002"]["roles"]
    assert "role-finance-viewer" in identities_by_id["user-002"]["roles"]


def test_replacement_role_must_be_valid_and_different(client) -> None:
    same_role = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "REPLACE_ROLE",
            "identity_id": "user-002",
            "old_role_id": "role-production-breakglass",
            "new_role_id": "role-production-breakglass",
            "reason": "No-op should not be allowed.",
        },
    )
    invalid_role = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "REPLACE_ROLE",
            "identity_id": "user-002",
            "old_role_id": "role-production-breakglass",
            "new_role_id": "role-missing",
            "reason": "Invalid role should not be allowed.",
        },
    )

    assert same_role.status_code == 409
    assert invalid_role.status_code == 404


def test_add_to_group_works_and_records_audit(client) -> None:
    response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "ADD_TO_GROUP",
            "identity_id": "user-001",
            "group_id": "grp-engineering",
            "reason": "Temporary engineering collaboration.",
            "actor": "iam-analyst@example.local",
        },
    )
    identities = {
        identity["id"]: identity
        for identity in client.get("/api/identities").get_json()
    }
    audit = client.get("/api/remediation-audit").get_json()

    assert response.status_code == 201
    assert "grp-engineering" in identities["user-001"]["groups"]
    assert audit[-1]["action_type"] == "ADD_TO_GROUP"
    assert audit[-1]["actor"] == "iam-analyst@example.local"
    assert "grp-engineering" not in audit[-1]["before"]["groups"]
    assert "grp-engineering" in audit[-1]["after"]["groups"]


def test_change_group_works_and_records_audit(client) -> None:
    response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "CHANGE_GROUP",
            "identity_id": "user-001",
            "old_group_id": "grp-finance-readers",
            "new_group_id": "grp-engineering",
            "reason": "Move user to engineering access profile.",
        },
    )
    identities = {
        identity["id"]: identity
        for identity in client.get("/api/identities").get_json()
    }
    audit = client.get("/api/remediation-audit").get_json()

    assert response.status_code == 201
    assert "grp-finance-readers" not in identities["user-001"]["groups"]
    assert "grp-engineering" in identities["user-001"]["groups"]
    assert audit[-1]["action_type"] == "CHANGE_GROUP"
    assert audit[-1]["before"]["groups"] == ["grp-finance-readers"]
    assert audit[-1]["after"]["groups"] == ["grp-engineering"]


def test_duplicate_and_noop_group_actions_return_conflict(client) -> None:
    duplicate_add = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "ADD_TO_GROUP",
            "identity_id": "user-001",
            "group_id": "grp-finance-readers",
            "reason": "Duplicate group membership.",
        },
    )
    same_group_change = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "CHANGE_GROUP",
            "identity_id": "user-001",
            "old_group_id": "grp-finance-readers",
            "new_group_id": "grp-finance-readers",
            "reason": "No-op group change.",
        },
    )

    assert duplicate_add.status_code == 409
    assert same_group_change.status_code == 409


def test_accept_risk_requires_reason_and_records_audit(client) -> None:
    missing_reason = client.post(
        "/api/remediation-actions",
        json={"action_type": "ACCEPT_RISK", "finding_id": "finding-critical"},
    )
    response = client.post(
        "/api/remediation-actions",
        json={
            "action_type": "ACCEPT_RISK",
            "finding_id": "finding-critical",
            "reason": "Temporary exception approved by risk owner.",
            "actor": "risk-owner@example.local",
        },
    )
    finding = {
        item["id"]: item
        for item in client.get("/api/findings").get_json()
    }["finding-critical"]
    audit = client.get("/api/remediation-audit").get_json()

    assert missing_reason.status_code == 400
    assert response.status_code == 201
    assert finding["status"] == "SUPPRESSED"
    assert "Accepted risk: Temporary exception approved by risk owner." in finding["analyst_notes"]
    assert finding["lifecycle_history"][-1] == {
        "finding_id": "finding-critical",
        "previous_status": "OPEN",
        "new_status": "SUPPRESSED",
        "note": "Accepted risk: Temporary exception approved by risk owner.",
        "timestamp": "2026-05-24T00:00:00+00:00",
    }
    assert audit[-1]["action_type"] == "ACCEPT_RISK"
    assert audit[-1]["actor"] == "risk-owner@example.local"
    assert audit[-1]["reason"] == "Temporary exception approved by risk owner."
    assert audit[-1]["before"]["status"] == "OPEN"
    assert audit[-1]["after"]["status"] == "SUPPRESSED"


def test_remediation_audit_records_identity_before_after(client) -> None:
    client.post(
        "/api/remediation-actions",
        json={
            "action_type": "DISABLE_ACCOUNT",
            "identity_id": "user-004",
            "reason": "Investigation containment.",
            "actor": "analyst@example.local",
        },
    )

    response = client.get("/api/remediation-audit")

    assert response.status_code == 200
    audit = response.get_json()
    assert audit[-1]["action_type"] == "DISABLE_ACCOUNT"
    assert audit[-1]["target_type"] == "identity"
    assert audit[-1]["target_id"] == "user-004"
    assert audit[-1]["before"]["disabled"] is False
    assert audit[-1]["after"]["disabled"] is True
    assert audit[-1]["timestamp"] == "2026-05-24T00:00:00+00:00"


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
        "remediation_status",
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
        "pending_remediations",
        "completed_remediations",
        "stale_open_reviews",
        "unique_reviewers",
        "reviews_per_reviewer",
        "most_reviewed_resources",
        "most_reviewed_identities",
    }.issubset(metrics)
    assert metrics["total_reviews"] == 1
    assert metrics["open_reviews"] == 1
    assert metrics["undecided_reviews"] == 1
    assert metrics["pending_remediations"] == 0
    assert metrics["completed_remediations"] == 0


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
        "report_version",
        "executive_summary",
        "critical_high_iam_risks",
        "attack_path_summaries",
        "access_review_statistics",
        "remediation_statistics",
        "reviewer_activity_summary",
    }.issubset(report)
    assert report["generated_at"] == "2026-05-24T00:00:00+00:00"
    assert report["report_version"] == "1.0"
    assert report["total_findings"] == 2
    assert report["critical_findings"] == 1
    assert report["executive_summary"]["critical_high_findings"] == 1
    assert report["critical_high_iam_risks"][0]["severity"] == "CRITICAL"
    assert report["attack_path_summaries"][0]["finding_id"] == "finding-critical"
    assert "pending_remediations" in report["remediation_statistics"]
    assert "reviews_per_reviewer" not in report["remediation_statistics"]
    assert report["top_risky_resources"]
    assert report["top_risky_identities"]


def test_governance_summary_csv_export_content_type(client) -> None:
    response = client.get("/api/reports/governance-summary?format=csv")

    assert response.status_code == 200
    assert response.content_type.startswith("text/csv")
    assert b"generated_at,report_version,total_findings,critical_findings" in response.data
    assert b"top_risky_resources,top_risky_identities" in response.data
    assert b"2026-05-24T00:00:00+00:00,1.0,2,1" in response.data


def test_governance_summary_pdf_export_contains_auditor_sections(client) -> None:
    response = client.get("/api/reports/governance-summary?format=pdf")

    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF-1.4")
    assert b"IAM Sentinel Governance Report" in response.data
    assert b"Executive Summary" in response.data
    assert b"Critical and High IAM Risks" in response.data
    assert b"Attack-Path Summaries" in response.data
    assert b"Access Review Statistics" in response.data
    assert b"Remediation Statistics" in response.data
    assert b"Top 5 Critical and High IAM Risks" in response.data
    assert b"Top 5 Risky Identities" in response.data
    assert b"Top 5 Attack-Path Summaries" in response.data
    assert b"Reviewer Activity Summary" not in response.data
    assert b"Omar Haddad \\(user-002\\)" in response.data
    assert b"Customer 360 Database \\(res-customer-" in response.data
    assert b"database\\)" in response.data


def test_governance_evidence_csv_export_returns_consolidated_evidence(client) -> None:
    create_response = client.post(
        "/api/access-reviews",
        json={
            "identity_id": "user-004",
            "resource_id": "res-customer-database",
        },
    )
    client.patch(
        f"/api/access-reviews/{create_response.get_json()['id']}",
        json={
            "reviewer": "auditor@example.local",
            "decision": "REVOKE",
            "status": "COMPLETED",
        },
    )

    response = client.get("/api/reports/evidence.csv")

    assert response.status_code == 200
    assert response.content_type.startswith("text/csv")
    assert b"filename=governance-evidence.csv" in response.headers["Content-Disposition"].encode()
    assert (
        b"generated_at,report_version,evidence_type,item_id,severity,status,decision,"
        b"identity_id,resource_id,owner,reviewer,remediation_status,summary"
    ) in response.data
    assert b"2026-05-24T00:00:00+00:00,1.0" in response.data
    assert b"finding,finding-critical,CRITICAL,OPEN" in response.data
    assert b"access_review" in response.data
    assert b"user-004,res-customer-database" in response.data
    assert b"auditor@example.local" in response.data
    assert b"COMPLETED" in response.data
    assert b"Lucas Meyer (user-004)" in response.data
    assert b"Customer 360 Database (res-customer-database)" in response.data


def test_reports_include_updated_finding_lifecycle_status(client) -> None:
    update_response = client.patch(
        "/api/findings/finding-low/status",
        json={
            "status": "FALSE_POSITIVE",
            "note": "Validated as expected access for this identity.",
        },
    )
    findings_response = client.get("/api/reports/evidence.csv")
    report_response = client.get("/api/reports/governance-summary")

    assert update_response.status_code == 200
    assert b"finding,finding-low,LOW,FALSE_POSITIVE" in findings_response.data
    risks_by_id = {
        risk["id"]: risk
        for risk in report_response.get_json()["critical_high_iam_risks"]
    }
    assert risks_by_id["finding-critical"]["status"] == "OPEN"


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
        json={
            "status": "UNDER_REVIEW",
            "note": "Started lifecycle investigation.",
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "UNDER_REVIEW"
    assert response.get_json()["activity"][-1]["type"] == "STATUS_CHANGED"
    assert body["analyst_notes"] == ["Started lifecycle investigation."]
    assert body["lifecycle_history"] == [
        {
            "finding_id": "finding-low",
            "previous_status": "OPEN",
            "new_status": "UNDER_REVIEW",
            "note": "Started lifecycle investigation.",
            "timestamp": "2026-05-24T00:00:00+00:00",
        }
    ]


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
        json={"status": "REMEDIATED", "note": "Confirmed closure."},
    )

    assert response.status_code == 404
    assert response.get_json() == {"error": "Finding not found."}


def test_api_returns_error_for_invalid_status(client) -> None:
    response = client.patch(
        "/api/findings/finding-low/status",
        json={"status": "INVALID", "note": "Invalid transition attempt."},
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


def test_api_requires_note_for_finding_lifecycle_update(client) -> None:
    response = client.patch(
        "/api/findings/finding-low/status",
        json={"status": "UNDER_REVIEW"},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Missing required field: note"}


def extract_js_function_body(script: str, function_name: str) -> str:
    match = re.search(rf"function {function_name}\([^)]*\) \{{", script)
    assert match is not None
    body_start = match.end()
    depth = 1
    index = body_start
    while index < len(script) and depth:
        if script[index] == "{":
            depth += 1
        elif script[index] == "}":
            depth -= 1
        index += 1
    assert depth == 0
    return script[body_start:index - 1]


def extract_js_const_object_body(script: str, object_name: str) -> str:
    match = re.search(rf"const {object_name} = \{{(?P<body>.*?)\n  \}};", script, re.S)
    assert match is not None
    return match.group("body")


def extract_python_function_source(source: str, function_name: str) -> str:
    module = ast.parse(source)
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            function_source = ast.get_source_segment(source, node)
            assert function_source is not None
            return function_source
    raise AssertionError(f"Function not found: {function_name}")


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
