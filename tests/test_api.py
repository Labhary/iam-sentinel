from pathlib import Path
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
        "finding-owner-input",
        "finding-note-input",
        "finding-detail-evidence",
        "finding-detail-risk-factors",
        "finding-detail-attack-paths",
        "finding-detail-notes",
        "finding-detail-activity",
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
        "IN_PROGRESS": "In Progress",
        "OPEN": "Open",
        "RESOLVED": "Resolved",
        "CLOSED": "Closed",
    }.items():
        assert f"{raw_status}: '{label}'" in helper

    assert "function formatStatus(status)" in helper
    assert ".split('_')" in helper
    assert "formatStatus," in helper


def test_finding_status_dropdowns_keep_values_but_use_readable_labels() -> None:
    project_root = Path(__file__).resolve().parents[1]
    template_paths = [
        project_root / "templates/findings.html",
        project_root / "templates/finding_detail.html",
    ]
    templates_text = "\n".join(path.read_text() for path in template_paths)

    for value, label in {
        "OPEN": "Open",
        "IN_PROGRESS": "In Progress",
        "RESOLVED": "Resolved",
        "SUPPRESSED": "Suppressed",
    }.items():
        assert f'<option value="{value}">{label}</option>' in templates_text
        assert f'<option value="{value}">{value}</option>' not in templates_text

    for template_path in template_paths:
        template = template_path.read_text()
        assert '<option value="OPEN">OPEN</option>' not in template
        assert '<option value="RESOLVED">RESOLVED</option>' not in template
        assert '<option value="SUPPRESSED">SUPPRESSED</option>' not in template


def test_finding_status_dropdowns_do_not_duplicate_status_options() -> None:
    project_root = Path(__file__).resolve().parents[1]
    expected_options = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
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
    assert 'class="access-path-id"' in script
    assert 'class="table-truncate access-path-display" title="${pathDisplay}"' in script
    assert 'btn-group btn-group-sm access-path-actions' in script
    assert "btn-outline-success create-review-button" not in script
    assert "btn-outline-secondary create-review-button" in script
    assert "data-identity-id" in script
    assert "data-resource-id" in script
    assert ".access-paths-table .access-path-actions" in styles
    assert "flex-wrap: nowrap;" in styles
    assert "opacity: 0.82;" in styles
    assert "font-size: 0.76rem;" in styles
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
