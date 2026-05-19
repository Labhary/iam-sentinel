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

    save_findings(
        db_path,
        [
            make_finding("finding-low", Severity.LOW, 25, "user-001"),
            make_finding("finding-critical", Severity.CRITICAL, 95, "user-002"),
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
    assert response.data.count(b'<th scope="col">') == 7
    assert b'colspan="7"' in response.data
    assert response.data.count(b'id="select-all-findings"') == 1
    assert response.data.count(b'id="bulk-status-button"') == 1
    assert response.data.count(b'id="bulk-owner-button"') == 1
    assert response.data.count(b'id="finding-detail-activity"') == 1
    assert b"assets/js/iam-sentinel-findings.js" in response.data
    assert b"assets/js/iam-sentinel-dashboard.js" not in response.data
    assert b'id="run-analysis-button"' not in response.data
    assert b'id="severity-distribution-chart"' not in response.data
    assert b'id="status-distribution-chart"' not in response.data


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
