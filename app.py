from pathlib import Path

from flask import Flask, jsonify, render_template, request

from core.analysis_runner import run_analysis
from core.finding_store import (
    add_finding_note,
    assign_finding_owner,
    finding_exists,
    load_finding_activity,
    load_findings,
    update_finding_status,
)
from core.findings import summarize_findings
from core.models import Finding, FindingStatus


app = Flask(__name__)
app.config["FINDINGS_DB_PATH"] = Path("data") / "findings.db"
app.config["IAM_DATA_PATH"] = Path("data") / "sample_iam.json"


@app.get("/")
def index():
    return jsonify({"message": "IAM Sentinel is running"})


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.get("/findings")
def findings_page():
    return render_template("findings.html")


@app.get("/api/findings")
def get_findings():
    findings = load_findings(get_db_path())
    return jsonify([finding_to_dict(finding) for finding in findings])


@app.get("/api/findings/summary")
def get_findings_summary():
    summary = summarize_findings(load_findings(get_db_path()))
    return jsonify(summary_to_dict(summary))


@app.post("/api/analysis/run")
def post_run_analysis():
    result = run_analysis(
        iam_data_path=get_iam_data_path(),
        db_path=get_db_path(),
    )
    return jsonify(analysis_result_to_dict(result))


@app.patch("/api/findings/<finding_id>/status")
def patch_finding_status(finding_id: str):
    if not finding_exists(get_db_path(), finding_id):
        return error_response("Finding not found.", 404)

    payload = request.get_json(silent=True) or {}
    status_value = payload.get("status")
    if not status_value:
        return error_response("Missing required field: status", 400)

    try:
        status = FindingStatus(status_value)
    except ValueError:
        return error_response("Invalid finding status.", 400)

    update_finding_status(get_db_path(), finding_id, status)
    return jsonify(finding_to_dict(get_finding_or_none(finding_id)))


@app.patch("/api/findings/<finding_id>/owner")
def patch_finding_owner(finding_id: str):
    if not finding_exists(get_db_path(), finding_id):
        return error_response("Finding not found.", 404)

    payload = request.get_json(silent=True) or {}
    if "owner" not in payload:
        return error_response("Missing required field: owner", 400)

    assign_finding_owner(get_db_path(), finding_id, payload["owner"])
    return jsonify(finding_to_dict(get_finding_or_none(finding_id)))


@app.post("/api/findings/<finding_id>/notes")
def post_finding_note(finding_id: str):
    if not finding_exists(get_db_path(), finding_id):
        return error_response("Finding not found.", 404)

    payload = request.get_json(silent=True) or {}
    note = payload.get("note")
    if not note:
        return error_response("Missing required field: note", 400)

    add_finding_note(get_db_path(), finding_id, note)
    return jsonify(finding_to_dict(get_finding_or_none(finding_id))), 201


def get_db_path() -> Path:
    return Path(app.config["FINDINGS_DB_PATH"])


def get_iam_data_path() -> Path:
    return Path(app.config["IAM_DATA_PATH"])


def get_finding_or_none(finding_id: str) -> Finding:
    findings_by_id = {
        finding.id: finding
        for finding in load_findings(get_db_path())
    }
    return findings_by_id[finding_id]


def finding_to_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "score": finding.score,
        "identity_id": finding.identity_id,
        "resource_id": finding.resource_id,
        "finding_type": finding.finding_type,
        "description": finding.description,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
        "attack_paths": finding.attack_paths,
        "created_at": finding.created_at,
        "status": finding.status.value,
        "owner": finding.owner,
        "analyst_notes": finding.analyst_notes,
        "updated_at": finding.updated_at,
        "activity": load_finding_activity(get_db_path(), finding.id),
    }


def summary_to_dict(summary: dict) -> dict:
    return {
        "total_findings": summary["total_findings"],
        "count_per_severity": {
            severity.value: count
            for severity, count in summary["count_per_severity"].items()
        },
        "highest_score": summary["highest_score"],
        "affected_identities_count": summary["affected_identities_count"],
    }


def analysis_result_to_dict(result: dict) -> dict:
    return {
        "total_findings": result["total_findings"],
        "execution_timestamp": result["execution_timestamp"],
        "findings": [
            finding_to_dict(finding)
            for finding in result["findings"]
        ],
    }


def error_response(message: str, status_code: int):
    return jsonify({"error": message}), status_code


if __name__ == "__main__":
    app.run(debug=True)
