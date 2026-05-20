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
from core.graph_builder import (
    build_identity_graph,
    format_attack_path,
    get_attack_paths,
    get_reachable_resources,
)
from core.loader import load_iam_data
from core.models import Finding, FindingStatus, Resource, User


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


@app.get("/findings/<finding_id>")
def finding_detail_page(finding_id: str):
    return render_template("finding_detail.html", finding_id=finding_id)


@app.get("/identities")
def identities_page():
    return render_template("identities.html")


@app.get("/identities/<identity_id>")
def identity_detail_page(identity_id: str):
    return render_template("identity_detail.html", identity_id=identity_id)


@app.get("/resources")
def resources_page():
    return render_template("resources.html")


@app.get("/access-paths")
def access_paths_page():
    return render_template("access_paths.html")


@app.get("/resources/<resource_id>")
def resource_detail_page(resource_id: str):
    return render_template("resource_detail.html", resource_id=resource_id)


@app.get("/api/findings")
def get_findings():
    findings = load_findings(get_db_path())
    return jsonify([finding_to_dict(finding) for finding in findings])


@app.get("/api/findings/summary")
def get_findings_summary():
    summary = summarize_findings(load_findings(get_db_path()))
    return jsonify(summary_to_dict(summary))


@app.get("/api/identities")
def get_identities():
    iam_data = load_iam_data(get_iam_data_path())
    return jsonify([identity_to_dict(user) for user in iam_data.users])


@app.get("/api/resources")
def get_resources():
    iam_data = load_iam_data(get_iam_data_path())
    graph = build_identity_graph(iam_data)
    findings = load_findings(get_db_path())
    resource_access = build_resource_access(iam_data.users, graph)
    return jsonify([
        resource_to_dict(resource, iam_data.users_by_id, resource_access, findings)
        for resource in iam_data.resources
    ])


@app.get("/api/access-paths")
def get_access_paths():
    iam_data = load_iam_data(get_iam_data_path())
    graph = build_identity_graph(iam_data)
    access_paths = build_access_paths(
        iam_data.users,
        iam_data.resources_by_id,
        graph,
        identity_id=request.args.get("identity_id"),
        resource_id=request.args.get("resource_id"),
        sensitive_only=request.args.get("sensitive_only") == "true",
    )
    return jsonify(access_paths)


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
        "risk_factors": finding.risk_factors,
        "risk_explanation": finding.risk_explanation,
        "created_at": finding.created_at,
        "status": finding.status.value,
        "owner": finding.owner,
        "analyst_notes": finding.analyst_notes,
        "updated_at": finding.updated_at,
        "activity": load_finding_activity(get_db_path(), finding.id),
    }


def identity_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "type": user.type,
        "mfa_enabled": user.mfa_enabled,
        "external_user": user.external_user,
        "service_account": user.service_account,
        "groups": user.groups,
        "roles": user.roles,
    }


def build_resource_access(users: list[User], graph) -> dict[str, list[str]]:
    resource_access: dict[str, list[str]] = {}
    for user in users:
        for resource_id in get_reachable_resources(graph, user.id):
            resource_access.setdefault(resource_id, []).append(user.id)

    return {
        resource_id: sorted(user_ids)
        for resource_id, user_ids in resource_access.items()
    }


def build_access_paths(
    users: list[User],
    resources_by_id: dict[str, Resource],
    graph,
    identity_id: str | None = None,
    resource_id: str | None = None,
    sensitive_only: bool = False,
) -> list[dict]:
    access_paths = []

    for user in users:
        if identity_id and user.id != identity_id:
            continue

        for reachable_resource_id in get_reachable_resources(graph, user.id):
            if resource_id and reachable_resource_id != resource_id:
                continue

            resource = resources_by_id[reachable_resource_id]
            if sensitive_only and not resource.sensitive:
                continue

            for path_nodes in get_attack_paths(graph, user.id, resource.id):
                path_display = format_attack_path(graph, path_nodes)
                access_paths.append({
                    "identity_id": user.id,
                    "identity_name": user.name,
                    "identity_external_user": user.external_user,
                    "identity_service_account": user.service_account,
                    "resource_id": resource.id,
                    "resource_name": resource.name,
                    "resource_sensitive": resource.sensitive,
                    "path_nodes": path_nodes,
                    "path_display": path_display,
                    "path_length": max(len(path_nodes) - 1, 0),
                })

    return sorted(
        access_paths,
        key=lambda path: (
            not path["resource_sensitive"],
            path["identity_id"],
            path["resource_id"],
            path["path_display"],
        ),
    )


def resource_to_dict(
    resource: Resource,
    users_by_id: dict[str, User],
    resource_access: dict[str, list[str]],
    findings: list[Finding],
) -> dict:
    accessible_by = resource_access.get(resource.id, [])
    return {
        "id": resource.id,
        "name": resource.name,
        "type": resource.type,
        "sensitive": resource.sensitive,
        "accessible_by": accessible_by,
        "accessible_by_count": len(accessible_by),
        "external_access_count": sum(
            1
            for user_id in accessible_by
            if users_by_id[user_id].external_user
        ),
        "service_account_access_count": sum(
            1
            for user_id in accessible_by
            if users_by_id[user_id].service_account
        ),
        "related_findings_count": sum(
            1
            for finding in findings
            if finding.resource_id == resource.id
        ),
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
