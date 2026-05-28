import csv
import json
import sqlite3
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from textwrap import wrap

from flask import Flask, Response, jsonify, render_template, request

from core.access_review_store import (
    build_access_review_metrics,
    complete_access_review_remediation,
    create_access_review,
    is_access_review_stale,
    load_access_review_history,
    load_access_reviews,
    update_access_review,
)
from core.analysis_runner import run_analysis
from core.finding_store import (
    add_finding_note,
    assign_finding_owner,
    finding_exists,
    load_finding_activity,
    load_finding_lifecycle_history,
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
from core.models import (
    AccessReview,
    AccessReviewHistoryEvent,
    AccessReviewDecision,
    AccessReviewStatus,
    Finding,
    FindingStatus,
    Resource,
    User,
)


app = Flask(__name__)
app.config["FINDINGS_DB_PATH"] = Path("data") / "findings.db"
app.config["IAM_DATA_PATH"] = Path("data") / "sample_iam.json"
app.config["GOVERNANCE_REPORT_VERSION"] = "1.0"
REMEDIATION_REASON_REQUIRED = {
    "DISABLE_ACCOUNT",
    "ADD_TO_GROUP",
    "CHANGE_GROUP",
    "REMOVE_FROM_GROUP",
    "REPLACE_ROLE",
    "ACCEPT_RISK",
}


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


@app.get("/attack-graph")
def attack_graph_page():
    return render_template("attack_graph.html")


@app.get("/remediation-audit")
def remediation_audit_page():
    return render_template("remediation_audit.html")


@app.get("/access-reviews")
def access_reviews_page():
    return render_template("access_reviews.html")


@app.get("/reports")
def reports_page():
    return render_template("reports.html")


@app.get("/resources/<resource_id>")
def resource_detail_page(resource_id: str):
    return render_template("resource_detail.html", resource_id=resource_id)


@app.get("/api/findings")
def get_findings():
    findings = load_findings(get_db_path())
    iam_data = load_effective_iam_data()
    return jsonify([
        finding_to_dict(finding, iam_data.users_by_id)
        for finding in findings
    ])


@app.get("/api/findings/summary")
def get_findings_summary():
    summary = summarize_findings(load_findings(get_db_path()))
    return jsonify(summary_to_dict(summary))


@app.get("/api/identities")
def get_identities():
    iam_data = load_effective_iam_data()
    return jsonify([identity_to_dict(user, iam_data) for user in iam_data.users])


@app.get("/api/identities/<identity_id>")
def get_identity(identity_id: str):
    iam_data = load_effective_iam_data()
    identity = iam_data.users_by_id.get(identity_id)
    if identity is None:
        return error_response("Identity not found.", 404)

    return jsonify(identity_to_dict(identity, iam_data))


@app.get("/api/resources")
def get_resources():
    iam_data = load_effective_iam_data()
    graph = build_identity_graph(iam_data)
    findings = load_findings(get_db_path())
    resource_access = build_resource_access(iam_data.users, graph)
    return jsonify([
        resource_to_dict(resource, iam_data.users_by_id, resource_access, findings)
        for resource in iam_data.resources
    ])


@app.get("/api/resources/<resource_id>")
def get_resource(resource_id: str):
    iam_data = load_effective_iam_data()
    resource = iam_data.resources_by_id.get(resource_id)
    if resource is None:
        return error_response("Resource not found.", 404)

    graph = build_identity_graph(iam_data)
    findings = load_findings(get_db_path())
    resource_access = build_resource_access(iam_data.users, graph)
    return jsonify(
        resource_to_dict(resource, iam_data.users_by_id, resource_access, findings)
    )


@app.get("/api/access-paths")
def get_access_paths():
    iam_data = load_effective_iam_data()
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


@app.get("/api/attack-graph")
def get_attack_graph():
    return jsonify(build_attack_graph_data())


@app.get("/api/access-reviews")
def get_access_reviews():
    return jsonify([
        access_review_to_dict(review)
        for review in load_access_reviews(get_db_path())
    ])


@app.get("/api/access-review-metrics")
def get_access_review_metrics():
    return jsonify(build_access_review_metrics(load_access_reviews(get_db_path())))


@app.get("/api/access-reviews/<review_id>/history")
def get_access_review_history(review_id: str):
    return jsonify([
        access_review_history_to_dict(event)
        for event in load_access_review_history(get_db_path(), review_id)
    ])


@app.get("/api/reports/governance-summary")
def get_governance_summary_report():
    report = build_governance_summary_report()
    report_format = request.args.get("format", "json")
    if report_format == "pdf":
        return governance_summary_pdf_response(report)
    if report_format == "csv":
        return governance_summary_csv_response(report)
    if report_format != "json":
        return error_response("Invalid report format.", 400)
    return jsonify(report)


@app.get("/api/reports/evidence.csv")
def get_governance_evidence_csv_report():
    return governance_evidence_csv_response(
        load_findings(get_db_path()),
        load_access_reviews(get_db_path()),
        load_iam_data(get_iam_data_path()),
    )


@app.get("/api/reports/findings.csv")
def get_findings_csv_report():
    return findings_csv_response(load_findings(get_db_path()))


@app.get("/api/reports/access-reviews.csv")
def get_access_reviews_csv_report():
    return access_reviews_csv_response(load_access_reviews(get_db_path()))


@app.get("/api/reports/remediation-status.csv")
def get_remediation_status_csv_report():
    return remediation_status_csv_response(load_access_reviews(get_db_path()))


@app.get("/api/remediation-audit")
def get_remediation_audit():
    return jsonify(load_remediation_audit(get_db_path()))


@app.post("/api/remediation-actions/preview")
def post_remediation_action_preview():
    payload = request.get_json(silent=True) or {}
    try:
        preview = build_remediation_impact_preview(payload)
    except ValueError as error:
        return error_response(str(error), 400)
    except LookupError as error:
        return error_response(str(error), 404)
    except RuntimeError as error:
        return error_response(str(error), 409)

    return jsonify(preview)


@app.post("/api/remediation-actions")
def post_remediation_action():
    payload = request.get_json(silent=True) or {}
    try:
        result = apply_remediation_action(payload)
    except ValueError as error:
        return error_response(str(error), 400)
    except LookupError as error:
        return error_response(str(error), 404)
    except RuntimeError as error:
        return error_response(str(error), 409)

    return jsonify(result), 201


@app.post("/api/access-reviews")
def post_access_review():
    payload = request.get_json(silent=True) or {}
    identity_id = payload.get("identity_id")
    resource_id = payload.get("resource_id")
    if not identity_id or not resource_id:
        return error_response("Missing required fields: identity_id and resource_id", 400)

    review = create_access_review(get_db_path(), identity_id, resource_id)
    if review is None:
        return error_response("Active access review already exists.", 409)

    return jsonify(access_review_to_dict(review)), 201


@app.patch("/api/access-reviews/<review_id>")
def patch_access_review(review_id: str):
    payload = request.get_json(silent=True) or {}
    try:
        status = parse_access_review_status(payload.get("status"))
        decision = parse_access_review_decision(payload.get("decision"))
    except ValueError as error:
        return error_response(str(error), 400)

    review = update_access_review(
        get_db_path(),
        review_id,
        status=status,
        reviewer=payload.get("reviewer") if "reviewer" in payload else None,
        decision=decision,
        notes=payload.get("notes") if "notes" in payload else None,
        actor=payload.get("actor"),
    )
    if review is None:
        return error_response("Access review not found.", 404)

    return jsonify(access_review_to_dict(review))


@app.patch("/api/access-reviews/<review_id>/remediation")
def patch_access_review_remediation(review_id: str):
    payload = request.get_json(silent=True) or {}
    review = complete_access_review_remediation(
        get_db_path(),
        review_id,
        actor=payload.get("actor"),
    )
    if review is None:
        return error_response("Access review not found.", 404)

    return jsonify(access_review_to_dict(review))


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
    note = str(payload.get("note", "")).strip()
    if not status_value:
        return error_response("Missing required field: status", 400)
    if not note:
        return error_response("Missing required field: note", 400)

    try:
        status = FindingStatus(status_value)
    except ValueError:
        return error_response("Invalid finding status.", 400)

    update_finding_status(
        get_db_path(),
        finding_id,
        status,
        note,
        updated_at=get_report_generated_at(),
    )
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


def finding_to_dict(finding: Finding, users_by_id: dict[str, User] | None = None) -> dict:
    user = users_by_id.get(finding.identity_id) if users_by_id else None
    iam_data = load_effective_iam_data()
    resource = iam_data.resources_by_id.get(finding.resource_id) if finding.resource_id else None
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "score": finding.score,
        "identity_id": finding.identity_id,
        "identity_name": user.name if user else finding.identity_id,
        "identity_label": format_identity_label(user.name if user else None, finding.identity_id),
        "resource_id": finding.resource_id,
        "resource_name": resource.name if resource else finding.resource_id,
        "resource_label": format_resource_label(resource.name if resource else None, finding.resource_id),
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
        "lifecycle_history": load_finding_lifecycle_history(get_db_path(), finding.id),
    }


def identity_to_dict(user: User, iam_data=None) -> dict:
    row = {
        "id": user.id,
        "name": user.name,
        "label": format_identity_label(user.name, user.id),
        "email": user.email,
        "type": user.type,
        "mfa_enabled": user.mfa_enabled,
        "external_user": user.external_user,
        "service_account": user.service_account,
        "disabled": user.disabled,
        "groups": user.groups,
        "roles": user.roles,
    }
    if iam_data is not None:
        row["available_groups"] = [
            {"id": group.id, "name": group.name}
            for group in iam_data.groups
        ]
        row["available_roles"] = [
            {"id": role.id, "name": role.name}
            for role in iam_data.roles
        ]
    return row


def load_effective_iam_data():
    iam_data = load_iam_data(get_iam_data_path())
    overrides = load_identity_overrides(get_db_path())
    if not overrides:
        return iam_data

    users = []
    for user in iam_data.users:
        override = overrides.get(user.id)
        if not override:
            users.append(user)
            continue
        users.append(replace(
            user,
            mfa_enabled=override.get("mfa_enabled", user.mfa_enabled),
            disabled=override.get("disabled", user.disabled),
            groups=override.get("groups", user.groups),
            roles=override.get("roles", user.roles),
        ))

    return replace(iam_data, users=users, users_by_id={user.id: user for user in users})


def initialize_remediation_database(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS identity_overrides (
                identity_id TEXT PRIMARY KEY,
                mfa_enabled INTEGER,
                disabled INTEGER NOT NULL DEFAULT 0,
                groups_json TEXT,
                roles_json TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_audit (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                before_json TEXT NOT NULL,
                after_json TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )


def load_identity_overrides(db_path: Path) -> dict[str, dict]:
    initialize_remediation_database(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT identity_id, mfa_enabled, disabled, groups_json, roles_json
            FROM identity_overrides
            """
        ).fetchall()

    overrides = {}
    for row in rows:
        overrides[row[0]] = {
            "mfa_enabled": None if row[1] is None else bool(row[1]),
            "disabled": bool(row[2]),
            "groups": None if row[3] is None else json.loads(row[3]),
            "roles": None if row[4] is None else json.loads(row[4]),
        }
    return overrides


def save_identity_override(db_path: Path, user: User) -> None:
    initialize_remediation_database(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO identity_overrides (
                identity_id, mfa_enabled, disabled, groups_json, roles_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(identity_id) DO UPDATE SET
                mfa_enabled = excluded.mfa_enabled,
                disabled = excluded.disabled,
                groups_json = excluded.groups_json,
                roles_json = excluded.roles_json,
                updated_at = excluded.updated_at
            """,
            (
                user.id,
                int(user.mfa_enabled),
                int(user.disabled),
                json.dumps(user.groups),
                json.dumps(user.roles),
                get_report_generated_at(),
            ),
        )


def load_remediation_audit(db_path: Path) -> list[dict]:
    initialize_remediation_database(db_path)
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, actor, action_type, target_type, target_id,
                   before_json, after_json, reason
            FROM remediation_audit
            ORDER BY timestamp ASC, rowid ASC
            """
        ).fetchall()
    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "actor": row[2],
            "action_type": row[3],
            "target_type": row[4],
            "target_id": row[5],
            "before": json.loads(row[6]),
            "after": json.loads(row[7]),
            "reason": row[8],
        }
        for row in rows
    ]


def insert_remediation_audit(
    db_path: Path,
    action_type: str,
    target_type: str,
    target_id: str,
    before: dict,
    after: dict,
    reason: str,
    actor: str,
) -> dict:
    initialize_remediation_database(db_path)
    event = {
        "id": f"remediation-{uuid.uuid4().hex}",
        "timestamp": get_report_generated_at(),
        "actor": actor or "Unassigned Analyst",
        "action_type": action_type,
        "target_type": target_type,
        "target_id": target_id,
        "before": before,
        "after": after,
        "reason": reason,
    }
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO remediation_audit (
                id, timestamp, actor, action_type, target_type, target_id,
                before_json, after_json, reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["id"],
                event["timestamp"],
                event["actor"],
                event["action_type"],
                event["target_type"],
                event["target_id"],
                json.dumps(before, sort_keys=True),
                json.dumps(after, sort_keys=True),
                event["reason"],
            ),
        )
    return event


def user_state(user: User) -> dict:
    return {
        "identity_id": user.id,
        "mfa_enabled": user.mfa_enabled,
        "disabled": user.disabled,
        "groups": user.groups,
        "roles": user.roles,
    }


def build_remediation_impact_preview(payload: dict) -> dict:
    action_type = str(payload.get("action_type", "")).strip().upper()
    if not action_type:
        raise ValueError("Missing required field: action_type")
    if action_type == "ACCEPT_RISK":
        raise ValueError("Accepted-risk remediation does not change identity access paths.")

    identity_id = str(payload.get("identity_id", "")).strip()
    if not identity_id:
        raise ValueError("Missing required field: identity_id")

    iam_data = load_effective_iam_data()
    if identity_id not in iam_data.users_by_id:
        raise LookupError("Identity not found.")

    current = iam_data.users_by_id[identity_id]
    updated = build_updated_user_for_action(current, payload, action_type)
    simulated_iam_data = replace_user_in_iam_data(iam_data, updated)
    findings = load_findings(get_db_path())

    before_impact = build_identity_impact_summary(iam_data, identity_id, findings)
    after_impact = build_identity_impact_summary(simulated_iam_data, identity_id, findings)
    affected_findings = [
        finding_to_impact_dict(finding)
        for finding in findings
        if finding.identity_id == identity_id
    ]

    return {
        "identity_id": identity_id,
        "identity_name": current.name,
        "action_type": action_type,
        "action_label": format_remediation_action_label(action_type),
        "before": user_state(current),
        "after": user_state(updated),
        "impact": {
            "before": before_impact,
            "after": after_impact,
            "access_paths_delta": (
                after_impact["access_paths_count"]
                - before_impact["access_paths_count"]
            ),
            "sensitive_resources_delta": (
                after_impact["sensitive_resources_count"]
                - before_impact["sensitive_resources_count"]
            ),
            "affected_findings_count": len(affected_findings),
            "affected_findings": affected_findings,
            "risk_reduction": (
                after_impact["access_paths_count"] < before_impact["access_paths_count"]
                or after_impact["sensitive_resources_count"] < before_impact["sensitive_resources_count"]
            ),
        },
    }


def replace_user_in_iam_data(iam_data, updated_user: User):
    users = [
        updated_user if user.id == updated_user.id else user
        for user in iam_data.users
    ]
    return replace(iam_data, users=users, users_by_id={user.id: user for user in users})


def build_identity_impact_summary(
    iam_data,
    identity_id: str,
    findings: list[Finding],
) -> dict:
    graph = build_identity_graph(iam_data)
    access_paths = build_access_paths(
        iam_data.users,
        iam_data.resources_by_id,
        graph,
        identity_id=identity_id,
    )
    sensitive_resources = sorted({
        path["resource_id"]
        for path in access_paths
        if path["resource_sensitive"]
    })
    return {
        "access_paths_count": len(access_paths),
        "sensitive_resources_count": len(sensitive_resources),
        "sensitive_resources": [
            {
                "id": resource_id,
                "name": iam_data.resources_by_id[resource_id].name,
            }
            for resource_id in sensitive_resources
        ],
        "related_findings_count": sum(
            1
            for finding in findings
            if finding.identity_id == identity_id
        ),
    }


def finding_to_impact_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "score": finding.score,
        "resource_id": finding.resource_id,
        "status": finding.status.value,
    }


def format_remediation_action_label(action_type: str) -> str:
    return action_type.replace("_", " ").title()


def apply_remediation_action(payload: dict) -> dict:
    action_type = str(payload.get("action_type", "")).strip().upper()
    reason = str(payload.get("reason", "")).strip()
    actor = str(payload.get("actor", "")).strip() or "Unassigned Analyst"
    if not action_type:
        raise ValueError("Missing required field: action_type")
    if action_type in REMEDIATION_REASON_REQUIRED and not reason:
        raise ValueError("Reason is required for this remediation action.")

    if action_type == "ACCEPT_RISK":
        return apply_accept_risk_action(payload, reason, actor)

    identity_id = str(payload.get("identity_id", "")).strip()
    if not identity_id:
        raise ValueError("Missing required field: identity_id")

    iam_data = load_effective_iam_data()
    if identity_id not in iam_data.users_by_id:
        raise LookupError("Identity not found.")

    current = iam_data.users_by_id[identity_id]
    before = user_state(current)
    updated = build_updated_user_for_action(current, payload, action_type)
    after = user_state(updated)
    if before == after:
        raise RuntimeError("Action is already reflected in local IAM state.")

    save_identity_override(get_db_path(), updated)
    audit_event = insert_remediation_audit(
        get_db_path(),
        action_type,
        "identity",
        identity_id,
        before,
        after,
        reason,
        actor,
    )
    return {"status": "applied", "audit_event": audit_event, "identity": identity_to_dict(updated)}


def build_updated_user_for_action(user: User, payload: dict, action_type: str) -> User:
    if action_type == "ENABLE_MFA":
        return replace(user, mfa_enabled=True)
    if action_type == "DISABLE_ACCOUNT":
        return replace(user, disabled=True)
    if action_type == "REENABLE_ACCOUNT":
        return replace(user, disabled=False)
    if action_type == "ADD_TO_GROUP":
        group_id = str(payload.get("group_id", "")).strip()
        if not group_id:
            raise ValueError("Missing required field: group_id")
        iam_data = load_effective_iam_data()
        if group_id not in iam_data.groups_by_id:
            raise LookupError("Group not found.")
        if group_id in user.groups:
            raise RuntimeError("Identity already belongs to this group.")
        return replace(user, groups=[*user.groups, group_id])
    if action_type == "CHANGE_GROUP":
        old_group_id = str(payload.get("old_group_id", "")).strip()
        new_group_id = str(payload.get("new_group_id", "")).strip()
        if not old_group_id or not new_group_id:
            raise ValueError("Missing required fields: old_group_id and new_group_id")
        if old_group_id == new_group_id:
            raise RuntimeError("New group must be different from old group.")
        iam_data = load_effective_iam_data()
        if old_group_id not in user.groups:
            raise RuntimeError("Identity is not a member of this group.")
        if new_group_id not in iam_data.groups_by_id:
            raise LookupError("New group not found.")
        if new_group_id in user.groups:
            raise RuntimeError("Identity already belongs to the new group.")
        return replace(user, groups=[
            new_group_id if group == old_group_id else group
            for group in user.groups
        ])
    if action_type == "REMOVE_FROM_GROUP":
        group_id = str(payload.get("group_id", "")).strip()
        if not group_id:
            raise ValueError("Missing required field: group_id")
        if group_id not in user.groups:
            raise RuntimeError("Identity is not a member of this group.")
        return replace(user, groups=[group for group in user.groups if group != group_id])
    if action_type == "REPLACE_ROLE":
        old_role_id = str(payload.get("old_role_id", "")).strip()
        new_role_id = str(payload.get("new_role_id", "")).strip()
        if not old_role_id or not new_role_id:
            raise ValueError("Missing required fields: old_role_id and new_role_id")
        if old_role_id == new_role_id:
            raise RuntimeError("Replacement role must be different from current role.")
        iam_data = load_effective_iam_data()
        if old_role_id not in user.roles:
            raise RuntimeError("Identity does not have this role.")
        if new_role_id not in iam_data.roles_by_id:
            raise LookupError("Replacement role not found.")
        roles = [new_role_id if role == old_role_id else role for role in user.roles]
        return replace(user, roles=sorted(set(roles), key=roles.index))
    raise ValueError("Unsupported remediation action.")


def apply_accept_risk_action(payload: dict, reason: str, actor: str) -> dict:
    finding_id = str(payload.get("finding_id", "")).strip()
    if not finding_id:
        raise ValueError("Missing required field: finding_id")
    if not finding_exists(get_db_path(), finding_id):
        raise LookupError("Finding not found.")

    finding = get_finding_or_none(finding_id)
    before = {"finding_id": finding.id, "status": finding.status.value}
    if finding.status == FindingStatus.SUPPRESSED:
        raise RuntimeError("Finding is already marked as accepted risk.")

    update_finding_status(
        get_db_path(),
        finding_id,
        FindingStatus.SUPPRESSED,
        f"Accepted risk: {reason}",
        updated_at=get_report_generated_at(),
    )
    after = {"finding_id": finding.id, "status": FindingStatus.SUPPRESSED.value}
    audit_event = insert_remediation_audit(
        get_db_path(),
        "ACCEPT_RISK",
        "finding",
        finding_id,
        before,
        after,
        reason,
        actor,
    )
    return {"status": "applied", "audit_event": audit_event}


def build_governance_summary_report() -> dict:
    findings = load_findings(get_db_path())
    reviews = load_access_reviews(get_db_path())
    review_metrics = build_access_review_metrics(reviews)
    iam_data = load_iam_data(get_iam_data_path())
    external_user_ids = {
        user.id
        for user in iam_data.users
        if user.external_user
    }
    risky_external_identities = len({
        finding.identity_id
        for finding in findings
        if finding.identity_id in external_user_ids
    })
    critical_high_risks = build_critical_high_risks(findings, iam_data)
    open_access_reviews = review_metrics["open_reviews"] + review_metrics["in_review_reviews"]

    return {
        "generated_at": get_report_generated_at(),
        "report_version": app.config["GOVERNANCE_REPORT_VERSION"],
        "total_findings": len(findings),
        "critical_findings": sum(1 for finding in findings if finding.severity.value == "CRITICAL"),
        "high_findings": sum(1 for finding in findings if finding.severity.value == "HIGH"),
        "risky_external_identities": risky_external_identities,
        "stale_reviews": review_metrics["stale_open_reviews"],
        "revoke_decisions": review_metrics["revoke_decisions"],
        "top_risky_resources": build_top_risky_resources(findings),
        "top_risky_identities": build_top_risky_identities(findings),
        "open_access_reviews": open_access_reviews,
        "completed_access_reviews": review_metrics["completed_reviews"],
        "executive_summary": {
            "total_findings": len(findings),
            "critical_high_findings": len(critical_high_risks),
            "risky_external_identities": risky_external_identities,
            "open_access_reviews": open_access_reviews,
            "pending_remediations": review_metrics["pending_remediations"],
            "completed_remediations": review_metrics["completed_remediations"],
        },
        "critical_high_iam_risks": critical_high_risks,
        "attack_path_summaries": build_attack_path_summaries(findings, iam_data),
        "access_review_statistics": review_metrics,
        "remediation_statistics": build_remediation_statistics(reviews, review_metrics),
        "reviewer_activity_summary": review_metrics["reviews_per_reviewer"],
        "identity_display_names": {
            user.id: f"{user.name} ({user.id})"
            for user in iam_data.users
        },
        "resource_display_names": {
            resource.id: f"{resource.name} ({resource.id})"
            for resource in iam_data.resources
        },
    }


def get_report_generated_at() -> str:
    configured_timestamp = app.config.get("REPORT_GENERATED_AT")
    if configured_timestamp:
        return configured_timestamp
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_critical_high_risks(findings: list[Finding], iam_data) -> list[dict]:
    risks = [
        {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "score": finding.score,
            "identity_id": finding.identity_id,
            "identity_display": identity_display_name(iam_data, finding.identity_id),
            "resource_id": finding.resource_id,
            "resource_display": resource_display_name(iam_data, finding.resource_id),
            "status": finding.status.value,
            "owner": finding.owner or "Unassigned",
            "recommendation": finding.recommendation,
        }
        for finding in findings
        if finding.severity.value in {"CRITICAL", "HIGH"}
    ]
    return sorted(risks, key=lambda row: (-row["score"], row["id"]))


def build_attack_path_summaries(findings: list[Finding], iam_data) -> list[dict]:
    summaries = []
    for finding in findings:
        for attack_path in finding.attack_paths:
            summaries.append({
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "score": finding.score,
                "identity_id": finding.identity_id,
                "identity_display": identity_display_name(iam_data, finding.identity_id),
                "resource_id": finding.resource_id,
                "resource_display": resource_display_name(iam_data, finding.resource_id),
                "path": attack_path,
            })

    return sorted(
        summaries,
        key=lambda row: (-row["score"], row["finding_id"], row["path"]),
    )


def identity_display_name(iam_data, identity_id: str | None) -> str:
    if not identity_id:
        return "N/A"
    user = iam_data.users_by_id.get(identity_id)
    if user is None:
        return identity_id
    return format_identity_label(user.name, user.id)


def resource_display_name(iam_data, resource_id: str | None) -> str:
    if not resource_id:
        return "N/A"
    resource = iam_data.resources_by_id.get(resource_id)
    if resource is None:
        return resource_id
    return format_resource_label(resource.name, resource.id)


def format_identity_label(display_name: str | None, identity_id: str | None) -> str:
    return format_entity_label(display_name, identity_id)


def format_resource_label(display_name: str | None, resource_id: str | None) -> str:
    return format_entity_label(display_name, resource_id)


def format_entity_label(display_name: str | None, entity_id: str | None) -> str:
    if not entity_id:
        return display_name or "N/A"
    if display_name and display_name != entity_id:
        return f"{display_name} ({entity_id})"
    return entity_id


def build_remediation_statistics(
    reviews: list[AccessReview],
    review_metrics: dict,
) -> dict:
    return {
        "pending_remediations": review_metrics["pending_remediations"],
        "completed_remediations": review_metrics["completed_remediations"],
        "not_required_remediations": sum(
            1
            for review in reviews
            if review.remediation_status.value == "NOT_REQUIRED"
        ),
        "revoke_decisions": review_metrics["revoke_decisions"],
        "needs_follow_up_decisions": review_metrics["needs_follow_up_decisions"],
    }


def build_attack_graph_data() -> dict:
    iam_data = load_effective_iam_data()
    graph = build_identity_graph(iam_data)
    findings = load_findings(get_db_path())
    access_paths = build_access_paths(
        iam_data.users,
        iam_data.resources_by_id,
        graph,
    )
    finding_counts = build_finding_counts_by_node(findings)
    critical_high_nodes = build_critical_high_finding_nodes(findings)
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    for access_path in access_paths:
        path_nodes = access_path["path_nodes"]
        for node_id in path_nodes:
            nodes.setdefault(
                node_id,
                attack_graph_node_to_dict(
                    node_id,
                    graph,
                    iam_data,
                    finding_counts,
                    critical_high_nodes,
                ),
            )
        for source_id, target_id in zip(path_nodes, path_nodes[1:]):
            edge_id = f"{source_id}->{target_id}"
            edges.setdefault(
                edge_id,
                {
                    "id": edge_id,
                    "source": source_id,
                    "target": target_id,
                    "relationship": graph.edges[source_id, target_id].get(
                        "relationship",
                        "related_to",
                    ),
                },
            )

    return {
        "nodes": sorted(nodes.values(), key=lambda node: (node["type"], node["id"])),
        "edges": sorted(edges.values(), key=lambda edge: edge["id"]),
        "paths": [
            {
                "id": f"path-{index + 1}",
                "identity_id": access_path["identity_id"],
                "identity_name": access_path["identity_name"],
                "identity_label": access_path["identity_label"],
                "resource_id": access_path["resource_id"],
                "resource_name": access_path["resource_name"],
                "resource_label": access_path["resource_label"],
                "resource_sensitive": access_path["resource_sensitive"],
                "path_nodes": access_path["path_nodes"],
                "path_display": access_path["path_display"],
                "path_length": access_path["path_length"],
                "related_finding_count": count_path_related_findings(
                    findings,
                    access_path["identity_id"],
                    access_path["resource_id"],
                ),
                "finding_severity": get_path_finding_severity(
                    findings,
                    access_path["identity_id"],
                    access_path["resource_id"],
                ),
            }
            for index, access_path in enumerate(access_paths)
        ],
    }


def attack_graph_node_to_dict(
    node_id: str,
    graph,
    iam_data,
    finding_counts: dict[str, int],
    critical_high_nodes: set[str],
) -> dict:
    node_type = graph.nodes[node_id].get("node_type", "unknown")
    node = {
        "id": node_id,
        "label": graph.nodes[node_id].get("display_name", node_id),
        "type": node_type,
        "external_identity": False,
        "service_account": False,
        "privileged_role": False,
        "sensitive_resource": False,
        "critical_high_finding": node_id in critical_high_nodes,
        "related_finding_count": finding_counts.get(node_id, 0),
    }

    if node_type == "user" and node_id in iam_data.users_by_id:
        user = iam_data.users_by_id[node_id]
        node["external_identity"] = user.external_user
        node["service_account"] = user.service_account
    elif node_type == "role" and node_id in iam_data.roles_by_id:
        role = iam_data.roles_by_id[node_id]
        node["privileged_role"] = is_privileged_role(role)
    elif node_type == "resource" and node_id in iam_data.resources_by_id:
        node["sensitive_resource"] = iam_data.resources_by_id[node_id].sensitive

    node["risky"] = any([
        node["external_identity"],
        node["service_account"],
        node["privileged_role"],
        node["sensitive_resource"],
        node["critical_high_finding"],
    ])
    return node


def build_finding_counts_by_node(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.identity_id] = counts.get(finding.identity_id, 0) + 1
        if finding.resource_id:
            counts[finding.resource_id] = counts.get(finding.resource_id, 0) + 1
    return counts


def build_critical_high_finding_nodes(findings: list[Finding]) -> set[str]:
    node_ids = set()
    for finding in findings:
        if finding.severity.value not in {"CRITICAL", "HIGH"}:
            continue
        node_ids.add(finding.identity_id)
        if finding.resource_id:
            node_ids.add(finding.resource_id)
    return node_ids


def count_path_related_findings(
    findings: list[Finding],
    identity_id: str,
    resource_id: str,
) -> int:
    return sum(
        1
        for finding in findings
        if finding.identity_id == identity_id or finding.resource_id == resource_id
    )


def get_path_finding_severity(
    findings: list[Finding],
    identity_id: str,
    resource_id: str,
) -> str:
    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }
    severities = [
        finding.severity.value
        for finding in findings
        if finding.identity_id == identity_id or finding.resource_id == resource_id
    ]
    if not severities:
        return "NONE"
    return max(severities, key=lambda severity: severity_rank.get(severity, 0))


def is_privileged_role(role) -> bool:
    privileged_tokens = ("admin", "manage", "breakglass", "privileged", "owner")
    role_text = f"{role.id} {role.name}".lower()
    if any(token in role_text for token in privileged_tokens):
        return True
    return any(
        permission_id == "*"
        or "admin" in permission_id.lower()
        or "manage" in permission_id.lower()
        for permission_id in role.permissions
    )


def build_top_risky_resources(findings: list[Finding]) -> list[dict]:
    resource_rows: dict[str, dict] = {}
    for finding in findings:
        if not finding.resource_id:
            continue
        row = resource_rows.setdefault(
            finding.resource_id,
            {
                "resource_id": finding.resource_id,
                "finding_count": 0,
                "highest_score": 0,
            },
        )
        row["finding_count"] += 1
        row["highest_score"] = max(row["highest_score"], finding.score)

    return sorted(
        resource_rows.values(),
        key=lambda row: (-row["finding_count"], row["resource_id"]),
    )


def build_top_risky_identities(findings: list[Finding]) -> list[dict]:
    identity_rows: dict[str, dict] = {}
    for finding in findings:
        row = identity_rows.setdefault(
            finding.identity_id,
            {
                "identity_id": finding.identity_id,
                "finding_count": 0,
                "highest_score": 0,
            },
        )
        row["finding_count"] += 1
        row["highest_score"] = max(row["highest_score"], finding.score)

    return sorted(
        identity_rows.values(),
        key=lambda row: (-row["finding_count"], row["identity_id"]),
    )


def governance_summary_csv_response(report: dict) -> Response:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "generated_at",
            "report_version",
            "total_findings",
            "critical_findings",
            "high_findings",
            "risky_external_identities",
            "stale_reviews",
            "revoke_decisions",
            "pending_remediations",
            "completed_remediations",
            "open_access_reviews",
            "completed_access_reviews",
            "top_risky_resources",
            "top_risky_identities",
        ],
    )
    writer.writeheader()
    writer.writerow({
        **{
            key: report[key]
            for key in [
                "generated_at",
                "report_version",
                "total_findings",
                "critical_findings",
                "high_findings",
                "risky_external_identities",
                "stale_reviews",
                "revoke_decisions",
                "open_access_reviews",
                "completed_access_reviews",
            ]
        },
        "pending_remediations": report["remediation_statistics"]["pending_remediations"],
        "completed_remediations": report["remediation_statistics"]["completed_remediations"],
        "top_risky_resources": format_top_list_for_csv(
            report["top_risky_resources"],
            "resource_id",
        ),
        "top_risky_identities": format_top_list_for_csv(
            report["top_risky_identities"],
            "identity_id",
        ),
    })
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=governance-summary.csv"},
    )


def governance_evidence_csv_response(
    findings: list[Finding],
    reviews: list[AccessReview],
    iam_data,
) -> Response:
    generated_at = get_report_generated_at()
    report_version = app.config["GOVERNANCE_REPORT_VERSION"]
    fieldnames = [
        "generated_at",
        "report_version",
        "evidence_type",
        "item_id",
        "severity",
        "status",
        "decision",
        "identity_id",
        "resource_id",
        "owner",
        "reviewer",
        "remediation_status",
        "summary",
    ]
    rows = [
        {
            "generated_at": generated_at,
            "report_version": report_version,
            "evidence_type": "finding",
            "item_id": finding.id,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "decision": "",
            "identity_id": finding.identity_id,
            "resource_id": finding.resource_id or "",
            "owner": finding.owner or "Unassigned",
            "reviewer": "",
            "remediation_status": "",
            "summary": (
                f"{finding.title}: {identity_display_name(iam_data, finding.identity_id)}"
                f" -> {resource_display_name(iam_data, finding.resource_id)}"
            ),
        }
        for finding in findings
    ]
    rows.extend(
        {
            "generated_at": generated_at,
            "report_version": report_version,
            "evidence_type": "access_review",
            "item_id": review.id,
            "severity": "",
            "status": review.status.value,
            "decision": review.decision.value,
            "identity_id": review.identity_id,
            "resource_id": review.resource_id,
            "owner": "",
            "reviewer": review.reviewer or "",
            "remediation_status": review.remediation_status.value,
            "summary": (
                f"Access review for {identity_display_name(iam_data, review.identity_id)}"
                f" -> {resource_display_name(iam_data, review.resource_id)}"
            ),
        }
        for review in reviews
    )
    return csv_response("governance-evidence.csv", fieldnames, rows)


def findings_csv_response(findings: list[Finding]) -> Response:
    generated_at = get_report_generated_at()
    report_version = app.config["GOVERNANCE_REPORT_VERSION"]
    return csv_response(
        "findings.csv",
        [
            "generated_at",
            "report_version",
            "id",
            "title",
            "severity",
            "score",
            "identity_id",
            "resource_id",
            "finding_type",
            "status",
            "owner",
            "created_at",
            "updated_at",
            "attack_paths",
            "recommendation",
        ],
        [
            {
                "generated_at": generated_at,
                "report_version": report_version,
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "score": finding.score,
                "identity_id": finding.identity_id,
                "resource_id": finding.resource_id or "",
                "finding_type": finding.finding_type,
                "status": finding.status.value,
                "owner": finding.owner or "",
                "created_at": finding.created_at,
                "updated_at": finding.updated_at,
                "attack_paths": "; ".join(finding.attack_paths),
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
    )


def access_reviews_csv_response(reviews: list[AccessReview]) -> Response:
    generated_at = get_report_generated_at()
    report_version = app.config["GOVERNANCE_REPORT_VERSION"]
    return csv_response(
        "access-reviews.csv",
        [
            "generated_at",
            "report_version",
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
            "stale",
        ],
        [
            {
                "generated_at": generated_at,
                "report_version": report_version,
                "id": review.id,
                "identity_id": review.identity_id,
                "resource_id": review.resource_id,
                "status": review.status.value,
                "reviewer": review.reviewer or "",
                "decision": review.decision.value,
                "remediation_status": review.remediation_status.value,
                "notes": review.notes,
                "created_at": review.created_at,
                "updated_at": review.updated_at,
                "stale": is_access_review_stale(review),
            }
            for review in reviews
        ],
    )


def remediation_status_csv_response(reviews: list[AccessReview]) -> Response:
    generated_at = get_report_generated_at()
    report_version = app.config["GOVERNANCE_REPORT_VERSION"]
    return csv_response(
        "remediation-status.csv",
        [
            "generated_at",
            "report_version",
            "review_id",
            "identity_id",
            "resource_id",
            "decision",
            "remediation_status",
            "reviewer",
            "updated_at",
            "notes",
        ],
        [
            {
                "generated_at": generated_at,
                "report_version": report_version,
                "review_id": review.id,
                "identity_id": review.identity_id,
                "resource_id": review.resource_id,
                "decision": review.decision.value,
                "remediation_status": review.remediation_status.value,
                "reviewer": review.reviewer or "",
                "updated_at": review.updated_at,
                "notes": review.notes,
            }
            for review in reviews
        ],
    )


def csv_response(filename: str, fieldnames: list[str], rows: list[dict]) -> Response:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def governance_summary_pdf_response(report: dict) -> Response:
    pdf_bytes = build_pdf(render_governance_report_lines(report))
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=governance-summary.pdf"
        },
    )


def render_governance_report_lines(report: dict) -> list[str]:
    lines = [
        "IAM Sentinel Governance Report",
        f"Generated: {format_report_timestamp(report['generated_at'])}",
        f"Report version: {report['report_version']}",
        "",
        "Executive Summary",
        f"Total Findings: {report['executive_summary']['total_findings']}",
        f"Critical/High IAM Risks: {report['executive_summary']['critical_high_findings']}",
        f"Risky external identities: {report['executive_summary']['risky_external_identities']}",
        f"Open Access Reviews: {report['executive_summary']['open_access_reviews']}",
        f"Pending Remediations: {report['executive_summary']['pending_remediations']}",
        "",
        "Top 5 Critical and High IAM Risks",
    ]
    lines.extend(format_pdf_rows(
        report["critical_high_iam_risks"][:5],
        lambda row: (
            f"{row['severity']} score {row['score']} - {row['title']} "
            f"({row.get('identity_display', row['identity_id'])} -> "
            f"{row.get('resource_display', row['resource_id'] or 'N/A')}) "
            f"status {row['status']}, owner {row['owner']}"
        ),
        "No critical or high IAM risks.",
    ))
    lines.extend(["", "Top 5 Risky Identities"])
    lines.extend(format_pdf_rows(
        report["top_risky_identities"][:5],
        lambda row: (
            f"{report.get('identity_display_names', {}).get(row['identity_id'], row['identity_id'])}: "
            f"{row['finding_count']} findings, "
            f"highest score {row['highest_score']}"
        ),
        "No risky identities.",
    ))
    lines.extend(["", "Top 5 Attack-Path Summaries"])
    lines.extend(format_pdf_rows(
        top_unique_attack_path_summaries(report["attack_path_summaries"], 5),
        lambda row: (
            f"{row['severity']} score {row['score']} - {row['finding_id']}: "
            f"{row.get('identity_display', row['identity_id'])} -> "
            f"{row.get('resource_display', row['resource_id'] or 'N/A')}; "
            f"{row['path']}"
        ),
        "No attack paths recorded.",
    ))
    lines.extend(["", "Access Review Statistics"])
    lines.extend([
        f"Total reviews: {report['access_review_statistics']['total_reviews']}",
        f"Open reviews: {report['access_review_statistics']['open_reviews']}",
        f"In review: {report['access_review_statistics']['in_review_reviews']}",
        f"Completed reviews: {report['access_review_statistics']['completed_reviews']}",
        f"Stale open reviews: {report['access_review_statistics']['stale_open_reviews']}",
    ])
    lines.extend(["", "Remediation Statistics"])
    lines.extend([
        f"Pending remediations: {report['remediation_statistics']['pending_remediations']}",
        f"Completed remediations: {report['remediation_statistics']['completed_remediations']}",
        f"Not required: {report['remediation_statistics']['not_required_remediations']}",
    ])
    return lines


def format_report_timestamp(timestamp: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return str(timestamp)
    return parsed.astimezone(timezone.utc).strftime("%b %d, %Y %H:%M UTC")


def top_unique_attack_path_summaries(rows: list[dict], limit: int) -> list[dict]:
    selected = []
    selected_finding_ids = set()
    for row in rows:
        finding_id = row.get("finding_id")
        if finding_id in selected_finding_ids:
            continue
        selected.append(row)
        selected_finding_ids.add(finding_id)
        if len(selected) == limit:
            return selected

    for row in rows:
        if row in selected:
            continue
        selected.append(row)
        if len(selected) == limit:
            break
    return selected


def format_pdf_rows(rows: list[dict], formatter, empty_message: str) -> list[str]:
    if not rows:
        return [empty_message]
    formatted_rows = []
    for row in rows:
        formatted_rows.extend(wrap(formatter(row), width=96) or [""])
    return formatted_rows


def build_pdf(lines: list[str]) -> bytes:
    page_lines = paginate_pdf_lines(lines)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{' '.join(f'{3 + index * 2} 0 R' for index in range(len(page_lines)))}] /Count {len(page_lines)} >>".encode("ascii"),
    ]

    for index, lines_for_page in enumerate(page_lines):
        page_object_number = 3 + index * 2
        content_object_number = page_object_number + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents {content_object_number} 0 R >>".encode("ascii")
        )
        stream = build_pdf_content_stream(lines_for_page)
        objects.append(
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        )

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for object_number, content in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_number} 0 obj\n".encode("ascii"))
        pdf.extend(content)
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


def paginate_pdf_lines(lines: list[str]) -> list[list[str]]:
    page_size = 48
    return [
        lines[index:index + page_size]
        for index in range(0, len(lines), page_size)
    ] or [[]]


def build_pdf_content_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "14 TL", "50 750 Td"]
    for index, line in enumerate(lines):
        if index:
            commands.append("T*")
        commands.append(f"({escape_pdf_text(line)}) Tj")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def escape_pdf_text(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def format_top_list_for_csv(rows: list[dict], id_key: str) -> str:
    return "; ".join(
        f"{row[id_key]} ({row['finding_count']} findings, max score {row['highest_score']})"
        for row in rows
    )


def access_review_to_dict(review: AccessReview) -> dict:
    iam_data = load_effective_iam_data()
    return {
        "id": review.id,
        "identity_id": review.identity_id,
        "identity_label": identity_display_name(iam_data, review.identity_id),
        "resource_id": review.resource_id,
        "resource_label": resource_display_name(iam_data, review.resource_id),
        "status": review.status.value,
        "reviewer": review.reviewer,
        "decision": review.decision.value,
        "remediation_status": review.remediation_status.value,
        "notes": review.notes,
        "created_at": review.created_at,
        "updated_at": review.updated_at,
        "stale": is_access_review_stale(review),
    }


def access_review_history_to_dict(event: AccessReviewHistoryEvent) -> dict:
    return {
        "review_id": event.review_id,
        "actor": event.actor,
        "timestamp": event.timestamp,
        "changed_field": event.changed_field,
        "old_value": event.old_value,
        "new_value": event.new_value,
    }


def parse_access_review_status(value: str | None) -> AccessReviewStatus | None:
    if value is None:
        return None
    try:
        return AccessReviewStatus(value)
    except ValueError as exc:
        raise ValueError("Invalid access review status.") from exc


def parse_access_review_decision(value: str | None) -> AccessReviewDecision | None:
    if value is None:
        return None
    try:
        return AccessReviewDecision(value)
    except ValueError as exc:
        raise ValueError("Invalid access review decision.") from exc


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
                    "identity_label": format_identity_label(user.name, user.id),
                    "identity_external_user": user.external_user,
                    "identity_service_account": user.service_account,
                    "resource_id": resource.id,
                    "resource_name": resource.name,
                    "resource_label": format_resource_label(resource.name, resource.id),
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
        "label": format_resource_label(resource.name, resource.id),
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
