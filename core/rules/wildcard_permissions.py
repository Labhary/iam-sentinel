import networkx as nx

from core.models import Finding, IAMData, Severity
from core.rules.shared import (
    CREATED_AT,
    first_resource_id,
    format_sensitive_resource_evidence,
    format_risk_explanation,
    get_formatted_attack_paths_for_targets,
    get_reachable_permissions,
    get_reachable_sensitive_resources,
)
from core.scoring import calculate_risk_score


def detect_wildcard_or_admin_permissions(
    iam_data: IAMData,
    graph: nx.DiGraph,
) -> list[Finding]:
    findings = []

    for user in iam_data.users:
        risky_permissions = get_reachable_wildcard_or_admin_permissions(iam_data, graph, user.id)
        if not risky_permissions:
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        severity = Severity.CRITICAL if sensitive_resources else Severity.HIGH
        score = calculate_risk_score(
            severity,
            sensitive_resource=bool(sensitive_resources),
            external_identity=user.external_user,
            missing_mfa=not user.mfa_enabled,
        )
        risk_factors = ["Wildcard/admin permission"]
        if sensitive_resources:
            risk_factors.append("Sensitive resource access")
        if user.external_user:
            risk_factors.append("External identity")
        if not user.mfa_enabled:
            risk_factors.append("Missing MFA")

        findings.append(
            Finding(
                id=f"finding-wildcard-admin-{user.id}",
                title="Wildcard or admin-like permission",
                severity=severity,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="wildcard_or_admin_permission",
                description=f"{user.name} can reach wildcard or admin-like permissions.",
                evidence=[
                    format_risky_permission_evidence(iam_data, risky_permissions),
                    format_sensitive_resource_evidence(iam_data, sensitive_resources),
                ],
                recommendation="Replace broad permissions with scoped least-privilege access.",
                attack_paths=get_formatted_attack_paths_for_targets(
                    graph,
                    user.id,
                    sensitive_resources,
                    risky_permissions,
                ),
                created_at=CREATED_AT,
                risk_factors=risk_factors,
                risk_explanation=format_risk_explanation(user.name, risk_factors),
            )
        )

    return findings


def get_reachable_wildcard_or_admin_permissions(
    iam_data: IAMData,
    graph: nx.DiGraph,
    user_id: str,
) -> list[str]:
    return [
        permission_id
        for permission_id in get_reachable_permissions(iam_data, graph, user_id)
        if is_wildcard_or_admin_permission(iam_data.permissions_by_id[permission_id].action)
    ]


def is_wildcard_or_admin_permission(action: str) -> bool:
    normalized_action = action.lower()
    return (
        normalized_action == "*"
        or normalized_action.startswith("admin:")
        or normalized_action == "manage_all"
    )


def format_risky_permission_evidence(iam_data: IAMData, permission_ids: list[str]) -> str:
    permission_summaries = []

    for permission_id in permission_ids:
        permission = iam_data.permissions_by_id[permission_id]
        resource = iam_data.resources_by_id[permission.resource]
        permission_summaries.append(
            f"{permission.id} action={permission.action} resource={resource.name}"
        )

    return f"Risky permissions found: {', '.join(permission_summaries)}."
