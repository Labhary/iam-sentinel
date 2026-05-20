import networkx as nx

from core.models import Finding, IAMData, Severity
from core.rules.shared import (
    CREATED_AT,
    first_resource_id,
    format_sensitive_resource_evidence,
    format_risk_explanation,
    get_formatted_attack_paths,
    get_reachable_sensitive_resources,
    is_privileged_identity,
)
from core.scoring import calculate_risk_score


def detect_service_accounts_with_sensitive_access(
    iam_data: IAMData,
    graph: nx.DiGraph,
) -> list[Finding]:
    findings = []

    for user in iam_data.users:
        if not user.service_account:
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        if not sensitive_resources:
            continue

        is_privileged = is_privileged_identity(iam_data, graph, user.id)
        severity = Severity.CRITICAL if is_privileged else Severity.HIGH
        score = calculate_risk_score(
            severity,
            sensitive_resource=True,
            missing_mfa=not user.mfa_enabled,
        )
        evidence = [
            "Identity is marked as a service account.",
            format_sensitive_resource_evidence(iam_data, sensitive_resources),
        ]
        if is_privileged:
            evidence.append("Service account has privileged admin, manage, or administer capability.")
        risk_factors = ["Service account", "Sensitive resource access"]
        if is_privileged:
            risk_factors.append("Privileged access")
        if not user.mfa_enabled:
            risk_factors.append("Missing MFA")

        findings.append(
            Finding(
                id=f"finding-service-sensitive-{user.id}",
                title="Service account with sensitive access",
                severity=severity,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="service_account_sensitive_access",
                description=f"{user.name} is a service account that can reach sensitive resources.",
                evidence=evidence,
                recommendation="Review service account ownership and restrict access to required resources.",
                attack_paths=get_formatted_attack_paths(graph, user.id, sensitive_resources),
                created_at=CREATED_AT,
                risk_factors=risk_factors,
                risk_explanation=format_risk_explanation(user.name, risk_factors),
            )
        )

    return findings
