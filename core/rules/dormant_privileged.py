from datetime import date

import networkx as nx

from core.models import Finding, IAMData, Severity
from core.rules.shared import (
    CREATED_AT,
    DORMANT_DAYS,
    days_since_last_login,
    first_resource_id,
    format_sensitive_resource_evidence,
    format_risk_explanation,
    get_analysis_date,
    get_formatted_attack_paths,
    get_reachable_sensitive_resources,
    is_privileged_identity,
)
from core.scoring import calculate_risk_score


def detect_dormant_privileged_accounts(
    iam_data: IAMData,
    graph: nx.DiGraph,
    analysis_date: date | None = None,
) -> list[Finding]:
    findings = []
    resolved_analysis_date = get_analysis_date(analysis_date)

    for user in iam_data.users:
        dormant_days = days_since_last_login(user, resolved_analysis_date)
        if dormant_days <= DORMANT_DAYS or not is_privileged_identity(iam_data, graph, user.id):
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        score = calculate_risk_score(
            Severity.HIGH,
            sensitive_resource=bool(sensitive_resources),
            external_identity=user.external_user,
            missing_mfa=not user.mfa_enabled,
        )
        risk_factors = ["Dormant identity", "Privileged access"]
        if sensitive_resources:
            risk_factors.append("Sensitive resource access")
        if user.external_user:
            risk_factors.append("External identity")
        if not user.mfa_enabled:
            risk_factors.append("Missing MFA")

        findings.append(
            Finding(
                id=f"finding-dormant-{user.id}",
                title="Dormant privileged account",
                severity=Severity.HIGH,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="dormant_privileged",
                description=(
                    f"{user.name} has privileged access but has not logged in for "
                    f"{dormant_days} days."
                ),
                evidence=[
                    f"Last login was {user.last_login}.",
                    f"Identity has been dormant for {dormant_days} days.",
                    "Identity has an admin role, manage capability, or administer capability.",
                    format_sensitive_resource_evidence(iam_data, sensitive_resources),
                ],
                recommendation="Review ownership and disable or remove unused privileged access.",
                attack_paths=get_formatted_attack_paths(graph, user.id, sensitive_resources),
                created_at=CREATED_AT,
                risk_factors=risk_factors,
                risk_explanation=format_risk_explanation(user.name, risk_factors),
            )
        )

    return findings
