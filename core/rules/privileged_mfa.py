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


def detect_privileged_accounts_without_mfa(
    iam_data: IAMData,
    graph: nx.DiGraph,
) -> list[Finding]:
    findings = []

    for user in iam_data.users:
        if user.mfa_enabled or not is_privileged_identity(iam_data, graph, user.id):
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        attack_paths = get_formatted_attack_paths(graph, user.id, sensitive_resources)
        score = calculate_risk_score(
            Severity.HIGH,
            sensitive_resource=bool(sensitive_resources),
            external_identity=user.external_user,
            missing_mfa=True,
        )
        risk_factors = ["Missing MFA", "Privileged access"]
        if sensitive_resources:
            risk_factors.append("Sensitive resource access")
        if user.external_user:
            risk_factors.append("External identity")

        findings.append(
            Finding(
                id=f"finding-mfa-{user.id}",
                title="Privileged account without MFA",
                severity=Severity.HIGH,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="privileged_mfa",
                description=(
                    f"{user.name} has privileged access while multi-factor authentication is disabled."
                ),
                evidence=[
                    "MFA is disabled.",
                    "Identity has an admin role, manage capability, or administer capability.",
                    format_sensitive_resource_evidence(iam_data, sensitive_resources),
                ],
                recommendation="Enable MFA or remove privileged access from the identity.",
                attack_paths=attack_paths,
                created_at=CREATED_AT,
                risk_factors=risk_factors,
                risk_explanation=format_risk_explanation(user.name, risk_factors),
            )
        )

    return findings
