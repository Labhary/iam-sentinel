import networkx as nx

from core.models import Finding, IAMData, Severity
from core.rules.shared import (
    CREATED_AT,
    first_resource_id,
    format_sensitive_resource_evidence,
    get_formatted_attack_paths,
    get_reachable_sensitive_resources,
)
from core.scoring import calculate_risk_score


def detect_external_identities_with_sensitive_access(
    iam_data: IAMData,
    graph: nx.DiGraph,
) -> list[Finding]:
    findings = []

    for user in iam_data.users:
        if not user.external_user:
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        if not sensitive_resources:
            continue

        score = calculate_risk_score(
            Severity.HIGH,
            sensitive_resource=True,
            external_identity=True,
            missing_mfa=not user.mfa_enabled,
        )

        findings.append(
            Finding(
                id=f"finding-external-sensitive-{user.id}",
                title="External identity with sensitive access",
                severity=Severity.HIGH,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="external_sensitive_access",
                description=f"{user.name} is external and can reach sensitive resources.",
                evidence=[
                    "Identity is marked as external.",
                    format_sensitive_resource_evidence(iam_data, sensitive_resources),
                ],
                recommendation="Limit external access to least privilege and require MFA.",
                attack_paths=get_formatted_attack_paths(graph, user.id, sensitive_resources),
                created_at=CREATED_AT,
            )
        )

    return findings
