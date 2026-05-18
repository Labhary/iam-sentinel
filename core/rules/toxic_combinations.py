import networkx as nx

from core.models import Finding, IAMData, Severity
from core.rules.shared import (
    CREATED_AT,
    first_resource_id,
    format_sensitive_resource_evidence,
    get_formatted_attack_paths_for_targets,
    get_reachable_permissions,
    get_reachable_sensitive_resources,
    is_privileged_identity,
)
from core.scoring import calculate_risk_score


TOXIC_PERMISSION_COMBINATIONS = (
    ("read", "manage"),
    ("read", "administer"),
    ("approve", "create"),
    ("manage_roles", "administer_platform"),
)


def detect_toxic_permission_combinations(
    iam_data: IAMData,
    graph: nx.DiGraph,
) -> list[Finding]:
    findings = []

    for user in iam_data.users:
        reachable_permissions = get_reachable_permissions(iam_data, graph, user.id)
        capabilities = get_permission_capabilities(iam_data, reachable_permissions)
        toxic_combinations = get_toxic_combinations(capabilities)
        if not toxic_combinations:
            continue

        sensitive_resources = get_reachable_sensitive_resources(iam_data, graph, user.id)
        is_privileged = is_privileged_identity(iam_data, graph, user.id)
        severity = (
            Severity.CRITICAL
            if sensitive_resources and is_privileged
            else Severity.HIGH
        )
        score = calculate_risk_score(
            severity,
            sensitive_resource=bool(sensitive_resources),
            external_identity=user.external_user,
            missing_mfa=not user.mfa_enabled,
        )

        evidence = [
            format_toxic_combination_evidence(toxic_combinations),
            format_sensitive_resource_evidence(iam_data, sensitive_resources),
        ]
        if is_privileged:
            evidence.append("Identity has privileged admin, manage, or administer capability.")

        findings.append(
            Finding(
                id=f"finding-toxic-combo-{user.id}",
                title="Toxic permission combination",
                severity=severity,
                score=score,
                identity_id=user.id,
                resource_id=first_resource_id(sensitive_resources),
                finding_type="toxic_permission_combination",
                description=f"{user.name} has a separation-of-duties permission conflict.",
                evidence=evidence,
                recommendation="Separate conflicting duties across roles or remove unnecessary permissions.",
                attack_paths=get_formatted_attack_paths_for_targets(
                    graph,
                    user.id,
                    sensitive_resources,
                    reachable_permissions,
                ),
                created_at=CREATED_AT,
            )
        )

    return findings


def get_permission_capabilities(
    iam_data: IAMData,
    permission_ids: list[str],
) -> set[str]:
    capabilities = set()

    for permission_id in permission_ids:
        permission = iam_data.permissions_by_id[permission_id]
        capabilities.add(permission.action)

        if permission_id == "perm-manage-roles":
            capabilities.add("manage_roles")
        if permission_id == "perm-admin-users":
            capabilities.add("administer_platform")

    return capabilities


def get_toxic_combinations(capabilities: set[str]) -> list[tuple[str, str]]:
    return [
        combination
        for combination in TOXIC_PERMISSION_COMBINATIONS
        if combination[0] in capabilities and combination[1] in capabilities
    ]


def format_toxic_combination_evidence(combinations: list[tuple[str, str]]) -> str:
    formatted_combinations = [
        f"{format_capability(left)} + {format_capability(right)}"
        for left, right in combinations
    ]
    return f"Toxic permission combinations found: {', '.join(formatted_combinations)}."


def format_capability(capability: str) -> str:
    return capability.replace("_", " ")
