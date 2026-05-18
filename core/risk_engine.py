from datetime import date

import networkx as nx

from core.graph_builder import format_attack_path, get_attack_paths, get_reachable_resources
from core.models import Finding, IAMData, Severity, User
from core.scoring import calculate_risk_score


CREATED_AT = "2026-05-18T00:00:00Z"
DORMANT_DAYS = 90
TOXIC_PERMISSION_COMBINATIONS = (
    ("read", "manage"),
    ("read", "administer"),
    ("approve", "create"),
    ("manage_roles", "administer_platform"),
)


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
            )
        )

    return findings


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
            )
        )

    return findings


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
            )
        )

    return findings


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
                attack_paths=get_formatted_attack_paths_for_toxic_permissions(
                    graph,
                    user.id,
                    sensitive_resources,
                    reachable_permissions,
                ),
                created_at=CREATED_AT,
            )
        )

    return findings


def run_all_detections(
    iam_data: IAMData,
    graph: nx.DiGraph,
    analysis_date: date | None = None,
) -> list[Finding]:
    return (
        detect_privileged_accounts_without_mfa(iam_data, graph)
        + detect_dormant_privileged_accounts(iam_data, graph, analysis_date)
        + detect_external_identities_with_sensitive_access(iam_data, graph)
        + detect_service_accounts_with_sensitive_access(iam_data, graph)
        + detect_toxic_permission_combinations(iam_data, graph)
    )


def is_privileged_identity(iam_data: IAMData, graph: nx.DiGraph, user_id: str) -> bool:
    if user_id not in graph:
        return False

    reachable_nodes = nx.descendants(graph, user_id)

    for node_id in reachable_nodes:
        if graph.nodes[node_id].get("node_type") == "role":
            role = iam_data.roles_by_id[node_id]
            if "admin" in role.id.lower() or "admin" in role.name.lower():
                return True

        if graph.nodes[node_id].get("node_type") == "permission":
            permission = iam_data.permissions_by_id[node_id]
            if permission.action in {"manage", "administer"}:
                return True

    return False


def get_reachable_sensitive_resources(
    iam_data: IAMData,
    graph: nx.DiGraph,
    user_id: str,
) -> list[str]:
    return [
        resource_id
        for resource_id in get_reachable_resources(graph, user_id)
        if iam_data.resources_by_id[resource_id].sensitive
    ]


def get_reachable_permissions(
    iam_data: IAMData,
    graph: nx.DiGraph,
    user_id: str,
) -> list[str]:
    if user_id not in graph:
        return []

    permission_ids = [
        node_id
        for node_id in nx.descendants(graph, user_id)
        if graph.nodes[node_id].get("node_type") == "permission"
    ]
    return sorted(
        permission_id
        for permission_id in permission_ids
        if permission_id in iam_data.permissions_by_id
    )


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


def get_formatted_attack_paths_for_toxic_permissions(
    graph: nx.DiGraph,
    user_id: str,
    sensitive_resource_ids: list[str],
    permission_ids: list[str],
) -> list[str]:
    target_ids = sensitive_resource_ids if sensitive_resource_ids else permission_ids
    formatted_paths = []

    for target_id in target_ids:
        for path in get_attack_paths(graph, user_id, target_id):
            formatted_paths.append(format_attack_path(graph, path))

    return sorted(formatted_paths)


def get_formatted_attack_paths(
    graph: nx.DiGraph,
    user_id: str,
    resource_ids: list[str],
) -> list[str]:
    formatted_paths = []

    for resource_id in resource_ids:
        for path in get_attack_paths(graph, user_id, resource_id):
            formatted_paths.append(format_attack_path(graph, path))

    return sorted(formatted_paths)


def days_since_last_login(user: User, analysis_date: date) -> int:
    last_login = date.fromisoformat(user.last_login)
    return (analysis_date - last_login).days


def get_analysis_date(analysis_date: date | None) -> date:
    if analysis_date is None:
        return date.today()
    return analysis_date


def first_resource_id(resource_ids: list[str]) -> str | None:
    if not resource_ids:
        return None
    return sorted(resource_ids)[0]


def format_sensitive_resource_evidence(iam_data: IAMData, resource_ids: list[str]) -> str:
    if not resource_ids:
        return "No sensitive resources are reachable."

    resource_names = [
        iam_data.resources_by_id[resource_id].name
        for resource_id in sorted(resource_ids)
    ]
    return f"Reachable sensitive resources: {', '.join(resource_names)}."
