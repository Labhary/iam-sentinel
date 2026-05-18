from datetime import date

import networkx as nx

from core.graph_builder import format_attack_path, get_attack_paths, get_reachable_resources
from core.models import IAMData, User


CREATED_AT = "2026-05-18T00:00:00Z"
DORMANT_DAYS = 90


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


def get_formatted_attack_paths_for_targets(
    graph: nx.DiGraph,
    user_id: str,
    sensitive_resource_ids: list[str],
    fallback_target_ids: list[str],
) -> list[str]:
    target_ids = sensitive_resource_ids if sensitive_resource_ids else fallback_target_ids
    formatted_paths = []

    for target_id in target_ids:
        for path in get_attack_paths(graph, user_id, target_id):
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
