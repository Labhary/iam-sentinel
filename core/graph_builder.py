from typing import Any

import networkx as nx

from core.models import IAMData


def build_identity_graph(iam_data: IAMData) -> nx.DiGraph:
    graph = nx.DiGraph()

    add_nodes(graph, iam_data.users, "user")
    add_nodes(graph, iam_data.groups, "group")
    add_nodes(graph, iam_data.roles, "role")
    add_nodes(graph, iam_data.permissions, "permission")
    add_nodes(graph, iam_data.resources, "resource")

    for user in iam_data.users:
        if user.disabled:
            continue
        user_id = user.id
        for group_id in user.groups:
            graph.add_edge(user_id, group_id, relationship="member_of")
        for role_id in user.roles:
            graph.add_edge(user_id, role_id, relationship="has_role")

    for group in iam_data.groups:
        group_id = group.id
        for role_id in group.roles:
            graph.add_edge(group_id, role_id, relationship="grants_role")

    for role in iam_data.roles:
        role_id = role.id
        for permission_id in role.permissions:
            graph.add_edge(role_id, permission_id, relationship="grants_permission")

    for permission in iam_data.permissions:
        graph.add_edge(
            permission.id,
            permission.resource,
            relationship="applies_to",
        )

    return graph


def get_reachable_resources(graph: nx.DiGraph, user_id: str) -> list[str]:
    if user_id not in graph:
        return []

    descendants = nx.descendants(graph, user_id)
    resources = [
        node_id
        for node_id in descendants
        if graph.nodes[node_id].get("node_type") == "resource"
    ]

    return sorted(resources)


def get_attack_paths(
    graph: nx.DiGraph,
    user_id: str,
    target_resource_id: str,
) -> list[list[str]]:
    if user_id not in graph or target_resource_id not in graph:
        return []

    paths = nx.all_simple_paths(graph, source=user_id, target=target_resource_id)
    return [list(path) for path in paths]


def format_attack_path(graph: nx.DiGraph, path: list[str]) -> str:
    display_names = [
        graph.nodes[node_id].get("display_name", node_id)
        if node_id in graph
        else node_id
        for node_id in path
    ]

    return " -> ".join(display_names)


def add_nodes(graph: nx.DiGraph, items: list[Any], node_type: str) -> None:
    for item in items:
        node_id = item.id
        graph.add_node(
            node_id,
            node_type=node_type,
            display_name=get_display_name(item, node_type),
        )


def get_display_name(item: Any, node_type: str) -> str:
    if getattr(item, "name", None):
        return item.name

    item_id = item.id
    if node_type == "permission" and item_id.startswith("perm-"):
        return item_id.removeprefix("perm-").replace("-", " ").title()

    return item_id
