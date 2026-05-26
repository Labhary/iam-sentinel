from pathlib import Path

from core.graph_builder import (
    build_identity_graph,
    format_attack_path,
    get_attack_paths,
    get_reachable_resources,
)
from core.loader import load_iam_data


SAMPLE_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"


def test_build_identity_graph_creates_nodes_with_metadata() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))

    assert graph.nodes["user-003"]["node_type"] == "user"
    assert graph.nodes["user-003"]["display_name"] == "Ananya Rao"
    assert graph.nodes["grp-admins"]["node_type"] == "group"
    assert graph.nodes["role-platform-admin"]["node_type"] == "role"
    assert graph.nodes["perm-read-payroll"]["node_type"] == "permission"
    assert graph.nodes["res-payroll-system"]["node_type"] == "resource"


def test_build_identity_graph_creates_relationship_edges() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))

    assert graph.has_edge("user-001", "grp-finance-readers")
    assert graph.has_edge("user-001", "role-finance-viewer")
    assert graph.has_edge("grp-finance-readers", "role-finance-viewer")
    assert graph.has_edge("role-finance-viewer", "perm-read-finance")
    assert graph.has_edge("perm-read-finance", "res-finance-reports")


def test_get_reachable_resources_supports_inherited_group_access() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))

    reachable_resources = get_reachable_resources(graph, "user-001")

    assert "res-finance-reports" in reachable_resources


def test_get_attack_paths_returns_ordered_node_sequences() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))

    paths = get_attack_paths(graph, "user-001", "res-finance-reports")

    assert [
        "user-001",
        "grp-finance-readers",
        "role-finance-viewer",
        "perm-read-finance",
        "res-finance-reports",
    ] in paths


def test_format_attack_path_uses_display_names() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))

    formatted_path = format_attack_path(
        graph,
        [
            "user-005",
            "grp-admins",
            "role-platform-admin",
            "perm-manage-roles",
            "res-role-catalog",
        ],
    )

    assert formatted_path == (
        "Nadia El Fassi -> Identity Platform Administrators -> "
        "Identity Platform Admin -> Manage Roles -> IAM Role Catalog"
    )


def test_format_attack_path_falls_back_to_node_id_when_display_name_is_missing() -> None:
    graph = build_identity_graph(load_iam_data(SAMPLE_DATA_PATH))
    del graph.nodes["role-platform-admin"]["display_name"]

    formatted_path = format_attack_path(
        graph,
        ["user-005", "grp-admins", "role-platform-admin"],
    )

    assert formatted_path == "Nadia El Fassi -> Identity Platform Administrators -> role-platform-admin"
