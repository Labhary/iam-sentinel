from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IAMData:
    users: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    roles: list[dict[str, Any]]
    permissions: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    users_by_id: dict[str, dict[str, Any]]
    groups_by_id: dict[str, dict[str, Any]]
    roles_by_id: dict[str, dict[str, Any]]
    permissions_by_id: dict[str, dict[str, Any]]
    resources_by_id: dict[str, dict[str, Any]]
