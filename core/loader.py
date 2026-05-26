import json
from pathlib import Path
from typing import Any

from core.models import Group, IAMData, Permission, Resource, Role, User


REQUIRED_SECTIONS = ("users", "groups", "roles", "permissions", "resources")


class IAMDataValidationError(ValueError):
    """Raised when IAM sample data is missing required structure."""


def load_iam_data(path: str | Path) -> IAMData:
    data_path = Path(path)

    with data_path.open("r", encoding="utf-8") as file:
        raw_data = json.load(file)

    validate_iam_data(raw_data)
    users = [build_user(user) for user in raw_data["users"]]
    groups = [build_group(group) for group in raw_data["groups"]]
    roles = [build_role(role) for role in raw_data["roles"]]
    permissions = [
        build_permission(permission)
        for permission in raw_data["permissions"]
    ]
    resources = [build_resource(resource) for resource in raw_data["resources"]]

    return IAMData(
        users=users,
        groups=groups,
        roles=roles,
        permissions=permissions,
        resources=resources,
        users_by_id={user.id: user for user in users},
        groups_by_id={group.id: group for group in groups},
        roles_by_id={role.id: role for role in roles},
        permissions_by_id={permission.id: permission for permission in permissions},
        resources_by_id={resource.id: resource for resource in resources},
    )


def validate_iam_data(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise IAMDataValidationError("IAM data must be a JSON object.")

    missing_sections = [section for section in REQUIRED_SECTIONS if section not in data]
    if missing_sections:
        missing = ", ".join(missing_sections)
        raise IAMDataValidationError(f"IAM data missing required sections: {missing}")

    for section in REQUIRED_SECTIONS:
        if not isinstance(data[section], list):
            raise IAMDataValidationError(f"IAM data section must be a list: {section}")

    lookups = build_lookup_maps(data)
    validate_relationships(data, lookups)


def build_lookup_maps(data: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    return {
        section: build_lookup_map(section, data[section])
        for section in REQUIRED_SECTIONS
    }


def build_lookup_map(section: str, items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}

    for item in items:
        if not isinstance(item, dict):
            raise IAMDataValidationError(f"IAM data section contains a non-object item: {section}")

        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise IAMDataValidationError(f"IAM data item missing string id in section: {section}")

        if item_id in lookup:
            raise IAMDataValidationError(f"Duplicate id in {section}: {item_id}")

        lookup[item_id] = item

    return lookup


def validate_relationships(
    data: dict[str, Any],
    lookups: dict[str, dict[str, dict[str, Any]]],
) -> None:
    for user in data["users"]:
        user_id = user["id"]
        for group_id in user.get("groups", []):
            require_reference("user", user_id, "group", group_id, lookups["groups"])

        for role_id in user.get("roles", []):
            require_reference("user", user_id, "role", role_id, lookups["roles"])

    for group in data["groups"]:
        group_id = group["id"]
        for role_id in group.get("roles", []):
            require_reference("group", group_id, "role", role_id, lookups["roles"])

    for role in data["roles"]:
        role_id = role["id"]
        for permission_id in role.get("permissions", []):
            require_reference("role", role_id, "permission", permission_id, lookups["permissions"])

    for permission in data["permissions"]:
        permission_id = permission["id"]
        resource_id = permission.get("resource")
        require_reference("permission", permission_id, "resource", resource_id, lookups["resources"])


def require_reference(
    source_type: str,
    source_id: str,
    target_type: str,
    target_id: Any,
    target_lookup: dict[str, dict[str, Any]],
) -> None:
    if not isinstance(target_id, str) or target_id not in target_lookup:
        raise IAMDataValidationError(
            f"Invalid {target_type} reference from {source_type} {source_id}: {target_id}"
        )


def build_user(data: dict[str, Any]) -> User:
    return User(
        id=data["id"],
        name=data["name"],
        email=data["email"],
        type=data["type"],
        groups=list(data.get("groups", [])),
        roles=list(data.get("roles", [])),
        mfa_enabled=data["mfa_enabled"],
        last_login=data["last_login"],
        external_user=data["external_user"],
        service_account=data["service_account"],
        disabled=data.get("disabled", False),
    )


def build_group(data: dict[str, Any]) -> Group:
    return Group(
        id=data["id"],
        name=data["name"],
        roles=list(data.get("roles", [])),
    )


def build_role(data: dict[str, Any]) -> Role:
    return Role(
        id=data["id"],
        name=data["name"],
        permissions=list(data.get("permissions", [])),
    )


def build_permission(data: dict[str, Any]) -> Permission:
    return Permission(
        id=data["id"],
        action=data["action"],
        resource=data["resource"],
    )


def build_resource(data: dict[str, Any]) -> Resource:
    return Resource(
        id=data["id"],
        name=data["name"],
        type=data["type"],
        sensitive=data["sensitive"],
    )
