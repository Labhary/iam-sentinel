import json
from pathlib import Path
from typing import Any

from core.models import IAMData


REQUIRED_SECTIONS = ("users", "groups", "roles", "permissions", "resources")


class IAMDataValidationError(ValueError):
    """Raised when IAM sample data is missing required structure."""


def load_iam_data(path: str | Path) -> IAMData:
    data_path = Path(path)

    with data_path.open("r", encoding="utf-8") as file:
        raw_data = json.load(file)

    validate_iam_data(raw_data)
    lookups = build_lookup_maps(raw_data)

    return IAMData(
        users=raw_data["users"],
        groups=raw_data["groups"],
        roles=raw_data["roles"],
        permissions=raw_data["permissions"],
        resources=raw_data["resources"],
        users_by_id=lookups["users"],
        groups_by_id=lookups["groups"],
        roles_by_id=lookups["roles"],
        permissions_by_id=lookups["permissions"],
        resources_by_id=lookups["resources"],
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
