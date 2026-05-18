from pathlib import Path

import pytest

from core.loader import IAMDataValidationError, load_iam_data, validate_iam_data


SAMPLE_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"


def test_sample_iam_data_loads() -> None:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)

    assert len(iam_data.users) >= 6
    assert len(iam_data.groups) > 0
    assert len(iam_data.roles) > 0
    assert len(iam_data.permissions) > 0
    assert len(iam_data.resources) > 0


def test_sample_iam_data_loads_normalized_lookups() -> None:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)

    assert iam_data.users_by_id["user-003"]["name"] == "Priya Nair"
    assert iam_data.groups_by_id["grp-admins"]["name"] == "Platform Administrators"
    assert iam_data.roles_by_id["role-platform-admin"]["name"] == "Platform Admin"
    assert iam_data.permissions_by_id["perm-read-payroll"]["resource"] == "res-payroll-system"
    assert iam_data.resources_by_id["res-payroll-system"]["sensitive"] is True


def test_sample_iam_data_contains_required_identity_types() -> None:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)
    identity_types = {user["type"] for user in iam_data.users}

    assert "normal_user" in identity_types
    assert "developer" in identity_types
    assert "admin" in identity_types
    assert "external_contractor" in identity_types
    assert "dormant_user" in identity_types
    assert "service_account" in identity_types


def test_sample_iam_data_contains_required_user_fields() -> None:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)
    required_user_fields = {
        "id",
        "name",
        "email",
        "groups",
        "roles",
        "mfa_enabled",
        "last_login",
        "external_user",
        "service_account",
    }

    for user in iam_data.users:
        assert required_user_fields.issubset(user)


def test_sample_iam_data_contains_sensitive_resources() -> None:
    iam_data = load_iam_data(SAMPLE_DATA_PATH)

    assert any(resource["sensitive"] for resource in iam_data.resources)


def test_validate_iam_data_rejects_missing_required_section() -> None:
    invalid_data = {
        "users": [],
        "groups": [],
        "roles": [],
        "permissions": []
    }

    with pytest.raises(IAMDataValidationError):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_duplicate_ids() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["users"].append({
        "id": "user-001",
        "groups": [],
        "roles": []
    })

    with pytest.raises(IAMDataValidationError, match="Duplicate id in users: user-001"):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_invalid_user_group_reference() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["users"][0]["groups"] = ["grp-missing"]

    with pytest.raises(
        IAMDataValidationError,
        match="Invalid group reference from user user-001: grp-missing",
    ):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_invalid_user_role_reference() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["users"][0]["roles"] = ["role-missing"]

    with pytest.raises(
        IAMDataValidationError,
        match="Invalid role reference from user user-001: role-missing",
    ):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_invalid_group_role_reference() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["groups"][0]["roles"] = ["role-missing"]

    with pytest.raises(
        IAMDataValidationError,
        match="Invalid role reference from group grp-001: role-missing",
    ):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_invalid_role_permission_reference() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["roles"][0]["permissions"] = ["perm-missing"]

    with pytest.raises(
        IAMDataValidationError,
        match="Invalid permission reference from role role-001: perm-missing",
    ):
        validate_iam_data(invalid_data)


def test_validate_iam_data_rejects_invalid_permission_resource_reference() -> None:
    invalid_data = minimal_valid_data()
    invalid_data["permissions"][0]["resource"] = "res-missing"

    with pytest.raises(
        IAMDataValidationError,
        match="Invalid resource reference from permission perm-001: res-missing",
    ):
        validate_iam_data(invalid_data)


def minimal_valid_data() -> dict:
    return {
        "users": [
            {
                "id": "user-001",
                "groups": ["grp-001"],
                "roles": ["role-001"],
            }
        ],
        "groups": [
            {
                "id": "grp-001",
                "roles": ["role-001"],
            }
        ],
        "roles": [
            {
                "id": "role-001",
                "permissions": ["perm-001"],
            }
        ],
        "permissions": [
            {
                "id": "perm-001",
                "resource": "res-001",
            }
        ],
        "resources": [
            {
                "id": "res-001",
            }
        ],
    }
