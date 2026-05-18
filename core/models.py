from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class User:
    id: str
    name: str
    email: str
    type: str
    groups: list[str]
    roles: list[str]
    mfa_enabled: bool
    last_login: str
    external_user: bool
    service_account: bool


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    roles: list[str]


@dataclass(frozen=True)
class Role:
    id: str
    name: str
    permissions: list[str]


@dataclass(frozen=True)
class Permission:
    id: str
    action: str
    resource: str


@dataclass(frozen=True)
class Resource:
    id: str
    name: str
    type: str
    sensitive: bool


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    score: int
    identity_id: str
    resource_id: Optional[str]
    finding_type: str
    description: str
    evidence: list[str]
    recommendation: str
    attack_paths: list[str]
    created_at: str


@dataclass(frozen=True)
class IAMData:
    users: list[User]
    groups: list[Group]
    roles: list[Role]
    permissions: list[Permission]
    resources: list[Resource]
    users_by_id: dict[str, User]
    groups_by_id: dict[str, Group]
    roles_by_id: dict[str, Role]
    permissions_by_id: dict[str, Permission]
    resources_by_id: dict[str, Resource]
