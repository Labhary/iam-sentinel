from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AccessReviewStatus(Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    COMPLETED = "COMPLETED"


class AccessReviewDecision(Enum):
    UNDECIDED = "UNDECIDED"
    APPROVE = "APPROVE"
    REVOKE = "REVOKE"
    NEEDS_FOLLOW_UP = "NEEDS_FOLLOW_UP"


class AccessReviewRemediationStatus(Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"


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
    disabled: bool = False


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
    status: FindingStatus = FindingStatus.OPEN
    owner: Optional[str] = None
    analyst_notes: list[str] = field(default_factory=list)
    updated_at: Optional[str] = None
    risk_factors: list[str] = field(default_factory=list)
    risk_explanation: str = ""

    def __post_init__(self) -> None:
        if self.updated_at is None:
            object.__setattr__(self, "updated_at", self.created_at)


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


@dataclass(frozen=True)
class AccessReview:
    id: str
    identity_id: str
    resource_id: str
    status: AccessReviewStatus
    reviewer: Optional[str]
    decision: AccessReviewDecision
    remediation_status: AccessReviewRemediationStatus
    notes: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AccessReviewHistoryEvent:
    review_id: str
    actor: str
    timestamp: str
    changed_field: str
    old_value: Optional[str]
    new_value: Optional[str]
