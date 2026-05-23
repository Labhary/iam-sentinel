import sqlite3
import uuid
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core.models import (
    AccessReview,
    AccessReviewDecision,
    AccessReviewHistoryEvent,
    AccessReviewRemediationStatus,
    AccessReviewStatus,
)


ACTIVE_REVIEW_STATUSES = {
    AccessReviewStatus.OPEN.value,
    AccessReviewStatus.IN_REVIEW.value,
}
STALE_REVIEW_DAYS = 7
DEFAULT_DEMO_REVIEWS_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_access_reviews.json"
DEFAULT_DEMO_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "findings.db"


def initialize_access_review_database(db_path: str | Path) -> None:
    resolved_db_path = Path(db_path).resolve()
    with connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS access_reviews (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewer TEXT,
                decision TEXT NOT NULL,
                remediation_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
                notes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_access_reviews_remediation_column(connection)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS access_review_history (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'Unassigned Analyst',
                timestamp TEXT NOT NULL,
                changed_field TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT
            )
            """
        )
        ensure_access_review_history_actor_column(connection)
        seed_demo_access_reviews(connection, resolved_db_path)


def create_access_review(
    db_path: str | Path,
    identity_id: str,
    resource_id: str,
    created_at: str | None = None,
) -> AccessReview | None:
    initialize_access_review_database(db_path)
    if active_review_exists(db_path, identity_id, resource_id):
        return None

    timestamp = get_timestamp(created_at)
    review = AccessReview(
        id=f"review-{uuid.uuid4().hex}",
        identity_id=identity_id,
        resource_id=resource_id,
        status=AccessReviewStatus.OPEN,
        reviewer=None,
        decision=AccessReviewDecision.UNDECIDED,
        remediation_status=AccessReviewRemediationStatus.NOT_REQUIRED,
        notes="",
        created_at=timestamp,
        updated_at=timestamp,
    )

    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO access_reviews (
                id,
                identity_id,
                resource_id,
                status,
                reviewer,
                decision,
                remediation_status,
                notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            review_to_row(review),
        )

    return review


def load_access_reviews(db_path: str | Path) -> list[AccessReview]:
    initialize_access_review_database(db_path)

    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                identity_id,
                resource_id,
                status,
                reviewer,
                decision,
                remediation_status,
                notes,
                created_at,
                updated_at
            FROM access_reviews
            ORDER BY updated_at DESC, created_at DESC, id ASC
            """
        ).fetchall()

    return [row_to_review(row) for row in rows]


def update_access_review(
    db_path: str | Path,
    review_id: str,
    status: AccessReviewStatus | None = None,
    reviewer: str | None = None,
    decision: AccessReviewDecision | None = None,
    notes: str | None = None,
    actor: str | None = None,
    updated_at: str | None = None,
) -> AccessReview | None:
    initialize_access_review_database(db_path)
    reviews_by_id = {review.id: review for review in load_access_reviews(db_path)}
    if review_id not in reviews_by_id:
        return None

    current = reviews_by_id[review_id]
    updated_decision = decision or current.decision
    timestamp = get_timestamp(updated_at)
    updated = AccessReview(
        id=current.id,
        identity_id=current.identity_id,
        resource_id=current.resource_id,
        status=status or current.status,
        reviewer=current.reviewer if reviewer is None else reviewer,
        decision=updated_decision,
        remediation_status=get_remediation_status_for_decision(
            updated_decision,
            current.remediation_status,
        ),
        notes=current.notes if notes is None else notes,
        created_at=current.created_at,
        updated_at=timestamp,
    )
    history_events = build_access_review_history_events(
        current,
        updated,
        timestamp,
        normalize_history_actor(actor),
    )

    with connect(db_path) as connection:
        connection.execute(
            """
            UPDATE access_reviews
            SET status = ?,
                reviewer = ?,
                decision = ?,
                remediation_status = ?,
                notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                updated.status.value,
                updated.reviewer,
                updated.decision.value,
                updated.remediation_status.value,
                updated.notes,
                updated.updated_at,
                updated.id,
            ),
        )
        insert_access_review_history_events(connection, history_events)

    return updated


def complete_access_review_remediation(
    db_path: str | Path,
    review_id: str,
    actor: str | None = None,
    updated_at: str | None = None,
) -> AccessReview | None:
    initialize_access_review_database(db_path)
    reviews_by_id = {review.id: review for review in load_access_reviews(db_path)}
    if review_id not in reviews_by_id:
        return None

    current = reviews_by_id[review_id]
    timestamp = get_timestamp(updated_at)
    updated = AccessReview(
        id=current.id,
        identity_id=current.identity_id,
        resource_id=current.resource_id,
        status=current.status,
        reviewer=current.reviewer,
        decision=current.decision,
        remediation_status=AccessReviewRemediationStatus.COMPLETED,
        notes=current.notes,
        created_at=current.created_at,
        updated_at=timestamp,
    )
    normalized_actor = normalize_history_actor(actor)
    history_events = []
    if current.remediation_status != updated.remediation_status:
        history_events.append(
            AccessReviewHistoryEvent(
                review_id=updated.id,
                actor=normalized_actor,
                timestamp=timestamp,
                changed_field="remediation_status",
                old_value=current.remediation_status.value,
                new_value=updated.remediation_status.value,
            )
        )
    history_events.append(
        AccessReviewHistoryEvent(
            review_id=updated.id,
            actor=normalized_actor,
            timestamp=timestamp,
            changed_field="remediation_completed",
            old_value=current.remediation_status.value,
            new_value=updated.remediation_status.value,
        )
    )

    with connect(db_path) as connection:
        connection.execute(
            """
            UPDATE access_reviews
            SET remediation_status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                updated.remediation_status.value,
                updated.updated_at,
                updated.id,
            ),
        )
        insert_access_review_history_events(connection, history_events)

    return updated


def load_access_review_history(
    db_path: str | Path,
    review_id: str,
) -> list[AccessReviewHistoryEvent]:
    initialize_access_review_database(db_path)

    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                review_id,
                actor,
                timestamp,
                changed_field,
                old_value,
                new_value
            FROM access_review_history
            WHERE review_id = ?
            ORDER BY timestamp DESC, rowid DESC
            """,
            (review_id,),
        ).fetchall()

    return [
        AccessReviewHistoryEvent(
            review_id=row[0],
            actor=row[1],
            timestamp=row[2],
            changed_field=row[3],
            old_value=row[4],
            new_value=row[5],
        )
        for row in rows
    ]


def build_access_review_history_events(
    current: AccessReview,
    updated: AccessReview,
    timestamp: str,
    actor: str,
) -> list[AccessReviewHistoryEvent]:
    tracked_fields = [
        ("status", current.status.value, updated.status.value),
        ("decision", current.decision.value, updated.decision.value),
        (
            "remediation_status",
            current.remediation_status.value,
            updated.remediation_status.value,
        ),
        ("reviewer", current.reviewer, updated.reviewer),
        ("notes", current.notes, updated.notes),
    ]

    return [
        AccessReviewHistoryEvent(
            review_id=updated.id,
            actor=actor,
            timestamp=timestamp,
            changed_field=field,
            old_value=old_value,
            new_value=new_value,
        )
        for field, old_value, new_value in tracked_fields
        if old_value != new_value
    ]


def ensure_access_review_history_actor_column(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(access_review_history)").fetchall()
    }
    if "actor" not in columns:
        connection.execute(
            "ALTER TABLE access_review_history ADD COLUMN actor TEXT NOT NULL DEFAULT 'Unassigned Analyst'"
        )


def ensure_access_reviews_remediation_column(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(access_reviews)").fetchall()
    }
    if "remediation_status" not in columns:
        connection.execute(
            "ALTER TABLE access_reviews ADD COLUMN remediation_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED'"
        )


def normalize_history_actor(actor: str | None) -> str:
    normalized_actor = (actor or "").strip()
    return normalized_actor or "Unassigned Analyst"


def get_remediation_status_for_decision(
    decision: AccessReviewDecision,
    current_status: AccessReviewRemediationStatus,
) -> AccessReviewRemediationStatus:
    if decision in {AccessReviewDecision.REVOKE, AccessReviewDecision.NEEDS_FOLLOW_UP}:
        if current_status == AccessReviewRemediationStatus.COMPLETED:
            return current_status
        return AccessReviewRemediationStatus.PENDING
    return AccessReviewRemediationStatus.NOT_REQUIRED


def insert_access_review_history_events(
    connection: sqlite3.Connection,
    history_events: list[AccessReviewHistoryEvent],
) -> None:
    for event in history_events:
        connection.execute(
            """
            INSERT INTO access_review_history (
                id,
                review_id,
                actor,
                timestamp,
                changed_field,
                old_value,
                new_value
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"history-{uuid.uuid4().hex}",
                event.review_id,
                event.actor,
                event.timestamp,
                event.changed_field,
                event.old_value,
                event.new_value,
            ),
        )


def active_review_exists(
    db_path: str | Path,
    identity_id: str,
    resource_id: str,
) -> bool:
    initialize_access_review_database(db_path)

    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM access_reviews
            WHERE identity_id = ?
              AND resource_id = ?
              AND status IN (?, ?)
            LIMIT 1
            """,
            (
                identity_id,
                resource_id,
                AccessReviewStatus.OPEN.value,
                AccessReviewStatus.IN_REVIEW.value,
            ),
        ).fetchone()

    return row is not None


def build_access_review_metrics(
    reviews: list[AccessReview],
    reference_time: datetime | None = None,
) -> dict:
    reviewer_counts = Counter(
        normalize_reviewer(review.reviewer)
        for review in reviews
    )
    resource_counts = Counter(review.resource_id for review in reviews)
    identity_counts = Counter(review.identity_id for review in reviews)
    reviewers = {
        review.reviewer
        for review in reviews
        if review.reviewer
    }

    return {
        "total_reviews": len(reviews),
        "open_reviews": count_status(reviews, AccessReviewStatus.OPEN),
        "in_review_reviews": count_status(reviews, AccessReviewStatus.IN_REVIEW),
        "completed_reviews": count_status(reviews, AccessReviewStatus.COMPLETED),
        "pending_remediations": count_remediation_status(
            reviews,
            AccessReviewRemediationStatus.PENDING,
        ),
        "completed_remediations": count_remediation_status(
            reviews,
            AccessReviewRemediationStatus.COMPLETED,
        ),
        "approve_decisions": count_decision(reviews, AccessReviewDecision.APPROVE),
        "revoke_decisions": count_decision(reviews, AccessReviewDecision.REVOKE),
        "needs_follow_up_decisions": count_decision(
            reviews,
            AccessReviewDecision.NEEDS_FOLLOW_UP,
        ),
        "undecided_reviews": count_decision(reviews, AccessReviewDecision.UNDECIDED),
        "stale_open_reviews": sum(
            1
            for review in reviews
            if is_access_review_stale(review, reference_time)
        ),
        "unique_reviewers": len(reviewers),
        "reviews_per_reviewer": format_counter(reviewer_counts, "reviewer"),
        "most_reviewed_resources": format_counter(resource_counts, "resource_id"),
        "most_reviewed_identities": format_counter(identity_counts, "identity_id"),
    }


def is_access_review_stale(
    review: AccessReview,
    reference_time: datetime | None = None,
) -> bool:
    if review.status.value not in ACTIVE_REVIEW_STATUSES:
        return False

    resolved_reference_time = reference_time or datetime.now(timezone.utc)
    updated_at = parse_timestamp(review.updated_at)
    return (resolved_reference_time - updated_at).days > STALE_REVIEW_DAYS


def count_status(reviews: list[AccessReview], status: AccessReviewStatus) -> int:
    return sum(1 for review in reviews if review.status == status)


def count_decision(reviews: list[AccessReview], decision: AccessReviewDecision) -> int:
    return sum(1 for review in reviews if review.decision == decision)


def count_remediation_status(
    reviews: list[AccessReview],
    remediation_status: AccessReviewRemediationStatus,
) -> int:
    return sum(1 for review in reviews if review.remediation_status == remediation_status)


def format_counter(counter: Counter, key_name: str) -> list[dict]:
    return [
        {
            key_name: item_id,
            "count": count,
        }
        for item_id, count in sorted(
            counter.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]


def normalize_reviewer(reviewer: str | None) -> str:
    if not reviewer:
        return "Unassigned"
    return reviewer


def parse_timestamp(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def connect(db_path: str | Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(db_path))


def seed_demo_access_reviews(connection: sqlite3.Connection, db_path: Path) -> None:
    if db_path != DEFAULT_DEMO_DB_PATH:
        return

    row = connection.execute("SELECT COUNT(*) FROM access_reviews").fetchone()
    if row is None or row[0] != 0 or not DEFAULT_DEMO_REVIEWS_PATH.exists():
        return

    with DEFAULT_DEMO_REVIEWS_PATH.open("r", encoding="utf-8") as file:
        reviews = json.load(file)

    for review in reviews:
        connection.execute(
            """
            INSERT INTO access_reviews (
                id,
                identity_id,
                resource_id,
                status,
                reviewer,
                decision,
                remediation_status,
                notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review["id"],
                review["identity_id"],
                review["resource_id"],
                review["status"],
                review.get("reviewer"),
                review["decision"],
                get_remediation_status_for_decision(
                    AccessReviewDecision(review["decision"]),
                    AccessReviewRemediationStatus.NOT_REQUIRED,
                ).value,
                review.get("notes", ""),
                review["created_at"],
                review["updated_at"],
            ),
        )


def review_to_row(review: AccessReview) -> tuple:
    return (
        review.id,
        review.identity_id,
        review.resource_id,
        review.status.value,
        review.reviewer,
        review.decision.value,
        review.remediation_status.value,
        review.notes,
        review.created_at,
        review.updated_at,
    )


def row_to_review(row: tuple) -> AccessReview:
    return AccessReview(
        id=row[0],
        identity_id=row[1],
        resource_id=row[2],
        status=AccessReviewStatus(row[3]),
        reviewer=row[4],
        decision=AccessReviewDecision(row[5]),
        remediation_status=AccessReviewRemediationStatus(row[6]),
        notes=row[7],
        created_at=row[8],
        updated_at=row[9],
    )


def get_timestamp(timestamp: str | None = None) -> str:
    if timestamp is not None:
        return timestamp
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
