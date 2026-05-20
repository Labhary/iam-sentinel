import sqlite3
import uuid
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core.models import AccessReview, AccessReviewDecision, AccessReviewStatus


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
                notes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
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
                notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    updated_at: str | None = None,
) -> AccessReview | None:
    initialize_access_review_database(db_path)
    reviews_by_id = {review.id: review for review in load_access_reviews(db_path)}
    if review_id not in reviews_by_id:
        return None

    current = reviews_by_id[review_id]
    updated = AccessReview(
        id=current.id,
        identity_id=current.identity_id,
        resource_id=current.resource_id,
        status=status or current.status,
        reviewer=current.reviewer if reviewer is None else reviewer,
        decision=decision or current.decision,
        notes=current.notes if notes is None else notes,
        created_at=current.created_at,
        updated_at=get_timestamp(updated_at),
    )

    with connect(db_path) as connection:
        connection.execute(
            """
            UPDATE access_reviews
            SET status = ?,
                reviewer = ?,
                decision = ?,
                notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                updated.status.value,
                updated.reviewer,
                updated.decision.value,
                updated.notes,
                updated.updated_at,
                updated.id,
            ),
        )

    return updated


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
                notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review["id"],
                review["identity_id"],
                review["resource_id"],
                review["status"],
                review.get("reviewer"),
                review["decision"],
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
        notes=row[6],
        created_at=row[7],
        updated_at=row[8],
    )


def get_timestamp(timestamp: str | None = None) -> str:
    if timestamp is not None:
        return timestamp
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
