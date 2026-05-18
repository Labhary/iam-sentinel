from datetime import date
from pathlib import Path

from core.analysis_runner import run_analysis
from core.finding_store import load_findings


SAMPLE_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_iam.json"
FIXED_ANALYSIS_DATE = date(2026, 5, 18)
FIXED_EXECUTION_TIMESTAMP = "2026-05-18T12:00:00Z"


def test_run_analysis_executes_and_returns_findings(tmp_path) -> None:
    db_path = tmp_path / "findings.db"

    result = run_analysis(
        iam_data_path=SAMPLE_DATA_PATH,
        db_path=db_path,
        analysis_date=FIXED_ANALYSIS_DATE,
        execution_timestamp=FIXED_EXECUTION_TIMESTAMP,
    )

    assert result["total_findings"] == 7
    assert result["execution_timestamp"] == FIXED_EXECUTION_TIMESTAMP
    assert [finding.id for finding in result["findings"]] == [
        "finding-toxic-combo-user-003",
        "finding-toxic-combo-user-005",
        "finding-wildcard-admin-user-002",
        "finding-external-sensitive-user-004",
        "finding-dormant-user-005",
        "finding-mfa-user-005",
        "finding-service-sensitive-user-006",
    ]


def test_run_analysis_persists_findings(tmp_path) -> None:
    db_path = tmp_path / "findings.db"

    result = run_analysis(
        iam_data_path=SAMPLE_DATA_PATH,
        db_path=db_path,
        analysis_date=FIXED_ANALYSIS_DATE,
        execution_timestamp=FIXED_EXECUTION_TIMESTAMP,
    )

    persisted_findings = load_findings(db_path)
    assert persisted_findings == result["findings"]


def test_run_analysis_repeated_runs_are_deterministic_and_do_not_duplicate(tmp_path) -> None:
    db_path = tmp_path / "findings.db"

    first_result = run_analysis(
        iam_data_path=SAMPLE_DATA_PATH,
        db_path=db_path,
        analysis_date=FIXED_ANALYSIS_DATE,
        execution_timestamp=FIXED_EXECUTION_TIMESTAMP,
    )
    second_result = run_analysis(
        iam_data_path=SAMPLE_DATA_PATH,
        db_path=db_path,
        analysis_date=FIXED_ANALYSIS_DATE,
        execution_timestamp=FIXED_EXECUTION_TIMESTAMP,
    )

    assert second_result == first_result
    assert len(load_findings(db_path)) == 7
