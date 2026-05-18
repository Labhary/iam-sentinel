from datetime import date, datetime, timezone
from pathlib import Path

from core.finding_store import save_findings
from core.findings import sort_findings
from core.graph_builder import build_identity_graph
from core.loader import load_iam_data
from core.models import Finding
from core.risk_engine import run_all_detections


DEFAULT_IAM_DATA_PATH = Path("data") / "sample_iam.json"
DEFAULT_FINDINGS_DB_PATH = Path("data") / "findings.db"


def run_analysis(
    iam_data_path: str | Path = DEFAULT_IAM_DATA_PATH,
    db_path: str | Path = DEFAULT_FINDINGS_DB_PATH,
    analysis_date: date | None = None,
    execution_timestamp: str | None = None,
) -> dict:
    iam_data = load_iam_data(iam_data_path)
    graph = build_identity_graph(iam_data)
    findings = sort_findings(run_all_detections(iam_data, graph, analysis_date))

    save_findings(db_path, findings)

    return {
        "findings": findings,
        "total_findings": len(findings),
        "execution_timestamp": get_execution_timestamp(execution_timestamp),
    }


def get_execution_timestamp(execution_timestamp: str | None) -> str:
    if execution_timestamp is not None:
        return execution_timestamp
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
