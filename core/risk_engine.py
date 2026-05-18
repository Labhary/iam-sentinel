from datetime import date

import networkx as nx

from core.models import Finding, IAMData
from core.rules.dormant_privileged import detect_dormant_privileged_accounts
from core.rules.external_sensitive import detect_external_identities_with_sensitive_access
from core.rules.privileged_mfa import detect_privileged_accounts_without_mfa
from core.rules.service_accounts import detect_service_accounts_with_sensitive_access
from core.rules.toxic_combinations import detect_toxic_permission_combinations
from core.rules.wildcard_permissions import detect_wildcard_or_admin_permissions


def run_all_detections(
    iam_data: IAMData,
    graph: nx.DiGraph,
    analysis_date: date | None = None,
) -> list[Finding]:
    return (
        detect_privileged_accounts_without_mfa(iam_data, graph)
        + detect_dormant_privileged_accounts(iam_data, graph, analysis_date)
        + detect_external_identities_with_sensitive_access(iam_data, graph)
        + detect_service_accounts_with_sensitive_access(iam_data, graph)
        + detect_toxic_permission_combinations(iam_data, graph)
        + detect_wildcard_or_admin_permissions(iam_data, graph)
    )
