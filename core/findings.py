from core.models import Finding, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER[finding.severity],
            -finding.score,
            finding.id,
        ),
    )


def group_findings_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    grouped = {severity: [] for severity in Severity}

    for finding in sort_findings(findings):
        grouped[finding.severity].append(finding)

    return grouped


def summarize_findings(findings: list[Finding]) -> dict:
    counts_by_severity = {severity: 0 for severity in Severity}

    for finding in findings:
        counts_by_severity[finding.severity] += 1

    return {
        "total_findings": len(findings),
        "count_per_severity": counts_by_severity,
        "highest_score": max((finding.score for finding in findings), default=0),
        "affected_identities_count": len({finding.identity_id for finding in findings}),
    }
