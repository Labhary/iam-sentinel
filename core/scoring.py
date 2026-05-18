from core.models import Severity


SEVERITY_SCORES = {
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}


def severity_to_score(severity: Severity) -> int:
    return SEVERITY_SCORES[severity]


def calculate_risk_score(
    severity: Severity,
    *,
    sensitive_resource: bool = False,
    external_identity: bool = False,
    missing_mfa: bool = False,
) -> int:
    score = severity_to_score(severity)

    if sensitive_resource:
        score += 5
    if external_identity:
        score += 5
    if missing_mfa:
        score += 5

    return min(score, 100)


def score_to_severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW
