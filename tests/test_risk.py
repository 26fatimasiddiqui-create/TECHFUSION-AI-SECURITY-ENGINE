from app.services.risk_service import RiskService
from app.models.risk import RiskLevel


def test_zero_signals_low_risk():
    risk_svc = RiskService()
    assessment = risk_svc.assess_risk([])
    assert assessment.risk_score == 0
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.recommended_action == "Continue monitoring"


def test_moderate_risk_accumulation():
    risk_svc = RiskService()
    # unknown_device (15) + sensitive_resource (20) = 35 -> MODERATE
    assessment = risk_svc.assess_risk(["unknown_device", "sensitive_resource"])
    assert assessment.risk_score == 35
    assert assessment.risk_level == RiskLevel.MODERATE
    assert "Continue monitoring" not in assessment.recommended_action
    assert len(assessment.reasons) == 2


def test_critical_risk_accumulation():
    risk_svc = RiskService()
    # unknown_device (15) + sensitive_resource (20) + privilege_escalation (25) + unusual_tool_usage (20) + multi_event (15) = 95 -> CRITICAL
    signals = [
        "unknown_device",
        "sensitive_resource",
        "privilege_escalation",
        "unusual_tool_usage",
        "multi_event_correlated_chain",
    ]
    assessment = risk_svc.assess_risk(signals)
    assert assessment.risk_score >= 80
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert "suspend or isolate" in assessment.recommended_action.lower()
    assert len(assessment.reasons) >= 4
