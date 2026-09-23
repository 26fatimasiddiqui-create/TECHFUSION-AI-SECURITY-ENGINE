from app.models.event import SecurityEvent
from app.services.detection_service import DetectionService


def test_normal_event_detection():
    detector = DetectionService()
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        event_type="api_access",
        resource="/api/public/status"
    )
    result = detector.analyze_event(event)
    assert result.is_suspicious is False
    assert len(result.signals) == 0


def test_unknown_device_detection():
    detector = DetectionService()
    event = SecurityEvent(
        user_id="U001",
        device_id="unknown_laptop_123",
        event_type="login",
        metadata={"is_new_device": True}
    )
    result = detector.analyze_event(event)
    assert result.is_suspicious is True
    assert "unknown_device" in result.signals


def test_sensitive_resource_detection():
    detector = DetectionService()
    event = SecurityEvent(
        user_id="U001",
        event_type="api_access",
        resource="/api/customer-data/pii/export"
    )
    result = detector.analyze_event(event)
    assert result.is_suspicious is True
    assert "sensitive_resource" in result.signals


def test_unusual_tool_usage_detection():
    detector = DetectionService()
    event = SecurityEvent(
        agent_id="agent_copilot",
        event_type="tool_invocation",
        tool_name="raw_sql_exec"
    )
    result = detector.analyze_event(event)
    assert result.is_suspicious is True
    assert "unusual_tool_usage" in result.signals


def test_privilege_escalation_detection():
    detector = DetectionService()
    event = SecurityEvent(
        user_id="U001",
        event_type="privilege_change",
        metadata={"privilege_escalation": True, "role": "admin"}
    )
    result = detector.analyze_event(event)
    assert result.is_suspicious is True
    assert "privilege_escalation" in result.signals
