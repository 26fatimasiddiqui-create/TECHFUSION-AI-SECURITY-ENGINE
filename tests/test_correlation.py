from datetime import datetime, timezone, timedelta
from app.models.event import SecurityEvent
from app.services.correlation_service import CorrelationService


def test_event_correlation_by_user():
    service = CorrelationService(time_window_minutes=30)
    now = datetime.now(timezone.utc)

    event1 = SecurityEvent(
        user_id="U001",
        session_id="sess_alpha",
        event_type="login",
        timestamp=now
    )
    incident1, signals1 = service.correlate_event(event1, ["unknown_device"])

    event2 = SecurityEvent(
        user_id="U001",
        session_id="sess_alpha",
        event_type="api_access",
        resource="/api/customer-data",
        timestamp=now + timedelta(minutes=2)
    )
    incident2, signals2 = service.correlate_event(event2, ["sensitive_resource"])

    # Both events must be grouped under the same incident
    assert incident1.id == incident2.id
    assert len(incident2.events) == 2
    assert "unknown_device" in signals2
    assert "sensitive_resource" in signals2


def test_correlation_time_window_expiration():
    service = CorrelationService(time_window_minutes=10)
    now = datetime.now(timezone.utc)

    event1 = SecurityEvent(
        user_id="U002",
        event_type="login",
        timestamp=now
    )
    incident1, _ = service.correlate_event(event1, [])

    # Event 2 occurs 20 minutes later (beyond 10 minute window)
    event2 = SecurityEvent(
        user_id="U002",
        event_type="login",
        timestamp=now + timedelta(minutes=20)
    )
    incident2, _ = service.correlate_event(event2, [])

    # Must create a separate incident
    assert incident1.id != incident2.id
