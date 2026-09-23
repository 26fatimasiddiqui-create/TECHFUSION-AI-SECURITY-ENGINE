import pytest
from datetime import datetime, timezone, timedelta
from app.models.event import SecurityEvent, EventType
from app.models.risk import RiskLevel
from app.services.detection_service import DetectionService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.correlation_service import CorrelationService
from app.services.activity_graph_service import ActivityGraphService
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def cognee_svc():
    return CogneeService()


@pytest.fixture
def detection_svc():
    return DetectionService()


@pytest.fixture
def risk_svc():
    return RiskService()


@pytest.fixture
def correlation_svc():
    return CorrelationService(time_window_minutes=60)


@pytest.fixture
def repo():
    return SupabaseRepository()


# 1. Known device + known IP = normal
@pytest.mark.anyio
async def test_known_device_and_known_ip_is_normal(cognee_svc, detection_svc, risk_svc):
    """User U001 logging in with known device D001 from known IP 10.0.0.1 during normal hours (10:00 UTC)."""
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_normal_01",
        event_type="login",
        timestamp=datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc),
        metadata={"ip": "10.0.0.1", "location": "delhi"}
    )
    context = await cognee_svc.get_historical_context(event)
    detection = detection_svc.analyze_event(event, historical_context=context)

    # Should not flag new_device or new_ip
    assert "new_device" not in detection.signals
    assert "unknown_device" not in detection.signals
    assert "new_ip" not in detection.signals
    assert "abnormal_login_time" not in detection.signals

    assessment = risk_svc.assess_risk(detection.signals, context=context)
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score == 0


# 2. New device only = low / contextual risk (NOT confirmed threat)
@pytest.mark.anyio
async def test_new_device_only_is_low_contextual_risk(cognee_svc, detection_svc, risk_svc):
    """New device alone must create a risk signal but NOT be classified as confirmed threat (score <= 25, LOW)."""
    event = SecurityEvent(
        user_id="U001",
        device_id="MacBook_Pro_Unseen_99",
        session_id="sess_new_dev_01",
        event_type="login",
        timestamp=datetime(2026, 9, 23, 11, 0, tzinfo=timezone.utc),
        metadata={"ip": "10.0.0.1", "is_new_device": True}
    )
    context = await cognee_svc.get_historical_context(event)
    detection = detection_svc.analyze_event(event, historical_context=context)

    assert "new_device" in detection.signals or "unknown_device" in detection.signals
    assert "new_ip" not in detection.signals

    assessment = risk_svc.assess_risk(detection.signals, context=context)
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score <= 25
    assert "suspend or isolate" not in assessment.recommended_action.lower()


# 3. New IP only = low / contextual risk (NOT confirmed threat)
@pytest.mark.anyio
async def test_new_ip_only_is_low_contextual_risk(cognee_svc, detection_svc, risk_svc):
    """New IP alone must NOT be classified as confirmed threat (contextual risk signal, score <= 25, LOW)."""
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_new_ip_01",
        event_type="login",
        timestamp=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
        metadata={"ip": "198.51.100.42"}  # Unseen public IP for U001
    )
    context = await cognee_svc.get_historical_context(event)
    detection = detection_svc.analyze_event(event, historical_context=context)

    assert "new_ip" in detection.signals
    assert "new_device" not in detection.signals

    assessment = risk_svc.assess_risk(detection.signals, context=context)
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score <= 25


# 4. Impossible travel
@pytest.mark.anyio
async def test_impossible_travel_detection(cognee_svc, detection_svc, risk_svc):
    """User logs in from Delhi, then 20 minutes later logs in from London."""
    t0 = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)
    event1 = SecurityEvent(
        user_id="U_TRAVELER",
        device_id="dev_delhi",
        session_id="sess_t1",
        event_type="login",
        timestamp=t0,
        metadata={"location": "delhi", "ip": "10.0.0.1"}
    )

    t1 = t0 + timedelta(minutes=20)
    event2 = SecurityEvent(
        user_id="U_TRAVELER",
        device_id="dev_london",
        session_id="sess_t2",
        event_type="login",
        timestamp=t1,
        metadata={"location": "london", "ip": "81.2.69.144"}
    )

    detection = detection_svc.analyze_event(event2, recent_events=[event1])
    assert "impossible_travel" in detection.signals
    assert "Impossible travel" in detection.details["impossible_travel"]

    # Also test Cognee baseline historical location check
    context = await cognee_svc.get_historical_context(event2)
    detection_with_context = detection_svc.analyze_event(event2, historical_context=context, recent_events=[event1])
    assert "impossible_travel" in detection_with_context.signals


# 5. Abnormal login time
@pytest.mark.anyio
async def test_abnormal_login_time_detection(cognee_svc, detection_svc, risk_svc):
    """User U001 (normal hours 08:00 to 19:00 UTC) logs in at 03:00 UTC."""
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_night",
        event_type="login",
        timestamp=datetime(2026, 9, 23, 3, 15, tzinfo=timezone.utc),
        metadata={"ip": "10.0.0.1"}
    )
    context = await cognee_svc.get_historical_context(event)
    detection = detection_svc.analyze_event(event, historical_context=context)

    assert "abnormal_login_time" in detection.signals
    assessment = risk_svc.assess_risk(detection.signals, context=context)
    # Abnormal login time alone is contextual (LOW risk)
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score <= 25


# 6. Sensitive resource access (Contextual, not standalone malicious)
@pytest.mark.anyio
async def test_sensitive_resource_access_contextual(detection_svc, risk_svc):
    """Legitimate user accessing /api/customer-data should not automatically be classified as malicious."""
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_sens",
        event_type="api_access",
        resource="/api/customer-data/query",
        timestamp=datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc),
        metadata={"records_requested": 10}
    )
    detection = detection_svc.analyze_event(event)
    assert "sensitive_resource" in detection.signals

    assessment = risk_svc.assess_risk(detection.signals)
    # Standalone sensitive resource access remains LOW
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score <= 25


# 7. Bulk data access
@pytest.mark.anyio
async def test_bulk_data_access_detection(detection_svc, risk_svc):
    """Detects unusually large numbers of records requested or bulk export endpoint."""
    # A. Via records count threshold (>= 1000)
    event1 = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_bulk",
        event_type="api_access",
        resource="/api/v1/payroll/view",
        metadata={"records_requested": 5000}
    )
    detection1 = detection_svc.analyze_event(event1)
    assert "bulk_data_access" in detection1.signals

    # B. Via bulk endpoint
    event2 = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_bulk_2",
        event_type="api_access",
        resource="/api/v1/customer-data/export",
        metadata={}
    )
    detection2 = detection_svc.analyze_event(event2)
    assert "bulk_data_access" in detection2.signals


# 8. Privilege escalation transition tracking
@pytest.mark.anyio
async def test_privilege_escalation_transition(detection_svc, risk_svc):
    """Tracks transition: previous privilege -> new privilege -> subsequent activity."""
    t0 = datetime(2026, 9, 23, 11, 0, tzinfo=timezone.utc)
    event1 = SecurityEvent(
        user_id="U_ESCALATE",
        device_id="dev_01",
        session_id="sess_esc",
        event_type="privilege_change",
        timestamp=t0,
        metadata={
            "previous_role": "Analyst",
            "new_role": "Administrator",
            "privilege_escalation": True,
        }
    )
    detection1 = detection_svc.analyze_event(event1)
    assert "privilege_escalation" in detection1.signals
    assert "Analyst -> Administrator" in detection1.details["privilege_escalation"]

    # Subsequent activity using elevated privileges
    event2 = SecurityEvent(
        user_id="U_ESCALATE",
        device_id="dev_01",
        session_id="sess_esc",
        event_type="database_access",
        resource="/database/customer_credentials/dump",
        timestamp=t0 + timedelta(minutes=2),
        metadata={"role": "Administrator"}
    )
    detection2 = detection_svc.analyze_event(event2, recent_events=[event1])
    assert "privilege_escalation" in detection2.signals


# 9. Unusual API activity
@pytest.mark.anyio
async def test_unusual_api_activity(detection_svc, risk_svc):
    """Detects API calls unusual by endpoint or burst flag."""
    event = SecurityEvent(
        user_id="U001",
        device_id="D001",
        session_id="sess_api",
        event_type="api_access",
        resource="/api/v1/system/backup",
        metadata={"burst_api": True}
    )
    detection = detection_svc.analyze_event(event)
    assert "unusual_api_activity" in detection.signals
    assert "unusual_api_access" in detection.signals


# 10. Multiple signals increasing risk (Multi-Signal Correlation)
@pytest.mark.anyio
async def test_multiple_signals_increasing_risk(risk_svc):
    """Verifies that single weak signals remain LOW, but their combination escalates into CRITICAL."""
    # Single signal: New IP alone
    r_ip = risk_svc.assess_risk(["new_ip"])
    assert r_ip.risk_score <= 15
    assert r_ip.risk_level == RiskLevel.LOW

    # Single signal: New Device alone
    r_dev = risk_svc.assess_risk(["new_device"])
    assert r_dev.risk_score <= 20
    assert r_dev.risk_level == RiskLevel.LOW

    # Single signal: Abnormal Login Time alone
    r_time = risk_svc.assess_risk(["abnormal_login_time"])
    assert r_time.risk_score <= 15
    assert r_time.risk_level == RiskLevel.LOW

    # Multi-signal combination:
    # New Device + New IP + Abnormal Login Time + Sensitive Resource + Bulk Data Access
    combined_signals = [
        "new_device",
        "new_ip",
        "abnormal_login_time",
        "sensitive_resource",
        "bulk_data_access",
    ]
    r_multi = risk_svc.assess_risk(combined_signals)
    # Must produce significantly higher contextual risk
    assert r_multi.risk_score >= 80
    assert r_multi.risk_level == RiskLevel.CRITICAL
    assert len(r_multi.reasons) >= 5
    assert "Require human approval / suspend or isolate" in r_multi.recommended_action


# 11. Correlated internal attack chain into single incident
@pytest.mark.anyio
async def test_correlated_internal_attack_chain(correlation_svc, detection_svc, risk_svc):
    """Attack chain:
    USER -> LOGIN -> NEW DEVICE -> NEW IP -> SENSITIVE API -> BULK DATA ACCESS
    Must correlate into a single incident with collective signals and elevated risk.
    """
    user_id = "J. Singh"
    session_id = "sess_chain_attack_99"
    shared_device = "Unknown Device (Kali Linux)"
    shared_ip = "203.0.113.195"

    events = [
        SecurityEvent(
            user_id=user_id,
            device_id=shared_device,
            session_id=session_id,
            event_type="login",
            resource="/auth/login",
            metadata={"ip": shared_ip, "is_new_device": True, "is_new_ip": True}
        ),
        SecurityEvent(
            user_id=user_id,
            device_id=shared_device,
            session_id=session_id,
            event_type="api_access",
            resource="/api/v1/payroll/export",
            metadata={"ip": shared_ip, "records_requested": 5000}
        ),
        SecurityEvent(
            user_id=user_id,
            device_id=shared_device,
            session_id=session_id,
            event_type="database_access",
            resource="/database/customer_credentials/dump",
            metadata={"ip": shared_ip, "privilege_escalation": True}
        )
    ]

    last_incident = None
    for evt in events:
        detection = detection_svc.analyze_event(evt)
        inc, signals = correlation_svc.correlate_event(evt, detection.signals)
        last_incident = inc

    # Check unified correlation
    assert last_incident is not None
    assert len(last_incident.events) == 3
    assert last_incident.primary_entity == user_id
    # Collective signals aggregated across the sequence
    for expected_sig in ["new_device", "new_ip", "sensitive_resource", "bulk_data_access", "privilege_escalation"]:
        assert expected_sig in last_incident.signals_detected

    # Final incident risk assessment
    assessment = risk_svc.assess_risk(last_incident.signals_detected, correlated_event_count=3)
    assert assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert assessment.risk_score >= 70


# 12. Legitimate unusual activity not automatically classified as malicious (False positive handling)
@pytest.mark.anyio
async def test_legitimate_unusual_activity_not_automatically_malicious(cognee_svc, detection_svc, risk_svc):
    """An engineer accessing a sensitive documentation guide from their usual workstation."""
    event = SecurityEvent(
        user_id="A. Verma",
        device_id="Laptop (Windows)",
        session_id="sess_eng_01",
        event_type="api_access",
        resource="/api/customer-data/read",
        timestamp=datetime(2026, 9, 23, 14, 0, tzinfo=timezone.utc),
        metadata={"ip": "192.168.1.10"}
    )
    context = await cognee_svc.get_historical_context(event)
    detection = detection_svc.analyze_event(event, historical_context=context)

    assessment = risk_svc.assess_risk(detection.signals, context=context)
    # Must remain LOW risk (no alert)
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.risk_score <= 25


# 13. Cognee fallback resilience
@pytest.mark.anyio
async def test_cognee_fallback_resilience():
    """Cognee service operates seamlessly in offline mode with full local knowledge baselines."""
    svc = CogneeService()
    svc.api_key = "invalid_or_offline_key"
    svc.api_url = "http://127.0.0.1:9999"  # non-existent port

    event = SecurityEvent(
        user_id="U001",
        device_id="Unknown_Device_Offline",
        session_id="sess_offline",
        event_type="login",
        metadata={"ip": "10.99.99.99"}
    )
    # Should not crash; returns local baseline gracefully
    context = await svc.get_historical_context(event)
    assert isinstance(context, dict)
    assert "is_anomaly" in context
    assert context["device_unseen_for_user"] is True
    assert context["ip_unseen_for_user"] is True


# 14. User Activity Graph integration
@pytest.mark.anyio
async def test_activity_graph_internal_threat_integration(repo, detection_svc, correlation_svc, cognee_svc, risk_svc):
    """User Activity Graph includes IP node, device connection edge, and represents internal threat signals."""
    graph_svc = ActivityGraphService(repo, detection_svc, correlation_svc, cognee_svc, risk_svc)
    user_id = "U_GRAPH_TEST"
    session_id = "sess_graph_01"

    # Insert event
    event = SecurityEvent(
        user_id=user_id,
        device_id="MacBook_Graph_01",
        session_id=session_id,
        event_type="login",
        timestamp=datetime.now(timezone.utc),
        metadata={"ip": "192.168.50.100", "is_new_device": True, "is_new_ip": True}
    )
    await repo.insert_event(event)

    graph = await graph_svc.build_user_activity_graph(user_id=user_id)
    assert graph.user_id == user_id
    assert len(graph.nodes) >= 3  # User, Login, Device, IP

    # Verify IP node was derived
    ip_nodes = [n for n in graph.nodes if n.type.value == "IP"]
    assert len(ip_nodes) == 1
    assert "192.168.50.100" in ip_nodes[0].label

    # Verify Device -> IP edge exists
    edges = [e for e in graph.edges if e.relationship.value == "DEVICE_CONNECTED_FROM_IP"]
    assert len(edges) == 1
