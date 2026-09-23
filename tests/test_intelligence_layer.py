import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService


@pytest.fixture
def client():
    return TestClient(app)


# --- 1. Detection Engine Tests ---

def test_detection_signals():
    detector = DetectionService()

    # Unknown device
    e_dev = SecurityEvent(event_type="login", metadata={"is_new_device": True})
    assert "unknown_device" in detector.analyze_event(e_dev).signals

    # Sensitive resource
    e_res = SecurityEvent(event_type="api_access", resource="/api/customer-data/pii")
    assert "sensitive_resource" in detector.analyze_event(e_res).signals

    # Unusual API access
    e_api = SecurityEvent(event_type="api_access", resource="/api/export/bulk-dump")
    assert "unusual_api_access" in detector.analyze_event(e_api).signals

    # Privilege escalation
    e_priv = SecurityEvent(event_type="privilege_change", metadata={"privilege_escalation": True})
    assert "privilege_escalation" in detector.analyze_event(e_priv).signals

    # Unexpected AI agent activity
    e_agent = SecurityEvent(event_type="agent_invocation", agent_id="agent_copilot", metadata={"unexpected_agent": True})
    assert "unexpected_agent_activity" in detector.analyze_event(e_agent).signals

    # Unexpected / restricted tool usage
    e_tool = SecurityEvent(event_type="tool_invocation", agent_id="agent_copilot", tool_name="raw_sql_exec")
    assert "unexpected_tool_usage" in detector.analyze_event(e_tool).signals


# --- 2. Correlation Engine Tests ---

def test_correlation_multi_step_sequence():
    correlator = CorrelationService(time_window_minutes=30)
    session_id = "sess_multi_attack_99"
    user_id = "U_CORR_TEST"

    # Step 1: Login
    e1 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="login")
    inc1, sigs1 = correlator.correlate_event(e1, ["unknown_device"])

    # Step 2: Device change
    e2 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="device_change", device_id="D_NEW")
    inc2, sigs2 = correlator.correlate_event(e2, ["unknown_device"])

    # Step 3: API access
    e3 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="api_access", resource="/api/customer-data")
    inc3, sigs3 = correlator.correlate_event(e3, ["sensitive_resource"])

    # Step 4: Agent invocation
    e4 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="agent_invocation", agent_id="agent_copilot")
    inc4, sigs4 = correlator.correlate_event(e4, [])

    # Step 5: Tool invocation
    e5 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="tool_invocation", tool_name="raw_sql_exec")
    inc5, sigs5 = correlator.correlate_event(e5, ["unexpected_tool_usage"])

    # Step 6: Database access
    e6 = SecurityEvent(user_id=user_id, session_id=session_id, event_type="database_access", resource="/db/financial")
    inc6, sigs6 = correlator.correlate_event(e6, ["sensitive_resource"])

    # Single correlated incident check
    assert inc1.id == inc2.id == inc3.id == inc4.id == inc5.id == inc6.id
    assert len(inc6.events) == 6
    assert "abnormal_event_sequence" in sigs6
    assert "unknown_device" in sigs6
    assert "sensitive_resource" in sigs6
    assert "unexpected_tool_usage" in sigs6


# --- 3. Cognee Historical Context Tests ---

@pytest.mark.anyio
async def test_cognee_historical_context():
    cognee = CogneeService()

    # Agent copilot normally uses search_docs, format_json, read_summary
    normal_event = SecurityEvent(agent_id="agent_copilot", tool_name="search_docs", event_type="tool_invocation")
    ctx_normal = await cognee.get_historical_context(normal_event)
    assert ctx_normal["is_anomaly"] is False

    # Agent copilot using novel tool
    anomalous_event = SecurityEvent(agent_id="agent_copilot", tool_name="exfiltrate_tool", event_type="tool_invocation")
    ctx_anomaly = await cognee.get_historical_context(anomalous_event)
    assert ctx_anomaly["is_anomaly"] is True
    assert ctx_anomaly["tool_never_used_by_agent"] is True
    assert "Tool 'exfiltrate_tool' has never previously been used" in ctx_anomaly["summary"]


# --- 4. Risk Engine Tests ---

def test_risk_scoring_and_explanation():
    risk_svc = RiskService()

    # Low risk
    low = risk_svc.assess_risk([])
    assert low.risk_score == 0
    assert low.risk_level.value == "LOW"
    assert "Continue monitoring" in low.recommended_action

    # High / Critical risk
    signals = ["unknown_device", "sensitive_resource", "unexpected_tool_usage", "abnormal_event_sequence"]
    critical = risk_svc.assess_risk(signals, correlated_event_count=4)
    assert critical.risk_score >= 80
    assert critical.risk_level.value == "CRITICAL"
    assert critical.confidence > 0.85
    assert len(critical.reasons) >= 4
    assert "suspend or isolate" in critical.recommended_action.lower()


# --- 5. API POST /api/analyze Tests ---

def test_analyze_with_direct_payload(client):
    payload = {
        "user_id": "U001",
        "device_id": "unknown_macbook_99",
        "session_id": "sess_intel_01",
        "event_type": "api_access",
        "resource": "/api/customer-data/export",
        "metadata": {"is_new_device": True}
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "unknown_device" in data["detected_signals"]
    assert "sensitive_resource" in data["detected_signals"]
    assert data["risk_score"] >= 35
    assert data["risk_level"] in ["MODERATE", "HIGH", "CRITICAL"]
    assert len(data["reasons"]) >= 2
    assert "correlated_incident" in data
    assert data["correlated_incident"]["event_count"] >= 1


def test_analyze_with_existing_event_id(client):
    # Ingest event first
    ingest_resp = client.post("/api/events", json={
        "user_id": "U_STORED_TEST",
        "event_type": "privilege_change",
        "metadata": {"privilege_escalation": True}
    })
    assert ingest_resp.status_code == 201
    event_id = ingest_resp.json()["event"]["id"]

    # Now analyze using event_id
    analyze_resp = client.post("/api/analyze", json={"event_id": event_id})
    assert analyze_resp.status_code == 200
    data = analyze_resp.json()
    assert data["event"]["id"] == event_id
    assert "privilege_escalation" in data["detected_signals"]
    assert data["risk_level"] in ["LOW", "MODERATE", "HIGH"]


def test_analyze_invalid_request(client):
    # Empty payload
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400

    # Non-existent event_id
    response404 = client.post("/api/analyze", json={"event_id": "non-existent-uuid"})
    assert response404.status_code == 404
