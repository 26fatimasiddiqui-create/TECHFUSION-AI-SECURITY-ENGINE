import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def client():
    return TestClient(app)


# =====================================================================
# 1. Integration Requirements Verification
# =====================================================================

def test_full_pipeline_ingest_and_intelligence(client):
    """Verifies requirements 1-10:
    1. Receive event
    2. Store event
    3. Generate detection signals
    4. Correlate related events
    5. Retrieve Cognee context
    6. Calculate risk score and level
    7. Generate explanation
    8. Store alert
    9. n8n trigger
    10. Trigger automation on HIGH/CRITICAL
    """
    session_id = "sess_verify_pipeline_100"
    user_id = "U_INTEGRATION_VERIFY"

    # Step A: Ingest Event 1 via /api/events
    r1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_OFFICE_01",
        "session_id": session_id,
        "event_type": "login",
        "metadata": {}
    })
    assert r1.status_code == 201
    d1 = r1.json()
    assert d1["status"] == "success"
    assert d1["event"]["id"] is not None
    incident_id = d1["incident_id"]

    # Step B: Ingest Event 2 (Suspicious) via n8n automation endpoint
    r2 = client.post("/api/n8n/process-event", json={
        "user_id": user_id,
        "device_id": "unknown_device_remote",
        "session_id": session_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "resource": "/api/customer-data/pii/export",
        "metadata": {"is_new_device": True}
    })
    assert r2.status_code == 200
    d2 = r2.json()

    # Verify n8n received clean escalation flags
    assert d2["status"] == "processed"
    assert d2["should_escalate"] is True
    assert d2["alert_created"] is True
    assert d2["risk_level"] in ["HIGH", "CRITICAL"]
    assert d2["risk_score"] >= 60
    assert d2["incident_id"] == incident_id  # correlated!
    assert len(d2["reasons"]) >= 3
    assert d2["notification_summary"].startswith("🚨 PS-8 Security Incident")

    # Verify Alert was stored
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert any(a["incident_id"] == incident_id for a in alerts)


# =====================================================================
# 2. Failure Handling Tests
# =====================================================================

def test_failure_invalid_event_missing_type(client):
    """Missing required event_type -> 422 Validation Error."""
    response = client.post("/api/events", json={"user_id": "U001"})
    assert response.status_code == 422


def test_failure_invalid_event_blank_type(client):
    """Blank/empty event_type -> 422 Validation Error."""
    response = client.post("/api/events", json={"user_id": "U001", "event_type": "   "})
    assert response.status_code == 422


def test_failure_n8n_malformed_request(client):
    """Malformed body to n8n endpoint -> 422 Validation Error."""
    response = client.post("/api/n8n/process-event", json={"metadata": "not_a_dict"})
    assert response.status_code == 422


@pytest.mark.anyio
async def test_failure_supabase_unavailable_fallback():
    """When Supabase client fails, repository must fall back cleanly without raising."""
    repo = SupabaseRepository()
    # Force client to None (simulating unavailable credentials / offline network)
    repo.supabase_client = None

    test_event = SecurityEvent(
        user_id="U_OFFLINE_TEST",
        event_type="api_access",
        resource="/api/test"
    )
    saved = await repo.insert_event(test_event)
    assert saved.id == test_event.id

    # Retrieve from memory cache
    retrieved = await repo.get_event_by_id(test_event.id)
    assert retrieved is not None
    assert retrieved.user_id == "U_OFFLINE_TEST"


@pytest.mark.anyio
async def test_failure_cognee_unavailable_fallback():
    """When Cognee API is unreachable or invalid key, CogneeService must return baseline without crashing."""
    cognee = CogneeService()
    cognee.api_key = "invalid_or_offline_key"
    cognee.api_url = "https://non-existent-cognee-host-9999.invalid"

    test_event = SecurityEvent(
        agent_id="agent_copilot",
        tool_name="search_docs",
        event_type="tool_invocation"
    )

    # Should not raise exception, falls back to local knowledge baseline
    ctx = await cognee.get_historical_context(test_event)
    assert ctx is not None
    assert "is_anomaly" in ctx
    assert "summary" in ctx


# =====================================================================
# 3. Complete 6-Step Synthetic Demo Security Scenario
# =====================================================================

def test_six_step_synthetic_security_scenario(client):
    """Executes the exact 6-step attack path specified in the user request:
    1. Normal login
    2. Unknown device
    3. Sensitive API access
    4. AI-agent invocation
    5. Restricted tool invocation
    6. Sensitive database access
    """
    user_id = "U_VICTIM_ACCOUNT"
    session_id = "sess_synthetic_attack_chain"

    # Step 1: Normal Login
    r1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_VICTIM_PC_01",
        "session_id": session_id,
        "event_type": "login",
        "metadata": {"ip": "10.0.0.1"}
    })
    assert r1.status_code == 201
    d1 = r1.json()
    incident_id = d1["incident_id"]
    assert d1["risk_assessment"]["risk_level"] == "LOW"

    # Step 2: Unknown Device
    r2 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_external_kali",
        "session_id": session_id,
        "event_type": "device_change",
        "metadata": {"is_new_device": True}
    })
    assert r2.status_code == 201
    d2 = r2.json()
    assert d2["incident_id"] == incident_id
    assert "unknown_device" in d2["risk_assessment"]["correlated_signals"]

    # Step 3: Sensitive API Access
    r3 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_external_kali",
        "session_id": session_id,
        "event_type": "api_access",
        "resource": "/api/customer-data/pii/export",
        "metadata": {"records_requested": 5000}
    })
    assert r3.status_code == 201
    d3 = r3.json()
    assert d3["incident_id"] == incident_id
    assert "sensitive_resource" in d3["risk_assessment"]["correlated_signals"]

    # Step 4: AI-Agent Invocation
    r4 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_external_kali",
        "session_id": session_id,
        "event_type": "agent_invocation",
        "agent_id": "agent_copilot",
        "metadata": {"prompt": "Find all sensitive financial data"}
    })
    assert r4.status_code == 201
    d4 = r4.json()
    assert d4["incident_id"] == incident_id

    # Step 5: Restricted Tool Invocation
    r5 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_external_kali",
        "session_id": session_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "metadata": {"query": "SELECT * FROM credit_cards"}
    })
    assert r5.status_code == 201
    d5 = r5.json()
    assert d5["incident_id"] == incident_id
    assert any(sig in d5["risk_assessment"]["correlated_signals"] for sig in ["unexpected_tool_usage", "unusual_tool_usage"])

    # Step 6: Sensitive Database Access
    r6 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_external_kali",
        "session_id": session_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"action": "BULK_DUMP"}
    })
    assert r6.status_code == 201
    d6 = r6.json()
    assert d6["incident_id"] == incident_id

    # Final Incident & Risk Verification
    final_risk = d6["risk_assessment"]
    assert final_risk["risk_level"] in ["HIGH", "CRITICAL"]
    assert final_risk["risk_score"] >= 75
    assert final_risk["confidence"] >= 0.88

    # Signals correlated
    signals = final_risk["correlated_signals"]
    assert "unknown_device" in signals
    assert "sensitive_resource" in signals
    assert "abnormal_event_sequence" in signals

    # Plain-English Explanation
    assert len(final_risk["reasons"]) >= 4
    # Recommended Action
    assert len(final_risk["recommended_action"]) > 10

    # Alert generated and persisted
    assert d6["alert"] is not None
    assert d6["alert"]["risk_level"] in ["HIGH", "CRITICAL"]
    assert d6["alert"]["status"] in ["active", "escalated"]

    # Verify Incident Details via GET /api/incidents/{incident_id}
    inc_resp = client.get(f"/api/incidents/{incident_id}")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert len(inc_data["events"]) == 6
    assert inc_data["primary_entity"] == user_id
