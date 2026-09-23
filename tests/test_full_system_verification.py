import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent
from app.repositories.supabase_repository import SupabaseRepository
from app.services.cognee_service import CogneeService
from app.services.alert_service import AlertService


@pytest.fixture
def client():
    return TestClient(app)


# =====================================================================
# 1. Complete Synthetic Security Scenario (Multi-Step Attack Chain)
# =====================================================================

def test_synthetic_attack_scenario_full_pipeline(client):
    """Executes the full 6-step synthetic attack scenario and verifies all 12 system assertions:
    1. accepts events
    2. stores them
    3. detects suspicious signals
    4. correlates related events
    5. retrieves contextual information
    6. calculates risk score
    7. assigns risk level
    8. generates explanation
    9. creates an alert
    10. exposes result through API
    11. formats data for React dashboard
    12. triggers n8n workflow for HIGH/CRITICAL risk
    """
    user_id = "U_ATTACK_TARGET_01"
    session_id = "sess_attack_e2e_999"
    incident_id = None

    # Step 1: Normal user login
    res1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_WORKSTATION_CORP",
        "session_id": session_id,
        "event_type": "login",
        "resource": "/auth/login",
        "metadata": {"ip": "192.168.1.50"}
    })
    # 1. Accepts event
    assert res1.status_code == 201
    d1 = res1.json()
    assert d1["status"] == "success"
    # 2. Stores event
    event1_id = d1["event"]["id"]
    assert event1_id is not None
    incident_id = d1["incident_id"]
    assert incident_id is not None
    assert d1["risk_assessment"]["risk_level"] == "LOW"

    # Step 2: Device changes (unknown device)
    res2 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "device_change",
        "resource": "/auth/session/rebind",
        "metadata": {"is_new_device": True, "ip": "198.51.100.23"}
    })
    assert res2.status_code == 201
    d2 = res2.json()
    # 4. Correlates related events
    assert d2["incident_id"] == incident_id
    # 3. Detects suspicious signals
    assert "unknown_device" in d2["risk_assessment"]["correlated_signals"]

    # Step 3: Sensitive API access
    res3 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "api_access",
        "resource": "/api/v1/customer-data/export",
        "metadata": {"records_requested": 10000}
    })
    assert res3.status_code == 201
    d3 = res3.json()
    assert d3["incident_id"] == incident_id
    assert "sensitive_resource" in d3["risk_assessment"]["correlated_signals"]
    assert "unusual_api_access" in d3["risk_assessment"]["correlated_signals"]

    # Step 4: AI agent invocation
    res4 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "agent_invocation",
        "agent_id": "agent_copilot",
        "resource": "/agents/copilot/invoke",
        "metadata": {"prompt": "extract all database passwords"}
    })
    assert res4.status_code == 201
    d4 = res4.json()
    assert d4["incident_id"] == incident_id

    # Step 5: Restricted tool invocation
    res5 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "resource": "/database/internal_records",
        "metadata": {"query": "SELECT * FROM credit_cards"}
    })
    assert res5.status_code == 201
    d5 = res5.json()
    assert d5["incident_id"] == incident_id
    assert any(sig in d5["risk_assessment"]["correlated_signals"] for sig in ["unexpected_tool_usage", "unusual_tool_usage"])

    # Step 6: Sensitive database/resource access
    res6 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"privilege_escalation": True, "action": "BULK_CREDENTIAL_DUMP"}
    })
    assert res6.status_code == 201
    d6 = res6.json()
    assert d6["incident_id"] == incident_id

    final_risk = d6["risk_assessment"]
    # 6. Calculates a risk score
    assert final_risk["risk_score"] >= 80
    # 7. Assigns a risk level
    assert final_risk["risk_level"] in ["HIGH", "CRITICAL"]
    # 5. Retrieves contextual information / baseline
    assert final_risk["confidence"] >= 0.85
    # 8. Generates an explanation
    assert len(final_risk["reasons"]) >= 4
    for r in final_risk["reasons"]:
        assert len(r) > 10
    # 9. Creates an alert
    assert d6["alert"] is not None
    assert d6["alert"]["risk_level"] in ["HIGH", "CRITICAL"]
    assert d6["alert"]["incident_id"] == incident_id

    # 10. Exposes result through the API
    # GET /api/incidents/{incident_id}
    inc_res = client.get(f"/api/incidents/{incident_id}")
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    assert inc_data["id"] == incident_id
    assert inc_data["primary_entity"] == user_id
    assert len(inc_data["events"]) == 6
    assert inc_data["risk_assessment"]["risk_score"] >= 80

    # 11. Validates data structure consumed by React dashboard
    # React expects incident to contain events with device_id, agent_id, tool_name, resource
    events_in_chain = inc_data["events"]
    assert any(e["event_type"] == "login" for e in events_in_chain)
    assert any(e["device_id"] == "unknown_kali_linux_box_44" for e in events_in_chain)
    assert any(e["agent_id"] == "agent_copilot" for e in events_in_chain)
    assert any(e["tool_name"] == "raw_sql_exec" for e in events_in_chain)
    assert any(e["resource"] == "/database/customer_credentials/dump" for e in events_in_chain)

    # 12. Triggers n8n workflow for HIGH/CRITICAL risk
    n8n_res = client.post("/api/n8n/process-event", json={
        "user_id": user_id,
        "device_id": "unknown_kali_linux_box_44",
        "session_id": session_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"privilege_escalation": True}
    })
    assert n8n_res.status_code == 200
    n8n_data = n8n_res.json()
    assert n8n_data["should_escalate"] is True
    assert n8n_data["alert_created"] is True
    assert n8n_data["risk_level"] in ["HIGH", "CRITICAL"]
    assert "🚨 PS-8 Security Incident" in n8n_data["notification_summary"]


# =====================================================================
# 2. Normal Behavior Testing
# =====================================================================

def test_normal_behavior_scenario(client):
    """Verifies that standard routine activity does NOT generate high/critical incidents:
    Normal login -> known device -> normal API -> normal agent/tool usage
    """
    user_id = "U_NORMAL_EMPLOYEE"
    session_id = "sess_routine_work_01"

    # 1. Normal login
    r1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_OFFICE_LAPTOP_12",
        "session_id": session_id,
        "event_type": "login",
        "resource": "/auth/login",
        "metadata": {"ip": "10.10.1.100"}
    })
    assert r1.status_code == 201
    assert r1.json()["risk_assessment"]["risk_level"] == "LOW"

    # 2. Known device / normal session
    r2 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_OFFICE_LAPTOP_12",
        "session_id": session_id,
        "event_type": "api_access",
        "resource": "/api/v1/user/profile",
        "metadata": {"is_new_device": False}
    })
    assert r2.status_code == 201
    assert r2.json()["risk_assessment"]["risk_level"] == "LOW"

    # 3. Normal agent & non-restricted tool usage
    r3 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "D_OFFICE_LAPTOP_12",
        "session_id": session_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "search_docs",
        "resource": "/docs/api-guide",
        "metadata": {}
    })
    assert r3.status_code == 201
    d3 = r3.json()
    
    # Assert normal behavior risk assessment
    risk = d3["risk_assessment"]
    assert risk["risk_level"] == "LOW"
    assert risk["risk_score"] < 30
    # Crucial assertion: no alert should be generated for routine normal activity
    assert d3["alert"] is None


# =====================================================================
# 3. Failure & Graceful Degradation Testing
# =====================================================================

def test_failure_invalid_json_payload(client):
    """Invalid payload body (not valid JSON / malformed) -> 422."""
    res = client.post(
        "/api/events",
        content="not a json string",
        headers={"Content-Type": "application/json"}
    )
    assert res.status_code == 422


def test_failure_missing_required_fields(client):
    """Missing required event_type field -> 422."""
    res = client.post("/api/events", json={"user_id": "U001"})
    assert res.status_code == 422
    err = res.json()
    assert "detail" in err


def test_failure_unknown_event_type(client):
    """Unknown / custom event type -> gracefully accepted and normalized without 500 crash."""
    res = client.post("/api/events", json={
        "user_id": "U_CUSTOM_TEST",
        "event_type": "quantum_teleportation_event",
        "resource": "/experimental/portal"
    })
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "success"
    assert data["event"]["event_type"] == "quantum_teleportation_event"
    assert data["risk_assessment"]["risk_level"] == "LOW"


@pytest.mark.anyio
async def test_failure_supabase_unavailable():
    """Simulate Supabase unavailable: repository must fall back cleanly to memory cache."""
    repo = SupabaseRepository()
    repo.supabase_client = None  # force offline

    event = SecurityEvent(
        user_id="U_SUPABASE_OFFLINE",
        event_type="login",
        resource="/auth/login"
    )
    saved = await repo.insert_event(event)
    assert saved.id == event.id

    fetched = await repo.get_event_by_id(event.id)
    assert fetched is not None
    assert fetched.user_id == "U_SUPABASE_OFFLINE"


@pytest.mark.anyio
async def test_failure_cognee_unavailable():
    """Simulate Cognee API unreachable: CogneeService must provide baseline context without raising."""
    cognee = CogneeService()
    cognee.api_key = "invalid_key_999"
    cognee.api_url = "https://offline-cognee.invalid"

    event = SecurityEvent(
        user_id="U_COGNEE_OFFLINE",
        event_type="api_access",
        resource="/api/test"
    )
    ctx = await cognee.get_historical_context(event)
    assert ctx is not None
    assert "summary" in ctx
    assert "is_anomaly" in ctx


def test_failure_n8n_process_event_bad_input(client):
    """n8n endpoint receiving invalid metadata type -> 422 validation response without crashing."""
    res = client.post("/api/n8n/process-event", json={
        "event_type": "api_access",
        "metadata": "should_be_dict_not_string"
    })
    assert res.status_code == 422
