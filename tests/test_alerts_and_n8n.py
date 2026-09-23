import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.risk import RiskAssessment, RiskLevel
from app.services.alert_service import AlertService


@pytest.fixture
def client():
    return TestClient(app)


# --- 1. Alert Service Tests ---

@pytest.mark.anyio
async def test_alert_generation_levels():
    alert_svc = AlertService()

    # Moderate Risk
    mod_assessment = RiskAssessment(
        risk_score=45,
        risk_level=RiskLevel.MODERATE,
        confidence=0.85,
        reasons=["Unknown device observed"],
        recommended_action="Increase monitoring",
    )
    assert alert_svc.should_generate_alert(mod_assessment) is True
    mod_alert = await alert_svc.create_alert(incident_id="INC-MOD-01", risk_assessment=mod_assessment)
    assert mod_alert.alert_id.startswith("ALT-")
    assert mod_alert.risk_level == "MODERATE"
    assert mod_alert.status == "active"
    assert "increased monitoring" in mod_alert.simulated_action_taken.lower()

    # Critical Risk
    crit_assessment = RiskAssessment(
        risk_score=90,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.96,
        reasons=["Unknown device", "Sensitive resource", "Restricted tool raw_sql_exec"],
        recommended_action="Require human approval / suspend or isolate the affected action",
    )
    crit_alert = await alert_svc.create_alert(incident_id="INC-CRIT-01", risk_assessment=crit_assessment)
    assert crit_alert.risk_level == "CRITICAL"
    assert crit_alert.status == "escalated"
    assert "human approval" in crit_alert.simulated_action_taken.lower()


# --- 2. Alerts API Endpoints Tests ---

def test_alerts_api_list_get_and_patch(client):
    # Ingest event that creates high risk via n8n endpoint
    client.post("/api/n8n/process-event", json={
        "user_id": "U_ALERT_TEST",
        "device_id": "unknown_device_99",
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "resource": "/api/customer-data",
        "metadata": {"is_new_device": True}
    })

    # 1. GET /api/alerts
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) >= 1
    target_alert = alerts[0]
    alert_id = target_alert["alert_id"]

    # 2. GET /api/alerts/{alert_id}
    single_resp = client.get(f"/api/alerts/{alert_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["alert_id"] == alert_id

    # 3. PATCH /api/alerts/{alert_id} - Acknowledge or Resolve
    patch_resp = client.patch(f"/api/alerts/{alert_id}", json={"status": "acknowledged"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "acknowledged"

    # Verify status changed
    verify_resp = client.get(f"/api/alerts/{alert_id}")
    assert verify_resp.json()["status"] == "acknowledged"


# --- 3. n8n Automation Endpoint Tests ---

def test_n8n_process_event_benign(client):
    payload = {
        "user_id": "U_BENIGN",
        "device_id": "D001",
        "event_type": "api_access",
        "resource": "/api/public/status",
        "metadata": {}
    }
    response = client.post("/api/n8n/process-event", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["should_escalate"] is False
    assert data["requires_human_approval"] is False
    assert data["alert_created"] is False
    assert data["risk_level"] == "LOW"


def test_n8n_process_event_critical_escalation(client):
    payload = {
        "user_id": "U_ATTACKER",
        "device_id": "unknown_device_kali",
        "session_id": "sess_n8n_attack",
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "resource": "/api/customer-data/pii/export",
        "metadata": {
            "is_new_device": True,
            "privilege_escalation": True,
            "records_requested": 10000
        }
    }
    response = client.post("/api/n8n/process-event", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "processed"
    assert data["should_escalate"] is True
    assert data["requires_human_approval"] is True
    assert data["alert_created"] is True
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["alert"] is not None
    assert data["alert"]["alert_id"].startswith("ALT-")
    assert "notification_summary" in data
    assert "🚨 PS-8 Security Incident" in data["notification_summary"]
