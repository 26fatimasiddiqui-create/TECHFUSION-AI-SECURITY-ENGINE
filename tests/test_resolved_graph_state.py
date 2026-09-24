import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment, RiskLevel
from app.models.graph import ActivityRiskLevel


@pytest.fixture
def client():
    return TestClient(app)


def test_active_incident_produces_high_risk_and_resolve_updates_graph(client):
    """Verifies that an active incident results in high-risk graph state,
    and resolving the incident transitions the graph state to resolved without deleting events.
    """
    user_id = "test_user_graph_01"
    session_id = "sess_graph_01"

    # Ingest attack steps
    steps = [
        {"user_id": user_id, "session_id": session_id, "event_type": "login", "resource": "/auth/login"},
        {"user_id": user_id, "session_id": session_id, "event_type": "api_access", "resource": "/api/v1/payroll/export", "metadata": {"unusual_api": True}},
        {"user_id": user_id, "session_id": session_id, "event_type": "database_access", "resource": "/database/customer_credentials/dump", "metadata": {"privilege_escalation": True, "bulk_data_access": True}},
    ]
    last_resp = None
    for s in steps:
        r = client.post("/api/events", json=s)
        assert r.status_code == 201
        last_resp = r.json()

    incident_id = last_resp["incident_id"]
    alert = last_resp["alert"]
    assert alert is not None
    assert last_resp["risk_assessment"]["risk_score"] >= 80

    # 1. Fetch graph before resolution: must be high-risk
    g_before = client.get(f"/api/users/{user_id}/activity-graph").json()
    assert g_before["summary"]["risk_level"] == "high-risk"
    assert any(n["risk_level"] == "high-risk" for n in g_before["nodes"])

    # 2. Resolve incident via recovery endpoint
    rec_resp = client.post(f"/api/response/{incident_id}/recover", json={
        "actor": "SOC_Lead",
        "reason": "Verified legitimate test access",
    })
    assert rec_resp.status_code == 200
    rec_data = rec_resp.json()
    assert rec_data["status"] == "RESOLVED"
    assert rec_data["resolved"] is True

    # 3. Fetch graph after resolution: must transition to RESOLVED
    g_after = client.get(f"/api/users/{user_id}/activity-graph").json()
    assert g_after["summary"]["risk_score"] == 0
    assert g_after["summary"]["risk_level"] == "resolved"
    # Historical events must be preserved
    assert len(g_after["nodes"]) >= 3
    assert len(g_after["edges"]) >= 2
    # Nodes belonging to the resolved incident should have resolved status
    resolved_nodes = [n for n in g_after["nodes"] if n["risk_level"] == "resolved"]
    assert len(resolved_nodes) > 0


def test_multi_incident_isolation_in_graph(client):
    """Suppose User A has Incident A (resolved) and User B has Incident B (active).
    Resolving Incident A must NOT turn Incident B green.
    """
    user_a = "user_alpha_multi"
    user_b = "user_beta_multi"

    # User A attack
    r_a = client.post("/api/events", json={
        "user_id": user_a,
        "session_id": "sess_a_1",
        "event_type": "database_access",
        "resource": "/database/dump",
        "metadata": {"privilege_escalation": True}
    })
    inc_a = r_a.json()["incident_id"]

    # User B attack
    r_b = client.post("/api/events", json={
        "user_id": user_b,
        "session_id": "sess_b_1",
        "event_type": "database_access",
        "resource": "/database/dump",
        "metadata": {"privilege_escalation": True}
    })
    inc_b = r_b.json()["incident_id"]
    assert inc_a != inc_b

    # Resolve only Incident A
    client.post(f"/api/response/{inc_a}/recover", json={"actor": "Lead", "reason": "Authorized drill"})

    # User A graph is resolved
    g_a = client.get(f"/api/users/{user_a}/activity-graph").json()
    assert g_a["summary"]["risk_level"] == "resolved"

    # User B graph is STILL high-risk
    g_b = client.get(f"/api/users/{user_b}/activity-graph").json()
    assert g_b["summary"]["risk_level"] == "high-risk"


def test_single_alert_resolution_preserves_queue(client):
    """Resolving one alert must NOT auto-resolve other queued alerts."""
    # Ingest attack steps for user 1 to generate alert 1
    steps_1 = [
        {"user_id": "queue_user_1", "session_id": "sess_q_1", "event_type": "login", "resource": "/auth/login"},
        {"user_id": "queue_user_1", "session_id": "sess_q_1", "event_type": "api_access", "resource": "/api/v1/payroll/export", "metadata": {"unusual_api": True}},
        {"user_id": "queue_user_1", "session_id": "sess_q_1", "event_type": "database_access", "resource": "/database/customer_credentials/dump", "metadata": {"privilege_escalation": True, "bulk_data_access": True}},
    ]
    r1 = None
    for s in steps_1:
        r1 = client.post("/api/events", json=s)
    alert_1 = r1.json()["alert"]
    assert alert_1 is not None
    alert_1_id = alert_1["alert_id"]

    # Ingest attack steps for user 2 to generate alert 2
    steps_2 = [
        {"user_id": "queue_user_2", "session_id": "sess_q_2", "event_type": "login", "resource": "/auth/login"},
        {"user_id": "queue_user_2", "session_id": "sess_q_2", "event_type": "api_access", "resource": "/api/v1/payroll/export", "metadata": {"unusual_api": True}},
        {"user_id": "queue_user_2", "session_id": "sess_q_2", "event_type": "database_access", "resource": "/database/customer_credentials/dump", "metadata": {"privilege_escalation": True, "bulk_data_access": True}},
    ]
    r2 = None
    for s in steps_2:
        r2 = client.post("/api/events", json=s)
    alert_2 = r2.json()["alert"]
    assert alert_2 is not None
    alert_2_id = alert_2["alert_id"]
    assert alert_1_id != alert_2_id

    # Resolve only Alert 1 via dedicated endpoint
    res_resp = client.post(f"/api/alerts/{alert_1_id}/resolve", json={
        "actor": "SOC_Analyst",
        "reason": "Single alert 1 resolved by operator"
    })
    assert res_resp.status_code == 200
    alert_1_data = res_resp.json()
    assert alert_1_data["status"] == "resolved"
    assert alert_1_data["risk_score"] == 0

    # Verify Alert 2 remains ACTIVE and unacknowledged
    alert_2_check = client.get(f"/api/alerts/{alert_2_id}").json()
    assert alert_2_check["status"] != "resolved"
    assert alert_2_check["risk_score"] > 25

