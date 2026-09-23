from starlette.testclient import TestClient
from app.main import app


def test_complete_correlated_attack_scenario():
    client = TestClient(app)
    session_id = "attack_scenario_sess_01"
    user_id = "U_HACKATHON_DEMO"

    # Step 1: User Login with unusual device
    resp1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_kali_box",
        "session_id": session_id,
        "event_type": "login",
        "metadata": {"is_new_device": True}
    })
    assert resp1.status_code == 201
    evt1_id = resp1.json()["event"]["id"]

    analysis1 = client.post("/api/analyze", json={"event_id": evt1_id})
    assert analysis1.status_code == 200
    d1 = analysis1.json()
    incident_id_1 = d1["correlated_incident"]["id"]
    assert "unknown_device" in d1["detected_signals"]

    # Step 2: Sensitive API access
    resp2 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_device_kali_box",
        "session_id": session_id,
        "event_type": "api_access",
        "resource": "/api/customer-data/pii/export",
        "metadata": {}
    })
    assert resp2.status_code == 201
    evt2_id = resp2.json()["event"]["id"]

    analysis2 = client.post("/api/analyze", json={"event_id": evt2_id})
    assert analysis2.status_code == 200
    d2 = analysis2.json()
    # Must correlate to the same incident
    assert d2["correlated_incident"]["id"] == incident_id_1
    assert "sensitive_resource" in d2["detected_signals"]

    # Step 3: AI agent invocation with restricted tool
    resp3 = client.post("/api/events", json={
        "user_id": user_id,
        "session_id": session_id,
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "event_type": "tool_invocation",
        "resource": "/database/internal_records",
        "metadata": {}
    })
    assert resp3.status_code == 201
    evt3_id = resp3.json()["event"]["id"]

    analysis3 = client.post("/api/analyze", json={"event_id": evt3_id})
    assert analysis3.status_code == 200
    d3 = analysis3.json()
    assert d3["correlated_incident"]["id"] == incident_id_1
    
    # Verify escalated risk level and combined multi-step correlation
    assert d3["risk_level"] in ["HIGH", "CRITICAL"]
    assert d3["risk_score"] >= 60
    assert len(d3["reasons"]) >= 3
    assert d3["correlated_incident"]["event_count"] >= 3
    assert "abnormal_event_sequence" in d3["correlated_incident"]["signals_detected"]
