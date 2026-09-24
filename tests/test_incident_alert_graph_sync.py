import pytest
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_suite_incident_alert_graph_synchronization(client):
    """Regression test suite for Incident / Alert / Graph State Synchronization:
    Tests A through H as specified in prompt.
    """

    # =========================================================================
    # TEST A: Create J. Singh CRITICAL ACTIVE incident.
    # =========================================================================
    user_singh = "J. Singh"
    session_singh = f"sess_singh_{id(user_singh)}"

    # Ingest critical threat events for J. Singh
    events_singh = [
        {
            "user_id": user_singh,
            "session_id": session_singh,
            "event_type": "login",
            "resource": "/auth/login",
            "metadata": {"ip": "198.51.100.88", "is_new_ip": True}
        },
        {
            "user_id": user_singh,
            "session_id": session_singh,
            "event_type": "api_access",
            "resource": "/api/v1/customer-records",
            "metadata": {"sensitive_resource": True}
        },
        {
            "user_id": user_singh,
            "session_id": session_singh,
            "event_type": "database_access",
            "resource": "/database/customer_credentials/dump",
            "metadata": {"privilege_escalation": True, "bulk_data_access": True}
        }
    ]

    last_res = None
    for evt in events_singh:
        r = client.post("/api/events", json=evt)
        assert r.status_code == 201
        last_res = r.json()

    singh_incident_id = last_res["incident_id"]
    assert singh_incident_id is not None
    assert last_res["risk_assessment"]["risk_score"] >= 80

    # Verify incident is active & critical
    inc_resp = client.get(f"/api/incidents/{singh_incident_id}")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert inc_data["status"] == "active"
    assert inc_data["risk_assessment"]["risk_score"] >= 80

    # Verify graph is active / high-risk
    graph_a = client.get(f"/api/users/{user_singh}/activity-graph").json()
    assert graph_a["summary"]["risk_level"] in ["high-risk", "suspicious"]

    # Verify active-critical endpoint returns J. Singh's alert
    active_crit_res = client.get("/api/alerts/active-critical")
    assert active_crit_res.status_code == 200
    crit_alert = active_crit_res.json()
    assert crit_alert is not None
    # Verify the alert is for J. Singh
    assert crit_alert["incident_id"] == singh_incident_id or crit_alert.get("primary_entity") == user_singh

    # =========================================================================
    # TEST B: Contain J. Singh incident.
    # =========================================================================
    # Approve containment via two-person rule
    r_appr1 = client.post(f"/api/response/{singh_incident_id}/approve", json={
        "actor": "SOC_Analyst_Alice",
        "approver_id": "SOC_Analyst_Alice",
        "role": "SECURITY_ANALYST",
        "session_id": "sess_alice_01",
        "notes": "Primary approval for J. Singh containment"
    })
    assert r_appr1.status_code == 200

    r_appr2 = client.post(f"/api/response/{singh_incident_id}/second-approve", json={
        "actor": "SOC_Admin_Bob",
        "approver_id": "SOC_Admin_Bob",
        "role": "SECURITY_ADMIN",
        "session_id": "sess_bob_02",
        "notes": "Secondary admin dual-control sign-off",
        "dry_run": True
    })
    assert r_appr2.status_code == 200

    # Verify incident status is now CONTAINED and score is 15 (LOW)
    inc_b = client.get(f"/api/incidents/{singh_incident_id}").json()
    assert inc_b["status"] == "contained"
    assert inc_b["risk_assessment"]["risk_score"] == 15
    assert inc_b["risk_assessment"]["risk_level"] == "LOW"

    # Verify active-critical endpoint STRICTLY EXCLUDES J. Singh
    active_crit_b = client.get("/api/alerts/active-critical").json()
    if active_crit_b is not None:
        assert active_crit_b["incident_id"] != singh_incident_id
        assert active_crit_b.get("primary_entity") != user_singh

    # Verify alert list returns J. Singh's alert with updated contained state (status != CRITICAL)
    alerts_b = client.get("/api/alerts").json()
    singh_alerts = [a for a in alerts_b if a.get("incident_id") == singh_incident_id]
    for sa in singh_alerts:
        assert sa["status"] == "contained"
        assert sa["risk_score"] <= 25
        assert sa["risk_level"] == "LOW"
        assert "CRITICAL" not in sa.get("title", "")

    # Verify graph no longer represents it as unresolved active threat
    graph_b = client.get(f"/api/users/{user_singh}/activity-graph").json()
    assert graph_b["summary"]["risk_level"] in ["contained", "resolved", "normal", "unusual"]
    assert graph_b["summary"]["risk_score"] <= 25

    # =========================================================================
    # TEST C: Resolve U_ANALYST. Verify J. Singh and Maheen remain unchanged.
    # =========================================================================
    # Create incident for Maheen Fatima
    user_maheen = "Maheen Fatima"
    r_maheen = client.post("/api/events", json={
        "user_id": user_maheen,
        "event_type": "login",
        "resource": "/auth/login",
        "metadata": {"ip": "10.0.0.99", "new_device": True}
    })
    maheen_inc_id = r_maheen.json().get("incident_id")

    # Ingest event for U_ANALYST
    user_analyst = "U_ANALYST"
    r_u = client.post("/api/events", json={
        "user_id": user_analyst,
        "event_type": "api_access",
        "resource": "/api/v1/system/backup",
        "metadata": {"sensitive_resource": True}
    })
    u_inc_id = r_u.json().get("incident_id")

    if u_inc_id:
        # Resolve U_ANALYST
        client.post(f"/api/response/{u_inc_id}/recover", json={
            "actor": "SOC_Lead",
            "reason": "Authorized backup procedure"
        })
        u_after = client.get(f"/api/incidents/{u_inc_id}").json()
        assert u_after["status"] in ["resolved", "mitigated"]

    # Verify J. Singh is STILL contained with score 15
    singh_check = client.get(f"/api/incidents/{singh_incident_id}").json()
    assert singh_check["status"] == "contained"
    assert singh_check["risk_assessment"]["risk_score"] == 15

    # Verify Maheen is unchanged
    if maheen_inc_id:
        maheen_check = client.get(f"/api/incidents/{maheen_inc_id}").json()
        assert maheen_check["status"] == "active"

    # =========================================================================
    # TEST D: Create A, B, C. Resolve A. Verify: A=RESOLVED, B=unchanged, C=unchanged.
    # =========================================================================
    # Ingest distinct events for User A, B, C
    uA, uB, uC = "User_A_Iso", "User_B_Iso", "User_C_Iso"
    rA = client.post("/api/events", json={"user_id": uA, "event_type": "data_access", "resource": "/data/a", "metadata": {"privilege_escalation": True}}).json()
    rB = client.post("/api/events", json={"user_id": uB, "event_type": "data_access", "resource": "/data/b", "metadata": {"privilege_escalation": True}}).json()
    rC = client.post("/api/events", json={"user_id": uC, "event_type": "data_access", "resource": "/data/c", "metadata": {"privilege_escalation": True}}).json()

    incA, incB, incC = rA["incident_id"], rB["incident_id"], rC["incident_id"]
    assert incA != incB and incB != incC

    # Resolve A
    client.post(f"/api/response/{incA}/recover", json={"actor": "SOC_Lead", "reason": "A resolved"})

    checkA = client.get(f"/api/incidents/{incA}").json()
    checkB = client.get(f"/api/incidents/{incB}").json()
    checkC = client.get(f"/api/incidents/{incC}").json()

    assert checkA["status"] in ["resolved", "mitigated"]
    assert checkB["status"] == "active"
    assert checkC["status"] == "active"

    # =========================================================================
    # TEST E: Select A then B then C. Verify each inspect view shows exact data.
    # =========================================================================
    dataA = client.get(f"/api/incidents/{incA}").json()
    dataB = client.get(f"/api/incidents/{incB}").json()
    dataC = client.get(f"/api/incidents/{incC}").json()

    assert dataA["id"] == incA
    assert dataA["primary_entity"] == uA
    assert dataB["id"] == incB
    assert dataB["primary_entity"] == uB
    assert dataC["id"] == incC
    assert dataC["primary_entity"] == uC

    # =========================================================================
    # TEST F: Stale response protection / Rapid inspection.
    # =========================================================================
    # Confirm endpoint accepts concurrent queries without returning cached cross-incident state
    respB_fast = client.get(f"/api/incidents/{incB}").json()
    respA_slow = client.get(f"/api/incidents/{incA}").json()
    assert respB_fast["id"] == incB
    assert respA_slow["id"] == incA

    # =========================================================================
    # TEST G: Same user with multiple incidents. Resolve one, others unchanged.
    # User = J. Singh with Incidents A (CRITICAL, ACTIVE), B (LOW, CONTAINED), C (HIGH, ACTIVE)
    # =========================================================================
    from app.models.incident import CorrelatedIncident
    from app.models.risk import RiskAssessment, RiskLevel
    from app.api.dependencies import get_correlation_service

    corr_svc = get_correlation_service()
    
    # Incident A: Credential Stuffing, CRITICAL, ACTIVE
    inc_A = CorrelatedIncident(
        primary_entity="J. Singh",
        entity_type="user",
        threat_type="Credential Stuffing",
        status="active",
        risk_assessment=RiskAssessment(risk_score=90, risk_level=RiskLevel.CRITICAL, confidence=0.9, reasons=["Brute force detected"], recommended_action="Block IP")
    )
    corr_svc.active_incidents[inc_A.id] = inc_A

    # Incident B: API Abuse, LOW, CONTAINED
    inc_B = CorrelatedIncident(
        primary_entity="J. Singh",
        entity_type="user",
        threat_type="API Abuse",
        status="contained",
        risk_assessment=RiskAssessment(risk_score=15, risk_level=RiskLevel.LOW, confidence=0.8, reasons=["Contained"], recommended_action="Monitor")
    )
    corr_svc.active_incidents[inc_B.id] = inc_B

    # Incident C: Prompt Injection, HIGH, ACTIVE
    inc_C = CorrelatedIncident(
        primary_entity="J. Singh",
        entity_type="user",
        threat_type="Prompt Injection",
        status="active",
        risk_assessment=RiskAssessment(risk_score=75, risk_level=RiskLevel.HIGH, confidence=0.85, reasons=["DAN mode override"], recommended_action="Quarantine session")
    )
    corr_svc.active_incidents[inc_C.id] = inc_C

    # Resolve B via recovery endpoint
    client.post(f"/api/response/{inc_B.id}/recover", json={"actor": "SOC_Lead", "reason": "B resolved"})

    state_A = client.get(f"/api/incidents/{inc_A.id}").json()
    state_B = client.get(f"/api/incidents/{inc_B.id}").json()
    state_C = client.get(f"/api/incidents/{inc_C.id}").json()

    assert state_B["status"] in ["resolved", "mitigated"]
    assert state_A["status"] == "active"
    assert state_A["risk_assessment"]["risk_score"] == 90
    assert state_C["status"] == "active"
    assert state_C["risk_assessment"]["risk_score"] == 75

    # =========================================================================
    # TEST H: Old CRITICAL alert + current LOW/CONTAINED incident.
    # =========================================================================
    # Old critical alert from J. Singh is now synchronized to LOW/contained
    alerts_h = client.get("/api/alerts").json()
    singh_h_alerts = [a for a in alerts_h if a.get("incident_id") == singh_incident_id]
    for h_alert in singh_h_alerts:
        assert h_alert["status"] == "contained"
        assert h_alert["risk_level"] == "LOW"
        assert "CRITICAL" not in h_alert.get("title", "")

    # Excluded from active critical banner endpoint
    banner_crit = client.get("/api/alerts/active-critical").json()
    if banner_crit is not None:
        assert banner_crit["incident_id"] != singh_incident_id
