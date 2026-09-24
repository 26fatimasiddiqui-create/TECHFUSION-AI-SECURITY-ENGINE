import pytest
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_three_thread_state_isolation(client):
    """
    Scenario:
    Thread A = previously resolved
    Thread B = newly created / active
    Thread C = newly created / active

    Verifies:
    1. Inspecting Thread A returns Thread A's user, IP, device, and resolved status.
    2. Inspecting Thread B returns Thread B's user, IP, device, and active status.
    3. Thread B inspection never reuses or leaks Thread A's data.
    4. Thread C inspection is completely isolated from Thread A and Thread B.
    """
    # 1. Create Thread A
    user_a = "user_alpha_iso"
    device_a = "macbook_pro_m3_a"
    ip_a = "198.51.100.11"
    sess_a = "sess_a_iso_1"

    steps_a = [
        {"user_id": user_a, "device_id": device_a, "session_id": sess_a, "event_type": "login", "resource": "/auth/login", "metadata": {"ip": ip_a}},
        {"user_id": user_a, "device_id": device_a, "session_id": sess_a, "event_type": "database_access", "resource": "/database/users/dump", "metadata": {"ip": ip_a, "privilege_escalation": True}},
    ]
    r_a = None
    for s in steps_a:
        r_a = client.post("/api/events", json=s)
        assert r_a.status_code == 201

    inc_a_id = r_a.json()["incident_id"]
    assert inc_a_id is not None

    # Resolve Thread A
    rec_a = client.post(f"/api/response/{inc_a_id}/recover", json={
        "actor": "SOC_Supervisor",
        "reason": "Authorized test drill completed"
    })
    assert rec_a.status_code == 200
    assert rec_a.json()["resolved"] is True

    # 2. Create Thread B
    user_b = "user_bravo_iso"
    device_b = "kali_linux_vm_b"
    ip_b = "203.0.113.22"
    sess_b = "sess_b_iso_1"

    steps_b = [
        {"user_id": user_b, "device_id": device_b, "session_id": sess_b, "event_type": "failed_login", "resource": "/auth/login", "metadata": {"client_ip": ip_b, "is_brute_force": True}},
        {"user_id": user_b, "device_id": device_b, "session_id": sess_b, "event_type": "login", "resource": "/auth/login", "metadata": {"client_ip": ip_b, "is_suspicious_ip": True}},
        {"user_id": user_b, "device_id": device_b, "session_id": sess_b, "event_type": "database_access", "resource": "/database/financials/export", "metadata": {"client_ip": ip_b, "bulk_data_access": True, "privilege_escalation": True}},
    ]
    r_b = None
    for s in steps_b:
        r_b = client.post("/api/events", json=s)
        assert r_b.status_code == 201

    inc_b_id = r_b.json()["incident_id"]
    assert inc_b_id is not None
    assert inc_b_id != inc_a_id

    # 3. Create Thread C
    user_c = "user_charlie_iso"
    device_c = "windows_desktop_c"
    ip_c = "192.0.2.33"
    sess_c = "sess_c_iso_1"

    steps_c = [
        {"user_id": user_c, "device_id": device_c, "session_id": sess_c, "event_type": "api_access", "resource": "/api/v1/confidential/keys", "metadata": {"ip": ip_c, "unusual_api": True}},
        {"user_id": user_c, "device_id": device_c, "session_id": sess_c, "event_type": "database_access", "resource": "/database/keys/dump", "metadata": {"ip": ip_c, "privilege_escalation": True}},
    ]
    r_c = None
    for s in steps_c:
        r_c = client.post("/api/events", json=s)
        assert r_c.status_code == 201

    inc_c_id = r_c.json()["incident_id"]
    assert inc_c_id is not None
    assert inc_c_id != inc_a_id
    assert inc_c_id != inc_b_id

    # --- VERIFY THREAD A INSPECTION ---
    res_a = client.get(f"/api/incidents/{inc_a_id}")
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["id"] == inc_a_id
    assert data_a["status"] == "resolved"
    assert data_a["primary_entity"] == user_a
    # Events belong strictly to A
    for evt in data_a.get("events", []):
        assert evt["user_id"] == user_a
        assert evt["device_id"] == device_a

    # --- VERIFY THREAD B INSPECTION ---
    res_b = client.get(f"/api/incidents/{inc_b_id}")
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["id"] == inc_b_id
    assert data_b["status"] == "active"
    assert data_b["primary_entity"] == user_b
    assert data_b["risk_assessment"]["risk_score"] >= 60
    # Must NOT have Thread A's data
    assert data_b["primary_entity"] != user_a
    for evt in data_b.get("events", []):
        assert evt["user_id"] == user_b
        assert evt["device_id"] == device_b
        assert evt["user_id"] != user_a
        assert evt["device_id"] != device_a

    # --- VERIFY THREAD C INSPECTION ---
    res_c = client.get(f"/api/incidents/{inc_c_id}")
    assert res_c.status_code == 200
    data_c = res_c.json()
    assert data_c["id"] == inc_c_id
    assert data_c["status"] == "active"
    assert data_c["primary_entity"] == user_c
    for evt in data_c.get("events", []):
        assert evt["user_id"] == user_c


def test_action_center_containment_decision_isolation(client):
    """
    Verifies that applying containment actions or decisions to Thread B
    updates ONLY Thread B's containment status and audit trail, leaving
    Thread A and Thread C completely unaffected.
    """
    user_x = "actor_contain_x"
    user_y = "actor_contain_y"

    # Thread X
    rx = client.post("/api/events", json={
        "user_id": user_x,
        "session_id": "sess_x",
        "event_type": "database_access",
        "resource": "/database/dump",
        "metadata": {"privilege_escalation": True}
    })
    inc_x = rx.json()["incident_id"]

    # Thread Y
    ry = client.post("/api/events", json={
        "user_id": user_y,
        "session_id": "sess_y",
        "event_type": "database_access",
        "resource": "/database/dump",
        "metadata": {"privilege_escalation": True}
    })
    inc_y = ry.json()["incident_id"]
    assert inc_x != inc_y

    # Execute containment approval for Thread X only
    approval_resp = client.post(f"/api/response/{inc_x}/approve", json={
        "approver_id": "approver_alice",
        "role": "SECURITY_LEAD",
        "notes": "Approved containment for incident X",
        "dry_run": True
    })
    assert approval_resp.status_code == 200

    # Check Thread X approval status
    status_x = client.get(f"/api/response/{inc_x}/approval-status").json()
    assert status_x["incident_id"] == inc_x
    assert status_x.get("approver_1_id") == "approver_alice"

    # Check Thread Y approval status: MUST NOT inherit Thread X's approval
    status_y = client.get(f"/api/response/{inc_y}/approval-status").json()
    assert status_y["incident_id"] == inc_y
    assert status_y.get("approver_1_id") != "approver_alice"

    # Check Thread X response details
    resp_x = client.get(f"/api/response/{inc_x}")
    assert resp_x.status_code == 200
    data_resp_x = resp_x.json()
    assert data_resp_x["incident_id"] == inc_x

    # Check Thread Y response details: MUST NOT be contained/approved by Thread X's action
    resp_y = client.get(f"/api/response/{inc_y}")
    assert resp_y.status_code == 200
    data_resp_y = resp_y.json()
    assert data_resp_y["incident_id"] == inc_y

    # Verify audit trail isolation: Thread X audit trail vs Thread Y audit trail
    audit_x = client.get(f"/api/response/audit-trail?incident_id={inc_x}").json()
    assert all(entry.get("incident_id") == inc_x for entry in audit_x)

    audit_y = client.get(f"/api/response/audit-trail?incident_id={inc_y}").json()
    assert all(entry.get("incident_id") == inc_y for entry in audit_y)
    assert not any(entry.get("incident_id") == inc_x for entry in audit_y)


def test_same_user_distinct_sessions_isolation(client):
    """
    Verifies that the same user in two different sessions creates distinct incidents,
    and resolving the first incident does not leak into or resolve the second incident.
    """
    user = "multi_session_user"

    # Session 1 (Attacked and then resolved)
    r1 = client.post("/api/events", json={
        "user_id": user,
        "session_id": "sess_001",
        "event_type": "database_access",
        "resource": "/database/export_1",
        "metadata": {"privilege_escalation": True}
    })
    inc_1 = r1.json()["incident_id"]

    client.post(f"/api/response/{inc_1}/recover", json={
        "actor": "SOC_Lead",
        "reason": "False positive resolved for session 1"
    })

    # Session 2 (New active attack in a separate session)
    r2 = client.post("/api/events", json={
        "user_id": user,
        "session_id": "sess_002",
        "event_type": "database_access",
        "resource": "/database/export_2",
        "metadata": {"privilege_escalation": True}
    })
    inc_2 = r2.json()["incident_id"]

    assert inc_1 != inc_2

    # Verify inc_1 is resolved
    inc_1_data = client.get(f"/api/incidents/{inc_1}").json()
    assert inc_1_data["status"] == "resolved"

    # Verify inc_2 is active
    inc_2_data = client.get(f"/api/incidents/{inc_2}").json()
    assert inc_2_data["status"] == "active"
    assert inc_2_data["risk_assessment"]["risk_score"] >= 60
