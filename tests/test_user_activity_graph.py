from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.graph import ActivityRiskLevel, NodeType, RelationshipType


@pytest.fixture
def client():
    return TestClient(app)


def test_activity_graph_empty_user(client):
    """Querying a user with no activity returns a valid empty graph structure with 200 OK."""
    resp = client.get("/api/users/U_NON_EXISTENT_USER_9999/activity-graph")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert data["user_id"] == "U_NON_EXISTENT_USER_9999"
    assert data["summary"]["total_events"] == 0
    assert data["summary"]["node_count"] == 0
    assert data["summary"]["edge_count"] == 0
    assert data["summary"]["risk_score"] == 0
    assert data["summary"]["risk_level"] == "normal"
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["timeline"] == []
    assert data["incidents"] == []


def test_activity_graph_new_device_not_isolated_threat(client):
    """Requirement 4: A new IP or new device by itself must NOT automatically be classified
    as a threat. It should be treated as a risk signal (unusual) and evaluated with other behavior.
    """
    user_id = f"U_TEST_NEW_DEVICE_{int(datetime.now().timestamp())}"
    
    # Ingest single event with unknown device
    ingest_resp = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_phone_box",
        "session_id": f"sess_isolated_{user_id}",
        "event_type": "login",
        "metadata": {"is_new_device": True, "ip": "198.51.100.1"}
    })
    assert ingest_resp.status_code == 201

    graph_resp = client.get(f"/api/users/{user_id}/activity-graph")
    assert graph_resp.status_code == 200
    graph = graph_resp.json()

    # The risk level for this isolated event should be 'unusual', NOT 'critical' or 'high-risk'
    assert graph["summary"]["risk_level"] in ["unusual", "normal"]
    assert graph["summary"]["risk_score"] < 60

    # Device node should reflect 'unusual' risk signal, not high-risk threat
    dev_node = next((n for n in graph["nodes"] if n["type"] == "Device"), None)
    assert dev_node is not None
    assert dev_node["risk_level"] == "unusual"

    # Edge from user to device should show 'unusual'
    dev_edge = next((e for e in graph["edges"] if e["relationship"] == "USER_USED_DEVICE"), None)
    assert dev_edge is not None
    assert dev_edge["risk_level"] == "unusual"
    assert any("device" in r.lower() for r in dev_edge["reasons"])


def test_activity_graph_node_types_and_relationships(client):
    """Requirement 1 & 2: Supports all required node types and relationship types:
    Nodes: User, Login, Session, Device, IP, API, AI Agent, Tool, Resource, Database.
    Edges: USER_PERFORMED_LOGIN, USER_USED_DEVICE, DEVICE_CONNECTED_FROM_IP,
           USER_CREATED_SESSION, USER_CALLED_API, USER_INVOKED_AGENT,
           AGENT_USED_TOOL, API_ACCESSED_RESOURCE, TOOL_ACCESSED_RESOURCE.
    """
    user_id = f"U_FULL_NODES_TEST_{int(datetime.now().timestamp())}"
    sess_id = f"sess_full_{user_id}"
    shared_device = "workstation_alpha_01"

    # Step 1: Login with device, session, and IP
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": sess_id,
        "event_type": "login",
        "metadata": {"ip": "10.10.10.42"}
    })

    # Step 2: API Access with Resource
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": sess_id,
        "event_type": "api_access",
        "resource": "/api/customer-data/export",
        "metadata": {"records_requested": 1500}
    })

    # Step 3: Agent Invocation
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": sess_id,
        "event_type": "agent_invocation",
        "agent_id": "agent_copilot",
        "metadata": {}
    })

    # Step 4: Tool Invocation
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": sess_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "metadata": {}
    })

    # Step 5: Database Access
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": sess_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"privilege_escalation": True}
    })

    graph_resp = client.get(f"/api/users/{user_id}/activity-graph")
    assert graph_resp.status_code == 200
    graph = graph_resp.json()

    # Verify All 10 Node Types
    node_types_present = {n["type"] for n in graph["nodes"]}
    expected_node_types = {
        NodeType.USER.value,
        NodeType.LOGIN.value,
        NodeType.SESSION.value,
        NodeType.DEVICE.value,
        NodeType.IP.value,
        NodeType.API.value,
        NodeType.AI_AGENT.value,
        NodeType.TOOL.value,
        NodeType.RESOURCE.value,
        NodeType.DATABASE.value,
    }
    for expected_type in expected_node_types:
        assert expected_type in node_types_present, f"Missing expected node type: {expected_type}"

    # Verify All 9 Relationship Types
    relationships_present = {e["relationship"] for e in graph["edges"]}
    expected_relationships = {
        RelationshipType.USER_PERFORMED_LOGIN.value,
        RelationshipType.USER_USED_DEVICE.value,
        RelationshipType.DEVICE_CONNECTED_FROM_IP.value,
        RelationshipType.USER_CREATED_SESSION.value,
        RelationshipType.USER_CALLED_API.value,
        RelationshipType.USER_INVOKED_AGENT.value,
        RelationshipType.AGENT_USED_TOOL.value,
        RelationshipType.API_ACCESSED_RESOURCE.value,
        RelationshipType.TOOL_ACCESSED_RESOURCE.value,
    }
    for expected_rel in expected_relationships:
        assert expected_rel in relationships_present, f"Missing expected relationship: {expected_rel}"


def test_activity_graph_chronological_ordering(client):
    """Requirement 3: The graph must preserve event chronology (what happened first -> next -> after)."""
    user_id = f"U_CHRONO_{int(datetime.now().timestamp())}"
    sess_id = f"sess_chrono_{user_id}"

    steps = [
        ("login", None, None, None),
        ("device_change", "unknown_device_beta", None, None),
        ("api_access", "unknown_device_beta", None, "/api/customer-data/export"),
        ("agent_invocation", "unknown_device_beta", "agent_copilot", None),
        ("tool_invocation", "unknown_device_beta", "agent_copilot", "/database/sql_table"),
    ]

    for event_type, dev, agent, res in steps:
        payload = {
            "user_id": user_id,
            "session_id": sess_id,
            "event_type": event_type,
        }
        if dev:
            payload["device_id"] = dev
        if agent:
            payload["agent_id"] = agent
            if event_type == "tool_invocation":
                payload["tool_name"] = "raw_sql_exec"
        if res:
            payload["resource"] = res
        
        r = client.post("/api/events", json=payload)
        assert r.status_code == 201

    graph = client.get(f"/api/users/{user_id}/activity-graph").json()
    timeline = graph["timeline"]

    assert len(timeline) >= 5
    # Steps must be strictly sequentially numbered: 1, 2, 3, ...
    for idx, item in enumerate(timeline, start=1):
        assert item["step"] == idx
        # Ensure timestamp is non-decreasing
        if idx > 1:
            prev_time = datetime.fromisoformat(timeline[idx - 2]["timestamp"])
            curr_time = datetime.fromisoformat(item["timestamp"])
            assert curr_time >= prev_time


def test_activity_graph_user_filtering_and_performance(client):
    """Requirement 9: Ensure filtering is strictly scoped to the requested user without cross-leakage."""
    user_a = f"USER_ALICE_{int(datetime.now().timestamp())}"
    user_b = f"USER_BOB_{int(datetime.now().timestamp())}"

    client.post("/api/events", json={"user_id": user_a, "event_type": "login", "device_id": "alice_laptop"})
    client.post("/api/events", json={"user_id": user_b, "event_type": "login", "device_id": "bob_desktop"})

    graph_a = client.get(f"/api/users/{user_a}/activity-graph").json()
    graph_b = client.get(f"/api/users/{user_b}/activity-graph").json()

    # User A's graph must only reference Alice and her devices
    assert graph_a["user_id"] == user_a
    assert any("alice_laptop" in n["id"] for n in graph_a["nodes"])
    assert not any("bob_desktop" in n["id"] for n in graph_a["nodes"])

    # User B's graph must only reference Bob and his devices
    assert graph_b["user_id"] == user_b
    assert any("bob_desktop" in n["id"] for n in graph_b["nodes"])
    assert not any("alice_laptop" in n["id"] for n in graph_b["nodes"])


def test_activity_graph_risk_reason_transparency(client):
    """Requirement 6: Transparent risk reasons from existing detection & baseline models."""
    user_id = f"U_RISK_REASONS_{int(datetime.now().timestamp())}"
    sess_id = f"sess_reasons_{user_id}"

    # Step 1: New device
    client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_rogue_device",
        "session_id": sess_id,
        "event_type": "device_change",
        "metadata": {"is_new_device": True}
    })

    # Step 2: Restricted tool execution
    client.post("/api/events", json={
        "user_id": user_id,
        "session_id": sess_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "metadata": {}
    })

    graph = client.get(f"/api/users/{user_id}/activity-graph").json()
    
    # Check that tool node has transparent reason
    tool_node = next((n for n in graph["nodes"] if n["type"] == "Tool"), None)
    assert tool_node is not None
    assert tool_node["risk_level"] == "high-risk"
    assert any("restricted" in r.lower() or "baseline" in r.lower() for r in tool_node["reasons"])

    # Check timeline step has reasons
    tool_step = next((t for t in graph["timeline"] if t["event_type"] == "tool_invocation"), None)
    assert tool_step is not None
    assert len(tool_step["reasons"]) > 0


def test_activity_graph_incident_linkage(client):
    """Requirement 7: Incident linkage connects graph events to correlated incidents and risk scores."""
    user_id = f"U_INCIDENT_LINK_{int(datetime.now().timestamp())}"
    sess_id = f"sess_inc_{user_id}"

    # Ingest multi-event sequence that correlates into an incident
    r1 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_attacker_box",
        "session_id": sess_id,
        "event_type": "login",
        "metadata": {"is_new_device": True}
    })
    incident_id = r1.json()["incident_id"]

    r2 = client.post("/api/events", json={
        "user_id": user_id,
        "device_id": "unknown_attacker_box",
        "session_id": sess_id,
        "event_type": "api_access",
        "resource": "/api/customer-data/pii/export",
        "metadata": {"records_requested": 5000}
    })

    graph = client.get(f"/api/users/{user_id}/activity-graph").json()

    # The incident must be present in incidents list
    assert len(graph["incidents"]) >= 1
    linked_inc = next((i for i in graph["incidents"] if i["id"] == incident_id), None)
    assert linked_inc is not None
    assert linked_inc["risk_score"] > 0

    # Edges should carry the incident_id
    assert any(e.get("incident_id") == incident_id for e in graph["edges"])
    # Timeline steps should carry the incident_id
    assert any(t.get("incident_id") == incident_id for t in graph["timeline"])


def test_list_users_api_endpoint(client):
    """Validates GET /api/users endpoint returns user summaries."""
    user_id = f"U_TRACKED_{int(datetime.now().timestamp())}"
    client.post("/api/events", json={"user_id": user_id, "event_type": "login"})

    resp = client.get("/api/users")
    assert resp.status_code == 200
    users = resp.json()
    assert isinstance(users, list)
    assert any(u["user_id"] == user_id for u in users)
    user_obj = next(u for u in users if u["user_id"] == user_id)
    assert user_obj["event_count"] >= 1
    assert "highest_risk_level" in user_obj
