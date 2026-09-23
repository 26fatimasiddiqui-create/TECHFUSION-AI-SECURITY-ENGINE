import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent, EventType
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def client():
    return TestClient(app)


def test_event_ingest_auto_id(client):
    payload = {
        "user_id": "U001",
        "device_id": "D001",
        "event_type": "login",
        "metadata": {"ip": "192.168.1.1"}
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert "event" in data
    assert data["event"]["id"] is not None
    assert len(data["event"]["id"]) > 10
    assert data["event"]["event_type"] == "login"
    assert data["event"]["user_id"] == "U001"
    assert data["event"]["device_id"] == "D001"


def test_event_ingest_provided_id(client):
    custom_id = "EVT-CUSTOM-999"
    payload = {
        "id": custom_id,
        "user_id": "U001",
        "device_id": "D001",
        "event_type": "api_access",
        "resource": "/api/customer-data",
        "metadata": {}
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["event"]["id"] == custom_id


def test_event_normalization(client):
    payload = {
        "user_id": "  U_NORMALIZED  ",
        "device_id": "  D_NORMALIZED  ",
        "event_type": "  API_ACCESS  ",  # should be lowercased and stripped
        "resource": "  /api/v1/users  ",
        "agent_id": "   ",  # whitespace only should become None
        "metadata": {"key": "val"}
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["event"]["user_id"] == "U_NORMALIZED"
    assert data["event"]["device_id"] == "D_NORMALIZED"
    assert data["event"]["event_type"] == "api_access"
    assert data["event"]["resource"] == "/api/v1/users"
    assert data["event"]["agent_id"] is None


def test_supported_event_types(client):
    event_types = [
        "login",
        "logout",
        "failed_login",
        "api_access",
        "privilege_change",
        "agent_invocation",
        "tool_invocation",
        "database_access",
        "data_access",
        "device_change",
        "custom_sec_event",
    ]
    for et in event_types:
        resp = client.post("/api/events", json={
            "user_id": "U001",
            "event_type": et
        })
        assert resp.status_code == 201
        assert resp.json()["event"]["event_type"] == et.lower()


def test_event_ingest_missing_event_type(client):
    response = client.post("/api/events", json={
        "user_id": "U001"
    })
    assert response.status_code == 422


def test_event_ingest_blank_event_type(client):
    response = client.post("/api/events", json={
        "user_id": "U001",
        "event_type": "   "
    })
    assert response.status_code == 422


def test_event_retrieval_by_id(client):
    # Ingest event
    custom_id = "EVT-RETRIEVE-123"
    post_resp = client.post("/api/events", json={
        "id": custom_id,
        "user_id": "U002",
        "event_type": "database_access",
        "resource": "/db/financial_records"
    })
    assert post_resp.status_code == 201

    # Retrieve by ID
    get_resp = client.get(f"/api/events/{custom_id}")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["id"] == custom_id
    assert retrieved["user_id"] == "U002"
    assert retrieved["event_type"] == "database_access"
    assert retrieved["resource"] == "/db/financial_records"


def test_event_retrieval_not_found(client):
    resp = client.get("/api/events/non-existent-event-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_event_listing_and_filtering(client):
    # Ingest test events for a specific user
    user_target = "U_FILTER_TARGET"
    client.post("/api/events", json={"user_id": user_target, "event_type": "login"})
    client.post("/api/events", json={"user_id": user_target, "event_type": "api_access"})
    client.post("/api/events", json={"user_id": "U_OTHER", "event_type": "login"})

    # Filter by user_id
    resp = client.get(f"/api/events?user_id={user_target}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["count"] >= 2
    assert all(e["user_id"] == user_target for e in data["events"])

    # Filter by event_type
    resp_type = client.get(f"/api/events?event_type=api_access&user_id={user_target}")
    assert resp_type.status_code == 200
    data_type = resp_type.json()
    assert all(e["event_type"] == "api_access" for e in data_type["events"])
