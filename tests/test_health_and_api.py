def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "integrations" in data
    assert "supabase" in data["integrations"]


def test_event_ingestion_valid(client):
    payload = {
        "user_id": "U001",
        "device_id": "D001",
        "session_id": "sess_test_1",
        "event_type": "api_access",
        "resource": "/api/public/profile",
        "metadata": {"ip": "127.0.0.1"}
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["event"]["user_id"] == "U001"


def test_event_ingestion_invalid(client):
    # Missing required field `event_type`
    payload = {
        "user_id": "U001"
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 422


def test_analyze_endpoint(client):
    payload = {
        "user_id": "U001",
        "device_id": "unknown_device_99",
        "event_type": "api_access",
        "resource": "/api/customer-data/export",
        "metadata": {"is_new_device": True}
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["detection"]["is_suspicious"] is True
    assert "unknown_device" in data["detection"]["signals"]
    assert "sensitive_resource" in data["detection"]["signals"]
    assert data["risk_score"] > 30
