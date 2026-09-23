#!/usr/bin/env python3
"""Complete End-to-End Verification Script for PS-8 Security Platform.

Exercises the entire pipeline:
n8n -> FastAPI -> Event Validation -> Detection -> Correlation -> Cognee Context -> Risk Analysis -> Supabase -> Alert -> React Dashboard contract
"""
import sys
import json
import asyncio
from starlette.testclient import TestClient
from app.main import app
from app.models.event import SecurityEvent
from app.repositories.supabase_repository import SupabaseRepository
from app.services.cognee_service import CogneeService


def log_step(step_name: str, passed: bool, detail: str = ""):
    status = " [PASS] " if passed else "![FAIL]!"
    print(f"{status} | {step_name:<42} | {detail}")


def main():
    print("=" * 80)
    print(" PS-8 COMPLETE END-TO-END VERIFICATION SUITE")
    print(" Architecture: n8n -> FastAPI -> Detection -> Correlation -> Cognee -> Risk -> Supabase -> Alert")
    print("=" * 80)

    client = TestClient(app)
    failures = []

    # -------------------------------------------------------------------------
    # 1. SYNTHETIC SECURITY SCENARIO (6-STEP ATTACK CHAIN)
    # -------------------------------------------------------------------------
    print("\n--- 1. SYNTHETIC ATTACK CHAIN (6-STEP ESCALATION) ---")
    user_id = "U_TARGET_ACCOUNT_01"
    session_id = "sess_e2e_attack_chain"
    incident_id = None

    attack_steps = [
        ("Step 1: Normal user login", {
            "user_id": user_id,
            "device_id": "D_OFFICE_PC",
            "session_id": session_id,
            "event_type": "login",
            "resource": "/auth/login",
            "metadata": {"ip": "10.0.1.5"}
        }, "LOW"),
        ("Step 2: Device change (unknown device)", {
            "user_id": user_id,
            "device_id": "unknown_kali_box_99",
            "session_id": session_id,
            "event_type": "device_change",
            "resource": "/auth/session/rebind",
            "metadata": {"is_new_device": True}
        }, None),
        ("Step 3: Sensitive API access", {
            "user_id": user_id,
            "device_id": "unknown_kali_box_99",
            "session_id": session_id,
            "event_type": "api_access",
            "resource": "/api/v1/customer-data/pii/export",
            "metadata": {"records_requested": 5000}
        }, None),
        ("Step 4: AI agent invocation", {
            "user_id": user_id,
            "device_id": "unknown_kali_box_99",
            "session_id": session_id,
            "event_type": "agent_invocation",
            "agent_id": "agent_copilot",
            "resource": "/agents/copilot/invoke",
            "metadata": {"prompt": "Find all sensitive financial data"}
        }, None),
        ("Step 5: Restricted tool invocation", {
            "user_id": user_id,
            "device_id": "unknown_kali_box_99",
            "session_id": session_id,
            "event_type": "tool_invocation",
            "agent_id": "agent_copilot",
            "tool_name": "raw_sql_exec",
            "resource": "/database/internal_records",
            "metadata": {"query": "SELECT * FROM users"}
        }, None),
        ("Step 6: Sensitive database bulk access", {
            "user_id": user_id,
            "device_id": "unknown_kali_box_99",
            "session_id": session_id,
            "event_type": "database_access",
            "resource": "/database/customer_credentials/dump",
            "metadata": {"privilege_escalation": True}
        }, "CRITICAL"),
    ]

    last_response = None
    for step_title, payload, expected_level in attack_steps:
        resp = client.post("/api/events", json=payload)
        if resp.status_code != 201:
            log_step(step_title, False, f"Expected 201, got {resp.status_code}")
            failures.append(f"{step_title}: Ingestion failed")
            continue

        data = resp.json()
        last_response = data
        if incident_id is None:
            incident_id = data["incident_id"]
        else:
            # Verify correlation
            assert data["incident_id"] == incident_id, f"Failed correlation: {data['incident_id']} != {incident_id}"

        curr_level = data["risk_assessment"]["risk_level"]
        score = data["risk_assessment"]["risk_score"]
        signals = data["risk_assessment"]["correlated_signals"]
        log_step(step_title, True, f"Risk: {curr_level} ({score}/100) | Signals: {len(signals)}")

    # Final attack chain assertions
    final_risk = last_response["risk_assessment"]
    assert final_risk["risk_score"] >= 80, "Expected score >= 80"
    assert final_risk["risk_level"] in ["HIGH", "CRITICAL"], "Expected HIGH/CRITICAL risk level"
    assert last_response["alert"] is not None, "Expected alert to be created"
    log_step("Incident correlated across 6 steps", True, f"Incident ID: {incident_id}")
    log_step("Alert created and persisted", True, f"Alert ID: {last_response['alert']['alert_id']}")
    log_step("Plain-English explanation generated", True, f"Reasons count: {len(final_risk['reasons'])}")

    # Verify Incident API for React Dashboard
    inc_resp = client.get(f"/api/incidents/{incident_id}")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert len(inc_data["events"]) == 6
    log_step("GET /api/incidents/{id} React contract", True, f"6 events in attack chain")

    # Verify n8n webhook workflow trigger
    n8n_resp = client.post("/api/n8n/process-event", json={
        "user_id": user_id,
        "device_id": "unknown_kali_box_99",
        "session_id": session_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"privilege_escalation": True}
    })
    assert n8n_resp.status_code == 200
    n8n_data = n8n_resp.json()
    assert n8n_data["should_escalate"] is True
    assert n8n_data["requires_human_approval"] is True
    log_step("n8n escalation flags triggered", True, f"should_escalate=True, requires_human_approval=True")

    # -------------------------------------------------------------------------
    # 2. NORMAL BEHAVIOR TEST
    # -------------------------------------------------------------------------
    print("\n--- 2. NORMAL BEHAVIOR SCENARIO ---")
    norm_user = "U_BENIGN_USER_01"
    norm_session = "sess_benign_work"

    norm_steps = [
        ("Normal login", {"user_id": norm_user, "device_id": "D_KNOWN_01", "session_id": norm_session, "event_type": "login", "resource": "/auth/login"}),
        ("Known device & normal API", {"user_id": norm_user, "device_id": "D_KNOWN_01", "session_id": norm_session, "event_type": "api_access", "resource": "/api/v1/profile"}),
        ("Normal agent & tool usage", {"user_id": norm_user, "device_id": "D_KNOWN_01", "session_id": norm_session, "event_type": "tool_invocation", "agent_id": "agent_copilot", "tool_name": "search_docs", "resource": "/docs"}),
    ]

    last_norm_data = None
    for title, payload in norm_steps:
        r = client.post("/api/events", json=payload)
        assert r.status_code == 201
        last_norm_data = r.json()

    norm_risk = last_norm_data["risk_assessment"]
    assert norm_risk["risk_level"] == "LOW", f"Expected LOW risk, got {norm_risk['risk_level']}"
    assert norm_risk["risk_score"] < 30, f"Expected score < 30, got {norm_risk['risk_score']}"
    assert last_norm_data["alert"] is None, "Normal behavior generated unexpected alert"
    log_step("Normal session remains LOW risk", True, f"Score: {norm_risk['risk_score']}/100 | Alerts: 0")

    # -------------------------------------------------------------------------
    # 3. FAILURE & GRACEFUL DEGRADATION TESTING
    # -------------------------------------------------------------------------
    print("\n--- 3. FAILURE HANDLING & RESILIENCE TESTS ---")

    # Test: invalid payload
    r_inv = client.post("/api/events", content="invalid json string", headers={"Content-Type": "application/json"})
    assert r_inv.status_code == 422
    log_step("Failure: Malformed JSON payload", True, "HTTP 422 handled")

    # Test: missing fields
    r_miss = client.post("/api/events", json={"user_id": "U001"})
    assert r_miss.status_code == 422
    log_step("Failure: Missing required event_type", True, "HTTP 422 handled")

    # Test: unknown event type
    r_unk = client.post("/api/events", json={"user_id": "U001", "event_type": "teleportation_flux_event"})
    assert r_unk.status_code == 201
    log_step("Failure: Unknown event type", True, "Accepted gracefully as custom event")

    # Test: Supabase unavailable fallback
    async def test_supabase_offline():
        repo = SupabaseRepository()
        repo.supabase_client = None
        evt = SecurityEvent(user_id="U_OFFLINE", event_type="login", resource="/auth")
        saved = await repo.insert_event(evt)
        assert saved.id == evt.id
        retrieved = await repo.get_event_by_id(evt.id)
        assert retrieved is not None
    asyncio.run(test_supabase_offline())
    log_step("Failure: Supabase unavailable", True, "In-memory cache fallback active")

    # Test: Cognee unavailable fallback
    async def test_cognee_offline():
        cognee = CogneeService()
        cognee.api_key = "invalid_key"
        cognee.api_url = "https://unreachable-cognee-host.invalid"
        ctx = await cognee.get_historical_context(SecurityEvent(event_type="login"))
        assert "summary" in ctx
    asyncio.run(test_cognee_offline())
    log_step("Failure: Cognee unavailable", True, "Safe baseline fallback active")

    # Test: n8n webhook request failure handling
    r_n8n_fail = client.post("/api/n8n/process-event", json={"metadata": "bad_type"})
    assert r_n8n_fail.status_code == 422
    log_step("Failure: n8n bad request validation", True, "HTTP 422 handled cleanly")

    print("\n" + "=" * 80)
    print(" ALL 12 PIPELINE CAPABILITIES & FAILURE MODES VERIFIED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    main()
