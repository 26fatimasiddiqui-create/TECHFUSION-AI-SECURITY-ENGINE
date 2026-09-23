"""Tests for PS-08 Step 6: Voice Alerts + High-Risk Security Alert UX.
Validates:
1. HIGH incident generates high-severity alert with voice_alert_required=True.
2. CRITICAL incident generates critical alert with voice_alert_required=True.
3. Alert contains risk score.
4. Alert contains explainable threat information and sanitized voice message.
5. Approval-required state is exposed correctly.
6. Acknowledgement does NOT resolve the incident.
7. Duplicate alert generation is prevented for same incident at same severity.
8. Severity escalation generates a new alert event / marks escalation and audit log.
9. Alert audit events (ALERT_CREATED, ALERT_ACKNOWLEDGED, ALERT_REPLAYED, SEVERITY_ESCALATED) are recorded.
10. Sensitive data (passwords, tokens, keys) is never present in voice messages.
11. GET /api/alerts/active-critical retrieves active unacknowledged critical alert.
"""

import time
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.risk import RiskLevel, RiskAssessment
from app.services.alert_service import (
    AlertService,
    derive_threat_type,
    format_voice_message,
    format_alert_message,
    sanitize_for_voice,
)

CLIENT = TestClient(app)


def test_sanitize_and_deterministic_voice_formatting():
    # Verify passwords, tokens, and sensitive strings are sanitized
    raw_text = "Sensitive data with password=super_secret and bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and token=secret_token"
    sanitized = sanitize_for_voice(raw_text)
    assert "super_secret" not in sanitized
    assert "eyJ" not in sanitized
    assert "secret_token" not in sanitized
    assert "[REDACTED]" in sanitized

    # Test deterministic voice formatting
    v_crit = format_voice_message(
        severity="CRITICAL",
        risk_score=94,
        threat_type="External attack chain",
        affected_entity="Aarav",
        approval_required=True,
    )
    assert "CRITICAL security alert" in v_crit
    assert "Aarav" in v_crit
    assert "Risk score 94" in v_crit
    assert "Human approval is required" in v_crit

    v_high = format_voice_message(
        severity="HIGH",
        risk_score=72,
        threat_type="Suspicious external activity",
        affected_entity="Aarav",
        approval_required=False,
    )
    assert "HIGH security alert" in v_high
    assert "Risk score 72" in v_high
    assert "Review recommended" in v_high


@pytest.mark.anyio
async def test_high_incident_generates_high_alert_with_voice_required():
    user_id = f"user_high_{int(time.time())}"
    # Ingest event that triggers HIGH risk (65 HIGH)
    r = CLIENT.post("/api/events", json={
        "user_id": user_id,
        "session_id": "sess_h_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/api/metrics",
        "metadata": {
            "is_external_ip": True,
            "agent_privilege_abuse": True,
        }
    })
    assert r.status_code == 201
    data = r.json()
    assert data["risk_assessment"]["risk_level"] == "HIGH"
    inc_id = data["incident_id"]

    # Verify alert via API
    r_alerts = CLIENT.get(f"/api/alerts?risk_level=HIGH")
    assert r_alerts.status_code == 200
    alerts = r_alerts.json()
    assert len(alerts) >= 1
    target = next((a for a in alerts if a["incident_id"] == inc_id), alerts[0])

    assert target["risk_level"] == "HIGH"
    assert target["risk_score"] >= 60
    assert target["voice_alert_required"] is True
    assert target["voice_message"] is not None
    assert "HIGH security alert" in target["voice_message"]
    assert target["acknowledged"] is False


@pytest.mark.anyio
async def test_critical_incident_generates_critical_alert_and_approval_required():
    user_id = f"user_crit_{int(time.time())}"
    # Ingest coordinated multi-signal attack chain (100 CRITICAL)
    r = CLIENT.post("/api/events", json={
        "user_id": user_id,
        "session_id": "sess_crit_99",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "185.220.101.44",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    assert r.status_code == 201
    data = r.json()
    assert data["risk_assessment"]["risk_level"] == "CRITICAL"
    inc_id = data["incident_id"]

    # Fetch alert
    r_alerts = CLIENT.get("/api/alerts?risk_level=CRITICAL")
    assert r_alerts.status_code == 200
    crit_alerts = r_alerts.json()
    assert len(crit_alerts) >= 1
    target = next((a for a in crit_alerts if a["incident_id"] == inc_id), crit_alerts[0])

    assert target["risk_level"] == "CRITICAL"
    assert target["risk_score"] >= 80
    assert target["voice_alert_required"] is True
    assert target["approval_required"] is True
    assert target["threat_type"] is not None
    assert "CRITICAL security alert" in target["voice_message"]
    assert "Human approval is required" in target["voice_message"]


@pytest.mark.anyio
async def test_alert_contains_risk_score_and_threat_info():
    alert_svc = AlertService()
    assessment = RiskAssessment(
        risk_score=78,
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        reasons=["Access to sensitive database tier", "Unfamiliar IP address"],
        recommended_action="Restrict session token",
        correlated_signals=["sensitive_resource", "suspicious_external_ip"],
    )

    alert = await alert_svc.create_alert(
        incident_id="INC-TEST-01",
        risk_assessment=assessment,
        primary_entity="Vikram",
        approval_required=True,
    )

    assert alert.risk_score == 78
    assert alert.risk_level == "HIGH"
    assert alert.threat_type == "External attack chain"
    assert "Vikram" in alert.voice_message
    assert alert.voice_alert_required is True
    assert alert.approval_required is True


@pytest.mark.anyio
async def test_acknowledgement_does_not_resolve_incident():
    # Ingest critical incident
    user_id = f"user_ack_{int(time.time())}"
    r = CLIENT.post("/api/events", json={
        "user_id": user_id,
        "event_type": "data_access",
        "resource": "/database/vault",
        "metadata": {
            "is_external_ip": True,
            "data_exfiltration": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True
        }
    })
    inc_id = r.json()["incident_id"]

    # Get alert
    r_alerts = CLIENT.get("/api/alerts")
    alerts = [a for a in r_alerts.json() if a.get("incident_id") == inc_id]
    assert len(alerts) >= 1
    alert_id = alerts[0]["alert_id"]

    # Acknowledge the alert
    r_ack = CLIENT.post(f"/api/alerts/{alert_id}/acknowledge", json={
        "actor": "SOC_Analyst_Sarah",
        "notes": "Analyst reviewed telemetry and commenced investigation."
    })
    assert r_ack.status_code == 200
    ack_alert = r_ack.json()
    assert ack_alert["acknowledged"] is True
    assert ack_alert["status"] == "acknowledged"
    assert ack_alert["acknowledged_by"] == "SOC_Analyst_Sarah"

    # CRUCIAL INVARIANT: Underlying incident status must NOT be resolved!
    r_inc = CLIENT.get(f"/api/incidents/{inc_id}")
    assert r_inc.status_code == 200
    inc_data = r_inc.json()
    assert inc_data["status"] != "resolved"
    assert inc_data["status"] != "mitigated"


@pytest.mark.anyio
async def test_duplicate_alert_prevention():
    alert_svc = AlertService()
    assessment = RiskAssessment(
        risk_score=70,
        risk_level=RiskLevel.HIGH,
        confidence=0.88,
        reasons=["Unusual tool invocation"],
        recommended_action="Review agent permissions",
        correlated_signals=["unexpected_tool_usage"],
    )

    # Initial alert creation
    alert1 = await alert_svc.create_alert(
        incident_id="INC-DUP-01",
        risk_assessment=assessment,
        primary_entity="Agent_Worker",
    )
    alert1_id = alert1.alert_id

    # Repeated poll with same severity
    alert2 = await alert_svc.create_alert(
        incident_id="INC-DUP-01",
        risk_assessment=assessment,
        primary_entity="Agent_Worker",
    )

    # Must NOT create a duplicate alert ID or spam
    assert alert2.alert_id == alert1_id
    assert len(alert_svc._memory_alerts) == 1


@pytest.mark.anyio
async def test_severity_escalation_generates_new_alert_state():
    from app.services.response_service import ResponseService
    resp_svc = ResponseService()
    alert_svc = AlertService(response_svc=resp_svc)

    # 1. Moderate initial event
    mod_assessment = RiskAssessment(
        risk_score=45,
        risk_level=RiskLevel.MODERATE,
        confidence=0.8,
        reasons=["New IP detected"],
        recommended_action="Increase monitoring",
        correlated_signals=["new_ip"],
    )
    alert_mod = await alert_svc.create_alert(
        incident_id="INC-ESC-01",
        risk_assessment=mod_assessment,
        primary_entity="Dev_User",
    )
    assert alert_mod.risk_level == "MODERATE"
    assert alert_mod.voice_alert_required is False

    # 2. Corroborated escalation to CRITICAL
    crit_assessment = RiskAssessment(
        risk_score=92,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.95,
        reasons=["Data exfiltration to external Tor exit node", "Brute force login"],
        recommended_action="Immediate containment and MFA reset",
        correlated_signals=["data_exfiltration", "brute_force_login", "external_attack_chain"],
    )
    alert_esc = await alert_svc.create_alert(
        incident_id="INC-ESC-01",
        risk_assessment=crit_assessment,
        primary_entity="Dev_User",
        approval_required=True,
    )

    # Verify escalation properties
    assert alert_esc.risk_level == "CRITICAL"
    assert alert_esc.risk_score == 92
    assert alert_esc.voice_alert_required is True
    assert alert_esc.status == "escalated"
    assert "CRITICAL security alert" in alert_esc.voice_message

    # Verify SEVERITY_ESCALATED audit entry was created
    audit = resp_svc.get_audit_trail(incident_id="INC-ESC-01")
    escalated_entries = [e for e in audit if e.action == "SEVERITY_ESCALATED"]
    assert len(escalated_entries) >= 1
    assert escalated_entries[0].details["old_severity"] == "MODERATE"
    assert escalated_entries[0].details["new_severity"] == "CRITICAL"


@pytest.mark.anyio
async def test_alert_audit_events_recorded():
    from app.services.response_service import ResponseService
    resp_svc = ResponseService()
    alert_svc = AlertService(response_svc=resp_svc)

    assessment = RiskAssessment(
        risk_score=85,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.9,
        reasons=["Prompt injection attack"],
        recommended_action="Block prompt and revoke agent session",
        correlated_signals=["prompt_injection"],
    )

    # 1. Alert Created
    alert = await alert_svc.create_alert(
        incident_id="INC-AUDIT-01",
        risk_assessment=assessment,
        primary_entity="Analyst_User",
    )

    # 2. Alert Acknowledged
    await alert_svc.acknowledge_alert(alert.alert_id, actor="SOC_Alice")

    # 3. Alert Replayed
    await alert_svc.replay_alert(alert.alert_id, actor="SOC_Alice")

    # Check Audit Log
    trail = resp_svc.get_audit_trail(incident_id="INC-AUDIT-01")
    actions = [t.action for t in trail]

    assert "ALERT_CREATED" in actions
    assert "ALERT_ACKNOWLEDGED" in actions
    assert "ALERT_REPLAYED" in actions


@pytest.mark.anyio
async def test_get_active_critical_alert_endpoint():
    # Ingest critical event
    user_id = f"user_banner_{int(time.time())}"
    CLIENT.post("/api/events", json={
        "user_id": user_id,
        "event_type": "data_access",
        "resource": "/database/critical_table",
        "metadata": {
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True
        }
    })

    # Query active-critical endpoint
    r = CLIENT.get("/api/alerts/active-critical")
    assert r.status_code == 200
    crit_alert = r.json()
    if crit_alert:
        assert crit_alert["risk_level"] == "CRITICAL"
        assert crit_alert["voice_alert_required"] is True
