"""PS-08 Step 6: Voice Alerts + High-Risk Security Alert UX Demo.
Demonstrates:
  DEMO A: Normal event -> Low risk -> No voice alert required
  DEMO B: HIGH risk incident -> Visual alert + Voice announcement generated
  DEMO C: CRITICAL attack chain -> Critical banner + Voice alert + Two-Person Rule approval required
  DEMO D: Same incident polled repeatedly -> Duplicate audio/voice spam suppressed
  DEMO E: Severity escalation (HIGH -> CRITICAL) -> New critical voice alert + Audit log
  DEMO F: Alert acknowledgement -> Operator notice confirmed -> Underlying incident remains active

Can be run directly via:
  python demo_voice_alerts.py
"""

import time
from starlette.testclient import TestClient
from app.main import app

CLIENT = TestClient(app)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(text: str, color: str = CYAN):
    print(f"\n{BOLD}{color}{'=' * 78}{RESET}")
    print(f"{BOLD}{color} {text}{RESET}")
    print(f"{BOLD}{color}{'=' * 78}{RESET}")


def run_demo():
    print_banner("PS-08 STEP 6: VOICE ALERTS + HIGH-RISK SECURITY ALERT UX DEMO", CYAN)
    print("Demonstrating real-time voice synthesis text generation, de-duplication,")
    print("severity escalation, non-resolving acknowledgement, and audit integration.\n")

    # =========================================================================
    # DEMO A: NORMAL EVENT -> LOW RISK -> NO VOICE ALERT
    # =========================================================================
    print_banner("DEMO A: NORMAL EVENT (LOW RISK) - NO VOICE ALERT", GREEN)
    print("Scenario: Regular user login and routine telemetry.")
    print("Expectation: Alert is passive monitoring, voice_alert_required is FALSE.")

    user_a = f"user_norm_{int(time.time())}"
    r_a = CLIENT.post("/api/events", json={
        "user_id": user_a,
        "event_type": "login",
        "resource": "/auth/login",
        "metadata": {"ip": "10.0.1.50"}
    })
    assert r_a.status_code == 201
    d_a = r_a.json()
    risk_a = d_a["risk_assessment"]
    alert_a = d_a.get("alert")
    print(f"  Incident ID          : {d_a['incident_id']}")
    print(f"  Risk Level           : {risk_a['risk_level']} (Score: {risk_a['risk_score']}/100)")
    print(f"  Voice Alert Required : {alert_a.get('voice_alert_required') if alert_a else False}")
    assert (alert_a is None) or (alert_a.get("voice_alert_required") is False)
    print(f"{BOLD}{GREEN}[PASS - DEMO A COMPLETE]{RESET} Low-risk event does not trigger voice alert.")

    # =========================================================================
    # DEMO B: HIGH RISK INCIDENT -> VOICE ANNOUNCEMENT GENERATED
    # =========================================================================
    print_banner("DEMO B: HIGH RISK INCIDENT - VOICE ALERT ANNOUNCEMENT", YELLOW)
    print("Scenario: Privileged tool access from external network.")
    print("Expectation: voice_alert_required is TRUE, concise sanitized voice message formatted.")

    user_b = f"user_high_{int(time.time())}"
    r_b = CLIENT.post("/api/events", json={
        "user_id": user_b,
        "session_id": "sess_high_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/api/metrics",
        "metadata": {
            "is_external_ip": True,
            "agent_privilege_abuse": True,
        }
    })
    assert r_b.status_code == 201
    d_b = r_b.json()
    alert_b = d_b["alert"]
    print(f"  Incident ID          : {d_b['incident_id']}")
    print(f"  Risk Level           : {alert_b['risk_level']} (Score: {alert_b['risk_score']}/100)")
    print(f"  Threat Type          : {alert_b['threat_type']}")
    print(f"  Voice Alert Required : {alert_b['voice_alert_required']}")
    print(f"  Synthesized Speech   : \"{alert_b['voice_message']}\"")
    assert alert_b["risk_level"] == "HIGH"
    assert alert_b["voice_alert_required"] is True
    assert "HIGH security alert" in alert_b["voice_message"]
    print(f"{BOLD}{GREEN}[PASS - DEMO B COMPLETE]{RESET} High risk incident generates voice announcement.")

    # =========================================================================
    # DEMO C: CRITICAL ATTACK CHAIN -> CRITICAL BANNER + TWO-PERSON GATING
    # =========================================================================
    print_banner("DEMO C: CRITICAL ATTACK CHAIN - VOICE ALERT + TWO-PERSON RULE GATING", RED)
    print("Scenario: Coordinated data exfiltration + prompt injection attack.")
    print("Expectation: Voice alert specifies human approval required; Step 5 Two-Person Rule enforced.")

    user_c = f"user_crit_{int(time.time())}"
    r_c = CLIENT.post("/api/events", json={
        "user_id": user_c,
        "session_id": "sess_crit_01",
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
    assert r_c.status_code == 201
    d_c = r_c.json()
    alert_c = d_c["alert"]
    print(f"  Incident ID          : {d_c['incident_id']}")
    print(f"  Risk Level           : {alert_c['risk_level']} (Score: {alert_c['risk_score']}/100)")
    print(f"  Approval Required    : {alert_c['approval_required']} (State: {alert_c['approval_state']})")
    print(f"  Voice Announcement   : \"{alert_c['voice_message']}\"")
    print(f"  Display Alert Text   : \"{alert_c['message']}\"")
    assert alert_c["risk_level"] == "CRITICAL"
    assert alert_c["voice_alert_required"] is True
    assert alert_c["approval_required"] is True
    assert "Human approval is required" in alert_c["voice_message"]
    print(f"{BOLD}{GREEN}[PASS - DEMO C COMPLETE]{RESET} Critical banner and approval requirements generated.")

    # =========================================================================
    # DEMO D: DUPLICATE ALERT PREVENTION
    # =========================================================================
    print_banner("DEMO D: DUPLICATE ALERT PREVENTION (NO AUDIO SPAM)", YELLOW)
    print("Scenario: Polling telemetry or repeating event on same incident at same severity.")
    print("Expectation: Reuses existing alert record; does NOT create duplicate alert ID.")

    inc_d = d_c["incident_id"]
    r_repeat = CLIENT.post("/api/events", json={
        "user_id": user_c,
        "session_id": "sess_crit_01",
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
    d_d = r_repeat.json()
    alert_d = d_d["alert"]
    print(f"  Original Alert ID    : {alert_c['alert_id']}")
    print(f"  Repeated Alert ID    : {alert_d['alert_id']}")
    assert alert_d["alert_id"] == alert_c["alert_id"]
    print(f"{BOLD}{GREEN}[PASS - DEMO D COMPLETE]{RESET} Duplicate alert prevented; stable alert ID preserved.")

    # =========================================================================
    # DEMO E: SEVERITY ESCALATION (MODERATE -> CRITICAL)
    # =========================================================================
    print_banner("DEMO E: SEVERITY ESCALATION (MODERATE -> CRITICAL)", RED)
    print("Scenario: Initial moderate activity followed by high-severity attack escalation.")
    print("Expectation: Alert escalates, voice_alert_required set to True, SEVERITY_ESCALATED logged.")

    from app.api.dependencies import get_alert_service, get_response_service
    from app.models.risk import RiskAssessment, RiskLevel

    alert_svc = get_alert_service()
    resp_svc = get_response_service()
    inc_e = f"INC-ESC-{int(time.time())}"

    # 1. Moderate initial alert
    mod_assessment = RiskAssessment(
        risk_score=40,
        risk_level=RiskLevel.MODERATE,
        confidence=0.85,
        reasons=["Unusual login location"],
        recommended_action="Increase monitoring",
        correlated_signals=["new_ip"],
    )
    alert_e1 = await_sync(alert_svc.create_alert(
        incident_id=inc_e,
        risk_assessment=mod_assessment,
        primary_entity="Eng_Lead",
    ))
    print(f"  Stage 1 Severity     : {alert_e1.risk_level} (Voice Required: {alert_e1.voice_alert_required})")
    assert alert_e1.risk_level == "MODERATE"
    assert alert_e1.voice_alert_required is False

    # 2. Critical escalation
    crit_assessment = RiskAssessment(
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.96,
        reasons=["Data exfiltration to external IP", "Prompt injection"],
        recommended_action="Isolate session and containment",
        correlated_signals=["data_exfiltration", "prompt_injection"],
    )
    alert_e2 = await_sync(alert_svc.create_alert(
        incident_id=inc_e,
        risk_assessment=crit_assessment,
        primary_entity="Eng_Lead",
        approval_required=True,
    ))
    print(f"  Stage 2 Escalated    : {alert_e2.risk_level} (Voice Required: {alert_e2.voice_alert_required})")
    print(f"  Escalated Voice Msg  : \"{alert_e2.voice_message}\"")
    assert alert_e2.risk_level == "CRITICAL"
    assert alert_e2.voice_alert_required is True
    assert alert_e2.status == "escalated"

    audit_e = resp_svc.get_audit_trail(incident_id=inc_e)
    esc_entry = next((e for e in audit_e if e.action == "SEVERITY_ESCALATED"), None)
    assert esc_entry is not None
    print(f"  Audit Trail Action   : {esc_entry.action} ({esc_entry.reason})")
    print(f"{BOLD}{GREEN}[PASS - DEMO E COMPLETE]{RESET} Severity escalation triggers new voice alert and audit log.")

    # =========================================================================
    # DEMO F: ALERT ACKNOWLEDGEMENT PRESERVES INCIDENT STATUS
    # =========================================================================
    print_banner("DEMO F: ALERT ACKNOWLEDGEMENT (PRESERVES INCIDENT STATUS)", CYAN)
    print("Scenario: Operator acknowledges the critical alert.")
    print("Expectation: alert.acknowledged=True, but incident remains ACTIVE and unmitigated.")

    r_ack = CLIENT.post(f"/api/alerts/{alert_c['alert_id']}/acknowledge", json={
        "actor": "SOC_Analyst_Devin",
        "notes": "Operator acknowledged voice alert; investigating credentials."
    })
    assert r_ack.status_code == 200
    ack_res = r_ack.json()
    print(f"  Alert Acknowledged   : {ack_res['acknowledged']} (By: {ack_res['acknowledged_by']})")
    print(f"  Alert Status         : {ack_res['status']}")
    assert ack_res["acknowledged"] is True

    # Check that incident is NOT resolved
    r_inc_check = CLIENT.get(f"/api/incidents/{d_c['incident_id']}")
    inc_status = r_inc_check.json().get("status")
    print(f"  Incident Status      : {inc_status} (NOT resolved / NOT suppressed)")
    assert inc_status != "resolved"
    assert inc_status != "mitigated"
    print(f"{BOLD}{GREEN}[PASS - DEMO F COMPLETE]{RESET} Acknowledgement confirms operator notice while preserving incident active state.")

    print_banner("PS-08 STEP 6 DEMONSTRATION COMPLETE - ALL 6 SCENARIOS VERIFIED", GREEN)


def await_sync(coro):
    """Utility to run async function synchronously in CLI demo."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


if __name__ == "__main__":
    run_demo()
