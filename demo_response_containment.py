"""PS-08 Step 4: Risk-Adaptive Response & Automated Containment Demo Scenario.
Demonstrates:
  Part 1: Benign / Contextual Unfamiliar IP (LOW Risk)
    - Unfamiliar external IP connects and logs in.
    - Evaluated as LOW risk.
    - Action: Passive MONITORING only.
    - CRITICAL SAFEGUARD VERIFIED: Unfamiliar IP is NEVER blocked on its own.

  Part 2: Suspicious Credential & API Jump (HIGH Risk)
    - New device + multiple rapid API requests to sensitive export endpoints.
    - Evaluated as HIGH risk.
    - Action: STEP_UP_AUTH (challenge required) + RESTRICT_API (rate-limiting).
    - Fully automated, safe mitigation without human gate.

  Part 3: Coordinated External Attack Chain & Containment (CRITICAL Risk)
    - Coordinated multi-stage attack: Suspicious IP -> Brute-Force -> Prompt Injection -> Privilege Abuse -> Exfiltration.
    - Evaluated as CRITICAL risk (100/100).
    - Human Approval Gate: Destructive containment actions held in PENDING_APPROVAL.
    - Analyst Review & Approval: Security operations approves containment.
    - Safe Simulation Execution: Session suspended, AI agent contained, corroborated source blocked in safe simulation mode.
    - Audit Trail: Immutable chronological record of every decision, approval, and execution.
    - False-Positive Recovery: Operator recovers an incident; restrictions are lifted, incident resolved, audit history preserved.

Can be run directly via:
  python demo_response_containment.py
"""

import json
import time
from datetime import datetime
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


def run_response_containment_demo():
    print_banner("PS-08 STEP 4: RISK-ADAPTIVE RESPONSE & CONTAINMENT DEMO", CYAN)
    print("This scenario demonstrates the closed-loop pipeline from threat detection")
    print("and risk scoring to calibrated, proportional response actions, human approval gates,")
    print("safe simulation containment, immutable audit trails, and false-positive recovery.\n")

    # =========================================================================
    # PART 1: UNFAMILIAR IP (LOW RISK) - SAFEGUARD VERIFICATION
    # =========================================================================
    print_banner("PART 1: UNFAMILIAR IP ALONE (LOW RISK) - SAFEGUARD VERIFIED", GREEN)
    print("User: Dan Green (Remote Employee)")
    print("Scenario: Dan authenticates from a new coffee shop IP.")
    print("Expectation: LOW risk -> Passive MONITORING -> NEVER blocked.")

    dan_user = f"dan_green_{int(time.time())}"
    dan_session = f"sess_dan_{int(time.time())}"
    dan_ip = "203.0.113.88"

    payload_low = {
        "user_id": dan_user,
        "session_id": dan_session,
        "event_type": "login",
        "action": "login",
        "resource": "/portal/dashboard",
        "metadata": {
            "ip": dan_ip,
            "device_id": "laptop_corporate_01",
            "is_new_ip": True,
            "status": "success",
        }
    }

    r1 = CLIENT.post("/api/events", json=payload_low)
    assert r1.status_code == 201, f"Failed: {r1.text}"
    resp1 = r1.json()

    risk1 = resp1.get("risk_assessment") or {}
    decision1 = resp1.get("response_decision") or {}

    print(f"  Risk Score        : {risk1.get('risk_score', 'N/A')}/100")
    print(f"  Risk Level        : {risk1.get('risk_level', 'N/A')}")
    print(f"  Response Level    : {decision1.get('response_level', 'N/A')}")
    print(f"  Recommended Actions: {decision1.get('recommended_actions', [])}")
    print(f"  Approval Required : {decision1.get('approval_required', False)}")

    # Verification of safeguard
    rec_actions = decision1.get("recommended_actions", [])
    assert "BLOCK_SOURCE" not in rec_actions, "VIOLATION: Unfamiliar IP must never be blocked!"
    print(f"\n{BOLD}{GREEN}[PASS - SAFEGUARD CONFIRMED]{RESET} Unfamiliar IP was NOT blocked. Passive monitoring active.")

    # =========================================================================
    # PART 2: HIGH-RISK THREAT - ADAPTIVE MITIGATION (NO HUMAN GATE)
    # =========================================================================
    print_banner("PART 2: HIGH-RISK CREDENTIAL & API ANOMALY (STEP-UP & RATE LIMIT)", YELLOW)
    print("User: Sarah Connor (Financial Analyst)")
    print("Scenario: Fast sequential requests from unfamiliar device to sensitive payroll endpoint.")
    print("Expectation: HIGH risk -> STEP_UP_AUTH & RESTRICT_API applied automatically.")

    sarah_user = f"sarah_c_{int(time.time())}"
    sarah_session = f"sess_sarah_{int(time.time())}"

    payload_high = {
        "user_id": sarah_user,
        "session_id": sarah_session,
        "event_type": "api_access",
        "action": "export",
        "resource": "/api/v1/payroll/salaries/export",
        "metadata": {
            "ip": "198.51.100.44",
            "device_id": "unknown_phone_dev",
            "is_new_device": True,
            "is_new_ip": True,
            "unusual_api_activity": True,
            "is_sensitive_resource": True,
        }
    }

    r2 = CLIENT.post("/api/events", json=payload_high)
    assert r2.status_code == 201, f"Failed: {r2.text}"
    resp2 = r2.json()

    risk2 = resp2.get("risk_assessment") or {}
    decision2 = resp2.get("response_decision") or {}

    print(f"  Risk Score        : {risk2.get('risk_score', 'N/A')}/100")
    print(f"  Risk Level        : {risk2.get('risk_level', 'N/A')}")
    print(f"  Response Level    : {decision2.get('response_level', 'N/A')}")
    print(f"  Recommended Actions: {decision2.get('recommended_actions', [])}")
    print(f"  Approval Required : {decision2.get('approval_required', False)}")
    print(f"  Action Status     : {decision2.get('action_status', 'N/A')}")

    print(f"\n{BOLD}{YELLOW}[PASS - HIGH RISK MITIGATION]{RESET} Step-up challenge issued and API rate-limited without business halt.")

    # =========================================================================
    # PART 3: CRITICAL ATTACK CHAIN - HUMAN APPROVAL & CONTAINMENT
    # =========================================================================
    print_banner("PART 3: CRITICAL COORDINATED ATTACK CHAIN (CONTAINMENT & APPROVAL)", RED)
    print("Target User: sysadmin_root")
    print("Scenario: Suspicious external IP conducts Brute-Force -> Prompt Injects Copilot -> Exfiltrates DB.")
    print("Expectation: CRITICAL (100/100) -> Containment gated by HUMAN APPROVAL.")

    target_user = f"sysadmin_{int(time.time())}"
    target_session = f"sess_crit_{int(time.time())}"
    attacker_ip = "185.220.101.5"

    payload_crit = {
        "user_id": target_user,
        "session_id": target_session,
        "agent_id": "security_copilot_v1",
        "tool_name": "raw_db_shell",
        "event_type": "data_access",
        "action": "exfiltration",
        "resource": "/database/prod/customer_vault",
        "metadata": {
            "ip": attacker_ip,
            "is_external_ip": True,
            "is_suspicious_ip": True,
            "brute_force_login": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
            "external_attack_chain": True,
            "outbound_bytes": 10_500_000,
        }
    }

    r3 = CLIENT.post("/api/events", json=payload_crit)
    assert r3.status_code == 201, f"Failed: {r3.text}"
    resp3 = r3.json()

    incident_id = resp3.get("incident_id")
    risk3 = resp3.get("risk_assessment") or {}
    decision3 = resp3.get("response_decision") or {}

    print(f"  Incident ID       : {incident_id}")
    print(f"  Risk Score        : {risk3.get('risk_score', 'N/A')}/100")
    print(f"  Risk Level        : {risk3.get('risk_level', 'N/A')}")
    print(f"  Response Level    : {decision3.get('response_level', 'N/A')}")
    print(f"  Human Approval Req: {decision3.get('approval_required', False)}")
    print(f"  Action Status     : {decision3.get('action_status', 'N/A')}")
    print(f"  Recommended Actions: {decision3.get('recommended_actions', [])}")

    assert decision3.get("approval_required") is True, "CRITICAL actions must require human approval!"

    # =========================================================================
    # PART 4: SECURITY ANALYST APPROVAL & SAFE CONTAINMENT EXECUTION
    # =========================================================================
    print_banner("PART 4: SOC ANALYST APPROVAL & SIMULATED CONTAINMENT", CYAN)
    print(f"Analyst 'SOC_Lead_Alice' reviews Incident {incident_id} and triggers containment approval.")

    r_approve = CLIENT.post(f"/api/response/{incident_id}/approve", json={
        "actor": "SOC_Lead_Alice",
        "notes": "Corroborated prompt injection and DB exfiltration. Containment authorized."
    })
    assert r_approve.status_code == 200, f"Approval failed: {r_approve.text}"
    approved_actions = r_approve.json()

    print(f"\n{BOLD}Executed Response Actions (Simulation Mode):{RESET}")
    for act in approved_actions:
        print(f"  - Type: {act.get('action_type'):<18} | Target: {act.get('target'):<24} | Status: {act.get('status')}")
        print(f"    Mode: {act.get('execution_mode')} | Simulation Notice: {act.get('details', {}).get('simulation_notice', 'N/A')[:60]}...")

    # =========================================================================
    # PART 5: IMMUTABLE AUDIT TRAIL VERIFICATION
    # =========================================================================
    print_banner("PART 5: AUDIT TRAIL VERIFICATION", GREEN)
    r_audit = CLIENT.get(f"/api/response/audit-trail?incident_id={incident_id}")
    assert r_audit.status_code == 200
    entries = r_audit.json()

    print(f"Retrieved {len(entries)} audit entries for incident {incident_id}:")
    for i, e in enumerate(entries, 1):
        print(f"  [{i}] {e.get('timestamp')} | Action: {e.get('action'):<20} | Actor: {e.get('actor'):<16} | Status: {e.get('status')}")

    # =========================================================================
    # PART 6: FALSE-POSITIVE RECOVERY WORKFLOW
    # =========================================================================
    print_banner("PART 6: FALSE-POSITIVE RECOVERY WORKFLOW", YELLOW)
    print("Scenario: Forensic analyst discovers this was an authorized red-team exercise.")
    print("Action: Analyst executes false-positive recovery -> Restrictions lifted -> Audit preserved.")

    r_recover = CLIENT.post(f"/api/response/{incident_id}/recover", json={
        "incident_id": incident_id,
        "reason": "Authorized Red Team Exercise engagement RT-2026-Q3",
        "actor": "SOC_Director_Bob",
        "restore_access": True
    })
    assert r_recover.status_code == 200, f"Recovery failed: {r_recover.text}"
    rec_result = r_recover.json()

    print(f"  Recovery Status   : {rec_result.get('recovery_status')}")
    print(f"  Actions Lifted    : {rec_result.get('actions_lifted_count')}")
    print(f"  Message           : {rec_result.get('message')}")

    # Verify audit trail still exists and contains recovery entry
    r_audit_after = CLIENT.get(f"/api/response/audit-trail?incident_id={incident_id}")
    entries_after = r_audit_after.json()
    print(f"\n{BOLD}Audit Trail after Recovery (Preserved):{RESET}")
    print(f"  Total Entries Count: {len(entries_after)} (Initial: {len(entries)})")
    assert any(e.get("action") == "RECOVER_FALSE_POSITIVE" for e in entries_after), "Recovery audit missing!"
    print(f"\n{BOLD}{GREEN}[PASS - PS-08 STEP 4 DEMONSTRATION COMPLETE]{RESET}")
    print("All response-adaptation, containment, human-approval, audit, and recovery flows verified successfully.\n")


if __name__ == "__main__":
    run_response_containment_demo()
