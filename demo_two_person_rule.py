"""PS-08 Step 5: Compromised Approver Detection, Two-Person Rule, and Independent Verification Demo.
Demonstrates:
  DEMO A: Normal Critical Incident -> Safe Approver 1 -> Independent Safe Approver 2 -> Simulated Containment
  DEMO B: Critical Incident -> Approver with Elevated Risk (Impossible Travel / Auth Anomaly) -> Approval Blocked
  DEMO C: Two-Person Rule Violation -> Approver 1 tries to self-approve as Approver 2 -> Rejected
  DEMO D: Approver 2 is also High-Risk -> Second Approval Blocked -> Containment Remains Held
  DEMO E: 15-Minute Expiration -> Approval Expired -> Execution Rejected -> Fresh Approval Required

Can be run directly via:
  python demo_two_person_rule.py
"""

import time
from datetime import datetime, timezone, timedelta
from starlette.testclient import TestClient
from app.main import app
from app.models.response import ApprovalState

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
    print_banner("PS-08 STEP 5: COMPROMISED APPROVER & TWO-PERSON RULE DEMO", CYAN)
    print("Demonstrating behavioral trust verification, human authorization gates,")
    print("and independent dual-approver enforcement for critical containment.\n")

    # =========================================================================
    # DEMO A: NORMAL CRITICAL INCIDENT -> DUAL SAFE APPROVALS -> SIMULATED EXECUTION
    # =========================================================================
    print_banner("DEMO A: NORMAL CRITICAL INCIDENT - TWO-PERSON APPROVAL FLOW", GREEN)
    print("Scenario: Coordinated DB exfiltration -> Critical incident formulated.")
    print("Flow: Approver 1 (Alice) approves -> APPROVER_2_REQUIRED -> Approver 2 (Bob) approves -> Execution.")

    # 1. Ingest Critical Threat
    user_a = f"sysadmin_a_{int(time.time())}"
    r_ingest_a = CLIENT.post("/api/events", json={
        "user_id": user_a,
        "session_id": "sess_crit_a_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "185.220.101.5",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    assert r_ingest_a.status_code == 201
    inc_a = r_ingest_a.json()["incident_id"]
    print(f"  Incident ID        : {inc_a}")
    print(f"  Response Level     : CRITICAL (Two-Person Rule Required)")

    # 2. Approver 1 Risk Evaluation & Approval
    r_appr1 = CLIENT.post(f"/api/response/{inc_a}/approve", json={
        "approver_id": "SOC_Analyst_Alice",
        "role": "SECURITY_ANALYST",
        "session_id": "sess_alice_safe",
        "ip": "10.0.1.100",
    })
    assert r_appr1.status_code == 200

    r_status1 = CLIENT.get(f"/api/response/{inc_a}/approval-status")
    status1 = r_status1.json()
    print(f"  Approver 1 Status  : {status1.get('state')} (Approver 1: {status1.get('approver_1_id')})")
    print(f"  Approver 1 Risk    : {status1.get('approver_1_risk_level')} (Score: {status1.get('approver_1_risk_score')}/100)")
    assert status1.get("state") in ["APPROVER_2_REQUIRED", "APPROVER_1_APPROVED"]

    # 3. Independent Approver 2 Approval
    r_appr2 = CLIENT.post(f"/api/response/{inc_a}/second-approve", json={
        "approver_id": "SOC_Admin_Bob",
        "role": "SECURITY_ADMIN",
        "session_id": "sess_bob_safe",
        "ip": "10.0.1.105",
    })
    assert r_appr2.status_code == 200
    executed_a = r_appr2.json()

    r_status2 = CLIENT.get(f"/api/response/{inc_a}/approval-status")
    status2 = r_status2.json()
    print(f"  Final State        : {status2.get('state')}")
    print(f"  Executed Actions   : {len(executed_a)} containment actions dispatched in simulation mode")
    print(f"{BOLD}{GREEN}[PASS - DEMO A COMPLETE]{RESET} Two-Person Rule satisfied by independent safe approvers.")

    # =========================================================================
    # DEMO B: ELEVATED APPROVER RISK (IMPOSSIBLE TRAVEL / ANOMALY) -> APPROVAL BLOCKED
    # =========================================================================
    print_banner("DEMO B: COMPROMISED APPROVER DETECTION - APPROVAL BLOCKED", RED)
    print("Scenario: Approver account has suspicious context (Impossible Travel & Anomaly).")
    print("Expectation: Approval is BLOCKED. Action remains held pending independent verification.")

    user_b = f"sysadmin_b_{int(time.time())}"
    r_ingest_b = CLIENT.post("/api/events", json={
        "user_id": user_b,
        "session_id": "sess_crit_b_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "198.51.100.99",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    inc_b = r_ingest_b.json()["incident_id"]

    # Suspicious approver evaluates risk
    r_eval_b = CLIENT.post(f"/api/response/{inc_b}/approvals/evaluate-approver", json={
        "approver_id": "Compromised_Lead_Charlie",
        "role": "SECURITY_ANALYST",
        "session_id": "sess_travel_anom",
        "metadata": {
            "impossible_travel": True,
            "failed_logins": True,
        }
    })
    assert r_eval_b.status_code == 200
    eval_b = r_eval_b.json()
    print(f"  Approver ID        : {eval_b.get('approver_id')}")
    print(f"  Risk Level         : {eval_b.get('approver_risk_level')} (Score: {eval_b.get('approver_risk_score')}/100)")
    print(f"  Approval Allowed   : {eval_b.get('approval_allowed')}")
    print(f"  Indep Verification : {eval_b.get('requires_independent_verification')}")
    print(f"  Explainable Reasons:")
    for r in eval_b.get("reasons", []):
        print(f"    - {r}")

    # Approver attempt is blocked
    r_block_b = CLIENT.post(f"/api/response/{inc_b}/approve", json={
        "approver_id": "Compromised_Lead_Charlie",
        "role": "SECURITY_ANALYST",
        "metadata": {"impossible_travel": True, "failed_logins": True},
    })
    assert r_block_b.status_code == 200
    r_status_b = CLIENT.get(f"/api/response/{inc_b}/approval-status")
    print(f"  Approval Record State: {r_status_b.json().get('state')}")
    assert r_status_b.json().get("state") == "APPROVAL_BLOCKED"
    print(f"{BOLD}{GREEN}[PASS - DEMO B COMPLETE]{RESET} Risky approver blocked from authorizing containment alone.")

    # =========================================================================
    # DEMO C: TWO-PERSON RULE VIOLATION (SELF-APPROVAL AS APPROVER 2)
    # =========================================================================
    print_banner("DEMO C: TWO-PERSON RULE VIOLATION (SAME APPROVER REJECTED)", YELLOW)
    print("Scenario: Approver 1 approves, then tries to approve as Approver 2.")
    print("Expectation: System strictly rejects attempt (Approver 1 != Approver 2).")

    user_c = f"sysadmin_c_{int(time.time())}"
    r_ingest_c = CLIENT.post("/api/events", json={
        "user_id": user_c,
        "session_id": "sess_crit_c_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "185.220.101.7",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    inc_c = r_ingest_c.json()["incident_id"]

    CLIENT.post(f"/api/response/{inc_c}/approve", json={
        "approver_id": "SOC_Analyst_Alice",
        "role": "SECURITY_ANALYST",
    })

    # Approver 1 tries to satisfy Approver 2
    r_self = CLIENT.post(f"/api/response/{inc_c}/second-approve", json={
        "approver_id": "SOC_Analyst_Alice",  # Same approver!
        "role": "SECURITY_ADMIN",
    })
    print(f"  Status Code        : {r_self.status_code}")
    print(f"  Error Detail       : {r_self.json().get('detail')}")
    assert r_self.status_code == 400
    assert "Two-Person Rule violation" in r_self.json().get("detail", "")
    print(f"{BOLD}{GREEN}[PASS - DEMO C COMPLETE]{RESET} Same approver self-approval rejected.")

    # =========================================================================
    # DEMO D: SECOND APPROVER IS ALSO HIGH-RISK -> BLOCKED
    # =========================================================================
    print_banner("DEMO D: HIGH-RISK SECOND APPROVER BLOCKED", RED)
    print("Scenario: Approver 1 is safe, but Approver 2 context exhibits privilege escalation.")
    print("Expectation: Approver 2 is blocked. Containment actions remain unexecuted.")

    user_d = f"sysadmin_d_{int(time.time())}"
    r_ingest_d = CLIENT.post("/api/events", json={
        "user_id": user_d,
        "session_id": "sess_crit_d_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "185.220.101.8",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    inc_d = r_ingest_d.json()["incident_id"]

    CLIENT.post(f"/api/response/{inc_d}/approve", json={
        "approver_id": "SOC_Analyst_Alice",
        "role": "SECURITY_ANALYST",
    })

    # Risky second approver
    r_risky2 = CLIENT.post(f"/api/response/{inc_d}/second-approve", json={
        "approver_id": "Risky_Admin_Eve",
        "role": "SECURITY_ADMIN",
        "metadata": {"privilege_escalation": True, "active_incident": True},
    })
    print(f"  Status Code        : {r_risky2.status_code}")
    print(f"  Rejection Notice   : {r_risky2.json().get('detail')}")
    assert r_risky2.status_code == 400

    r_status_d = CLIENT.get(f"/api/response/{inc_d}/approval-status")
    print(f"  Approval State     : {r_status_d.json().get('state')}")
    assert r_status_d.json().get("state") == "APPROVAL_BLOCKED"
    print(f"{BOLD}{GREEN}[PASS - DEMO D COMPLETE]{RESET} Containment held because Approver 2 was untrusted.")

    # =========================================================================
    # DEMO E: APPROVAL EXPIRATION (15-MINUTE WINDOW)
    # =========================================================================
    print_banner("DEMO E: 15-MINUTE APPROVAL EXPIRATION", YELLOW)
    print("Scenario: Approver 1 approves, but second approval is not completed within 15 minutes.")
    print("Expectation: Approval is EXPIRED. Execution is rejected; fresh approval required.")

    from app.api.dependencies import get_response_service
    resp_svc = get_response_service()

    user_e = f"sysadmin_e_{int(time.time())}"
    r_ingest_e = CLIENT.post("/api/events", json={
        "user_id": user_e,
        "session_id": "sess_crit_e_01",
        "agent_id": "copilot_agent",
        "tool_name": "raw_sql_exec",
        "event_type": "data_access",
        "resource": "/database/customer_vault",
        "metadata": {
            "ip": "185.220.101.9",
            "is_external_ip": True,
            "prompt_injection": True,
            "agent_privilege_abuse": True,
            "data_exfiltration": True,
        }
    })
    inc_e = r_ingest_e.json()["incident_id"]

    CLIENT.post(f"/api/response/{inc_e}/approve", json={
        "approver_id": "SOC_Analyst_Alice",
        "role": "SECURITY_ANALYST",
    })

    # Simulate expiration by rolling back expires_at past 15 minutes
    rec_e = resp_svc.get_approval_status(inc_e)
    rec_e.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    r_exp = CLIENT.post(f"/api/response/{inc_e}/second-approve", json={
        "approver_id": "SOC_Admin_Bob",
        "role": "SECURITY_ADMIN",
    })
    print(f"  Status Code        : {r_exp.status_code}")
    print(f"  Expiration Notice  : {r_exp.json().get('detail')}")
    assert r_exp.status_code == 400
    assert "Approval window has expired" in r_exp.json().get("detail", "")
    print(f"{BOLD}{GREEN}[PASS - DEMO E COMPLETE]{RESET} Expired approval safely blocked. Fresh authorization required.")

    print_banner("PS-08 STEP 5 DEMONSTRATION COMPLETE - ALL 5 SCENARIOS VERIFIED", GREEN)


if __name__ == "__main__":
    run_demo()
