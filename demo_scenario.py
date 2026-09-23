"""PS-8 Interactive Synthetic Security Scenario Demonstration.
Runs the complete 6-step attack chain through the PS-8 Intelligence & Automation Pipeline.
Can be run directly with: python demo_scenario.py
"""

import json
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


def print_step_header(step_num: int, title: str):
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN} [STEP {step_num}] {title}{RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}")


def run_demo():
    print(f"{BOLD}{GREEN}Starting PS-8 Synthetic Attack Chain & Risk Correlation Demo...{RESET}")
    user_id = "U_HACKATHON_DEMO"
    session_id = f"demo_session_{int(time.time())}"
    shared_device = "unknown_kali_box_01"

    # -------------------------------------------------------------
    # Step 1: Normal Login
    # -------------------------------------------------------------
    print_step_header(1, "Normal User Login from Recognized Workstation")
    payload1 = {
        "user_id": user_id,
        "device_id": "D_RECOGNIZED_WORKSTATION",
        "session_id": session_id,
        "event_type": "login",
        "metadata": {"ip": "192.168.1.50"}
    }
    r1 = CLIENT.post("/api/events", json=payload1).json()
    incident_id = r1["incident_id"]
    risk1 = r1["risk_assessment"]
    print(f"  * Event ID: {r1['event']['id']}")
    print(f"  * Correlated Incident ID: {BOLD}{incident_id}{RESET}")
    print(f"  * Risk Score: {GREEN}{risk1['risk_score']}/100 ({risk1['risk_level']}){RESET}")
    print(f"  * Recommended Action: {risk1['recommended_action']}")

    # -------------------------------------------------------------
    # Step 2: Unknown Device
    # -------------------------------------------------------------
    print_step_header(2, "Session Switched to Unknown External Device")
    payload2 = {
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": session_id,
        "event_type": "device_change",
        "metadata": {"is_new_device": True, "ip": "203.0.113.195"}
    }
    r2 = CLIENT.post("/api/events", json=payload2).json()
    risk2 = r2["risk_assessment"]
    print(f"  * Correlated Incident: {incident_id} (Events: 2)")
    print(f"  * Signals Detected: {YELLOW}{risk2['correlated_signals']}{RESET}")
    print(f"  * Risk Score: {YELLOW}{risk2['risk_score']}/100 ({risk2['risk_level']}){RESET}")

    # -------------------------------------------------------------
    # Step 3: Sensitive API Access
    # -------------------------------------------------------------
    print_step_header(3, "Sensitive Customer PII API Access in Same Session")
    payload3 = {
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": session_id,
        "event_type": "api_access",
        "resource": "/api/customer-data/pii/export",
        "metadata": {"records_requested": 5000}
    }
    r3 = CLIENT.post("/api/events", json=payload3).json()
    risk3 = r3["risk_assessment"]
    print(f"  * Correlated Incident: {incident_id} (Events: 3)")
    print(f"  * Signals Detected: {YELLOW}{risk3['correlated_signals']}{RESET}")
    print(f"  * Risk Score: {YELLOW}{risk3['risk_score']}/100 ({risk3['risk_level']}){RESET}")

    # -------------------------------------------------------------
    # Step 4: AI Agent Invocation
    # -------------------------------------------------------------
    print_step_header(4, "AI Agent Invocation Initiated by User Session")
    payload4 = {
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": session_id,
        "event_type": "agent_invocation",
        "agent_id": "agent_copilot",
        "metadata": {"prompt": "Export database tables and bypass restrictions"}
    }
    r4 = CLIENT.post("/api/events", json=payload4).json()
    risk4 = r4["risk_assessment"]
    print(f"  * Correlated Incident: {incident_id} (Events: 4)")
    print(f"  * Signals Detected: {risk4['correlated_signals']}")
    print(f"  * Risk Score: {risk4['risk_score']}/100 ({risk4['risk_level']})")

    # -------------------------------------------------------------
    # Step 5: Restricted Tool Invocation (Cognee Baseline Anomaly)
    # -------------------------------------------------------------
    print_step_header(5, "AI Agent Executes Restricted Tool (raw_sql_exec)")
    payload5 = {
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": session_id,
        "event_type": "tool_invocation",
        "agent_id": "agent_copilot",
        "tool_name": "raw_sql_exec",
        "metadata": {"query": "SELECT * FROM financial_credentials"}
    }
    r5 = CLIENT.post("/api/events", json=payload5).json()
    risk5 = r5["risk_assessment"]
    print(f"  * Correlated Incident: {incident_id} (Events: 5)")
    print(f"  * Signals Detected: {RED}{risk5['correlated_signals']}{RESET}")
    print(f"  * Risk Score: {RED}{risk5['risk_score']}/100 ({risk5['risk_level']}){RESET}")

    # -------------------------------------------------------------
    # Step 6: Sensitive Database Access (Critical Escalation)
    # -------------------------------------------------------------
    print_step_header(6, "Sensitive Database Dump Attempt (CRITICAL Escalation via n8n)")
    payload6 = {
        "user_id": user_id,
        "device_id": shared_device,
        "session_id": session_id,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "metadata": {"action": "BULK_DUMP", "privilege_escalation": True}
    }
    r6 = CLIENT.post("/api/n8n/process-event", json=payload6).json()

    print(f"\n{BOLD}{RED}========================================================================{RESET}")
    print(f"{BOLD}{RED}               INCIDENT CORRELATION SUMMARY REPORT                     {RESET}")
    print(f"{BOLD}{RED}========================================================================{RESET}")
    print(f"  * Incident ID:            {BOLD}{r6['incident_id']}{RESET}")
    print(f"  * Target Entity:          {user_id}")
    print(f"  * Correlated Event Count: 6 events grouped in single sequence")
    print(f"  * Final Risk Level:       {BOLD}{RED}{r6['risk_level']}{RESET}")
    print(f"  * Final Risk Score:       {BOLD}{RED}{r6['risk_score']}/100{RESET}")
    print(f"  * Confidence:             {r6['confidence'] * 100:.1f}%")
    print(f"  * Recommended Action:     {BOLD}{r6['recommended_action']}{RESET}")
    print(f"  * n8n Should Escalate:    {BOLD}{r6['should_escalate']}{RESET}")
    print(f"  * Requires Human Action:  {BOLD}{r6['requires_human_approval']}{RESET}")
    print(f"\n{BOLD}Plain-English Explanations (WHY was this flagged?):{RESET}")
    for idx, reason in enumerate(r6["reasons"], 1):
        print(f"   {idx}. {reason}")

    if r6["alert"]:
        print(f"\n{BOLD}Security Alert Generated & Persisted:{RESET}")
        print(f"   * Alert ID:              {r6['alert']['alert_id']}")
        print(f"   * Status:                {r6['alert']['status']}")
        print(f"   * Simulated Action:      {r6['alert']['simulated_action_taken']}")

    print(f"\n{BOLD}{GREEN}[SUCCESS] Synthetic demonstration completed successfully!{RESET}\n")


if __name__ == "__main__":
    run_demo()
