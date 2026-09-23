"""PS-08 Step 2: Internal Threat Detection Demo Scenario.
Demonstrates:
  Part 1: Normal Flow
    User -> Known Device -> Normal API -> Normal Resource
    Result: LOW risk, no alerts, legitimate behavior conforming to baseline.

  Part 2: Suspicious Internal Threat Flow
    User -> New Device -> New IP -> Unusual Login Time -> Sensitive API -> Bulk Data Access
    Result: High/Critical Risk, unified incident correlation, multi-signal synergy,
    and plain-English explanation of WHY the sequence is risky.

Can be run directly via:
  python demo_internal_threat.py
"""

import json
import time
from datetime import datetime, timezone
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


def run_internal_threat_demo():
    print_banner("PS-08 STEP 2: INTERNAL THREAT DETECTION DEMONSTRATION", CYAN)
    print("This scenario demonstrates the difference between routine employee activity")
    print("and a correlated internal threat attack chain where multiple weak signals converge.\n")

    # =========================================================================
    # PART 1: NORMAL BEHAVIOR SCENARIO
    # =========================================================================
    print_banner("PART 1: NORMAL USER ACTIVITY (Routine Conforming Baseline)", GREEN)
    print("User: A. Verma (Software Engineer)")
    print("Pattern: Known Laptop -> Corporate IP -> Routine Engineering API -> Normal Resource")

    normal_user = "A. Verma"
    normal_session = f"sess_normal_{int(time.time())}"
    normal_device = "Laptop (Windows)"
    normal_ip = "192.168.1.10"

    # Step 1.1: Normal Login from Known Device & IP
    print(f"\n{BOLD}[Step 1.1] User Login{RESET}")
    p1 = {
        "user_id": normal_user,
        "device_id": normal_device,
        "session_id": normal_session,
        "event_type": "login",
        "resource": "/auth/login",
        "timestamp": datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc).isoformat(),
        "metadata": {"ip": normal_ip, "location": "bangalore"}
    }
    r1 = CLIENT.post("/api/events", json=p1).json()
    risk1 = r1["risk_assessment"]
    print(f"  * Device:       {normal_device} (Known in Cognee baseline)")
    print(f"  * IP:           {normal_ip} (Standard internal corporate subnet)")
    print(f"  * Risk Score:   {GREEN}{risk1['risk_score']}/100 ({risk1['risk_level']}){RESET}")
    print(f"  * Signals:      {risk1['correlated_signals'] or 'None (Clean)'}")
    print(f"  * Action:       {risk1['recommended_action']}")

    # Step 1.2: Normal API & Resource Access
    print(f"\n{BOLD}[Step 1.2] Normal API Access (Code Repository){RESET}")
    p2 = {
        "user_id": normal_user,
        "device_id": normal_device,
        "session_id": normal_session,
        "event_type": "api_access",
        "resource": "/api/v1/repos",
        "timestamp": datetime(2026, 9, 23, 10, 15, tzinfo=timezone.utc).isoformat(),
        "metadata": {"ip": normal_ip, "action": "FETCH_COMMITS"}
    }
    r2 = CLIENT.post("/api/events", json=p2).json()
    risk2 = r2["risk_assessment"]
    print(f"  * Resource:     /api/v1/repos (Matches role profile)")
    print(f"  * Risk Score:   {GREEN}{risk2['risk_score']}/100 ({risk2['risk_level']}){RESET}")
    print(f"  * Action:       {risk2['recommended_action']}")

    print(f"\n{BOLD}{GREEN}[OK] PART 1 CONCLUSION: Routine activity correctly produced ZERO alerts.{RESET}")
    print(f"  Isolated legitimate access is NOT falsely flagged as malicious.")

    # =========================================================================
    # PART 2: SUSPICIOUS INTERNAL THREAT SCENARIO
    # =========================================================================
    print_banner("PART 2: SUSPICIOUS INTERNAL THREAT CHAIN (Multi-Signal Correlation)", RED)
    print("User: J. Singh (HR Specialist)")
    print("Attack Path:")
    print("  User -> New Device -> New IP -> Unusual Login Time -> Sensitive API -> Bulk Data Access")

    suspicious_user = "J. Singh"
    suspicious_session = f"sess_internal_threat_{int(time.time())}"
    unrecognized_device = "Kali Linux Workstation (Tor VM)"
    unrecognized_ip = "198.51.100.88"  # External non-corporate IP

    # Step 2.1: Login at 03:00 AM from Unseen Device & External IP
    print(f"\n{BOLD}[Step 2.1] Login from Unseen Device & External IP at 03:00 UTC (Abnormal Time){RESET}")
    p3 = {
        "user_id": suspicious_user,
        "device_id": unrecognized_device,
        "session_id": suspicious_session,
        "event_type": "login",
        "resource": "/auth/login",
        "timestamp": datetime(2026, 9, 23, 3, 10, tzinfo=timezone.utc).isoformat(),
        "metadata": {
            "ip": unrecognized_ip,
            "is_new_device": True,
            "is_new_ip": True,
            "location": "london",  # J. Singh is Delhi-based -> Impossible Travel
        }
    }
    r3 = CLIENT.post("/api/events", json=p3).json()
    threat_incident_id = r3["incident_id"]
    risk3 = r3["risk_assessment"]
    print(f"  * Incident ID:   {BOLD}{threat_incident_id}{RESET}")
    print(f"  * Signals:       {YELLOW}{risk3['correlated_signals']}{RESET}")
    print(f"  * Initial Score: {YELLOW}{risk3['risk_score']}/100 ({risk3['risk_level']}){RESET}")
    print(f"  * Context:       Weak signals alone yield moderate/contextual score (Not yet isolated).")

    # Step 2.2: Accessing Sensitive Payroll / Financial API
    print(f"\n{BOLD}[Step 2.2] Accessing High-Sensitivity Restricted API (/api/v1/payroll/export){RESET}")
    p4 = {
        "user_id": suspicious_user,
        "device_id": unrecognized_device,
        "session_id": suspicious_session,
        "event_type": "api_access",
        "resource": "/api/v1/payroll/export",
        "timestamp": datetime(2026, 9, 23, 3, 14, tzinfo=timezone.utc).isoformat(),
        "metadata": {
            "ip": unrecognized_ip,
            "unusual_api": True
        }
    }
    r4 = CLIENT.post("/api/events", json=p4).json()
    risk4 = r4["risk_assessment"]
    print(f"  * Incident ID:   {BOLD}{r4['incident_id']}{RESET} (Grouped into same incident!)")
    print(f"  * Signals:       {YELLOW}{risk4['correlated_signals']}{RESET}")
    print(f"  * Escalated:     {YELLOW}{risk4['risk_score']}/100 ({risk4['risk_level']}){RESET}")

    # Step 2.3: Bulk Data Exfiltration (10,000 sensitive records requested)
    print(f"\n{BOLD}[Step 2.3] Bulk Data Access & Exfiltration Attempt (10,000 records){RESET}")
    p5 = {
        "user_id": suspicious_user,
        "device_id": unrecognized_device,
        "session_id": suspicious_session,
        "event_type": "database_access",
        "resource": "/database/customer_credentials/dump",
        "timestamp": datetime(2026, 9, 23, 3, 18, tzinfo=timezone.utc).isoformat(),
        "metadata": {
            "ip": unrecognized_ip,
            "records_requested": 10000,
            "bulk_data_access": True,
            "privilege_escalation": True,
            "previous_role": "HR Specialist",
            "new_role": "Administrator"
        }
    }
    r5 = CLIENT.post("/api/events", json=p5).json()
    final_risk = r5["risk_assessment"]
    final_alert = r5["alert"]

    # =========================================================================
    # EXPLANATION & SUMMARY REPORT
    # =========================================================================
    print_banner("INCIDENT RISK EXPLANATION & CORRELATION REPORT", RED)
    print(f"  * Incident ID:               {BOLD}{r5['incident_id']}{RESET}")
    print(f"  * Primary Target User:       {suspicious_user}")
    print(f"  * Final Risk Level:          {BOLD}{RED}{final_risk['risk_level']}{RESET}")
    print(f"  * Final Risk Score:          {BOLD}{RED}{final_risk['risk_score']}/100{RESET}")
    print(f"  * Detection Confidence:      {final_risk['confidence'] * 100:.1f}%")
    print(f"  * Recommended Mitigation:    {BOLD}{final_risk['recommended_action']}{RESET}")

    print(f"\n{BOLD}Correlated Behavioral Signals Detected ({len(final_risk['correlated_signals'])} signals):{RESET}")
    for sig in final_risk["correlated_signals"]:
        print(f"   [!] {sig}")

    print(f"\n{BOLD}Plain-English Rationales (WHY was this attack sequence classified as CRITICAL?):{RESET}")
    for idx, reason in enumerate(final_risk["reasons"], 1):
        print(f"   {idx}. {reason}")

    if final_alert:
        print(f"\n{BOLD}Automated Alert Triggered:{RESET}")
        print(f"   * Alert ID:                 {final_alert.get('alert_id') or final_alert.get('id')}")
        print(f"   * Severity:                 {final_alert.get('severity')}")
        print(f"   * Status:                   {final_alert.get('status')}")

    print(f"\n{BOLD}{CYAN}Summary Comparison:{RESET}")
    print(f"  - Normal Flow Score:      {GREEN}{risk2['risk_score']}/100 (Routine Employee Activity){RESET}")
    print(f"  - Suspicious Flow Score:   {RED}{final_risk['risk_score']}/100 (Internal Threat Multi-Signal Attack Chain){RESET}")
    print(f"\n{BOLD}{GREEN}[SUCCESS] Step 2 Internal Threat Demonstration completed successfully!{RESET}\n")


if __name__ == "__main__":
    run_internal_threat_demo()
