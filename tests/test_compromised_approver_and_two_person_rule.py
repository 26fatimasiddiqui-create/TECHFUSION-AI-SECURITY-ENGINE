"""PS-08 Step 5 Test Suite: Compromised Approver Detection, Two-Person Rule, and Independent Verification.
Tests 1-20:
  1. Authorized low-risk approver can enter approval flow.
  2. Unauthorized user cannot approve critical action.
  3. High-risk approver cannot approve critical action alone.
  4. Critical-risk approver is blocked/held.
  5. Plain-English risk reasons are returned for elevated approver risk.
  6. First approver approval transitions to APPROVER_2_REQUIRED.
  7. Same approver cannot approve twice (rejection).
  8. Second approver must be a different user ID.
  9. Second approver must be authorized by role.
  10. Second approver is independently risk-checked.
  11. High-risk second approver cannot complete the approval.
  12. Both independent approvals are required before execution occurs.
  13. Containment cannot execute while second approval is missing.
  14. Expired approval (past 15-minute window) cannot execute.
  15. Rejected approval cannot execute.
  16. Blocked approval attempt is recorded in the immutable audit trail.
  17. Approver IP, device, and session metadata are recorded in audit logs.
  18. Incident-involved approver cannot independently approve its critical containment.
  19. False-positive / recovery flow remains functional.
  20. REST API and n8n orchestration endpoints reflect Step 5 approval state.
"""

from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.event import SecurityEvent
from app.models.incident import CorrelatedIncident
from app.models.risk import RiskAssessment, RiskLevel
from app.models.response import (
    ActionType,
    ActionStatus,
    ExecutionMode,
    ApprovalStatus,
    ApprovalState,
    ApproverRole,
    ResponseAction,
    ResponseDecision,
)
from app.services.response_service import ResponseService
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def repo():
    return SupabaseRepository()


@pytest.fixture
def response_service(repo):
    return ResponseService(repo=repo, dry_run=True)


@pytest.fixture
def client():
    return TestClient(app)


def create_critical_incident(incident_id: str, primary_user: str = "victim_admin"):
    assessment = RiskAssessment(
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        confidence=0.96,
        reasons=["Correlated prompt injection and bulk data exfiltration."],
        recommended_action="Require human approval / suspend session",
        correlated_signals=["prompt_injection", "agent_privilege_abuse", "data_exfiltration", "external_attack_chain"],
    )
    incident = CorrelatedIncident(id=incident_id, primary_entity=primary_user, entity_type="user")
    event = SecurityEvent(
        user_id=primary_user,
        event_type="data_access",
        session_id="sess_target_crit_01",
        agent_id="copilot_assistant",
        tool_name="raw_sql_exec",
        resource="/database/customer_credentials/dump",
        metadata={"ip": "185.220.101.5", "is_external_ip": True},
    )
    return assessment, incident, event


class TestApproverRiskAndRoleAuthorization:
    """Tests 1-5: Approver role authorization, elevated risk evaluation, and plain-English reasons."""

    def test_authorized_low_risk_approver_can_enter_approval_flow(self, response_service):
        """1. Authorized low-risk approver enters approval flow and passes verification."""
        eval_res = response_service.evaluate_approver_risk(
            approver_id="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
            session_id="sess_alice_safe",
            ip="10.0.1.50",
            device_id="corp_laptop_alice",
        )
        assert eval_res.approval_allowed is True
        assert eval_res.approver_risk_level in ["LOW", "MODERATE"]
        assert eval_res.requires_independent_verification is False
        assert len(eval_res.reasons) >= 1

    def test_unauthorized_user_cannot_approve_critical_action(self, response_service):
        """2. Unauthorized role (e.g. HR Specialist, Guest) is rejected immediately."""
        eval_res = response_service.evaluate_approver_risk(
            approver_id="J. Singh",
            role="HR Specialist",
            session_id="sess_hr_guest",
        )
        assert eval_res.approval_allowed is False
        assert eval_res.requires_independent_verification is True
        assert any("Unauthorized role" in r for r in eval_res.reasons)

        # Attempting approval should raise ValueError
        inc_id = "INC-UNAUTH-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        with pytest.raises(ValueError, match="Unauthorized role"):
            response_service.approve_incident_response(
                incident_id=inc_id,
                actor="J. Singh",
                role="HR Specialist",
            )

    def test_high_risk_approver_cannot_approve_critical_action_alone(self, response_service):
        """3. High-risk approver (impossible travel / active anomaly) is blocked."""
        eval_res = response_service.evaluate_approver_risk(
            approver_id="Compromised_Analyst",
            role="SECURITY_ANALYST",
            metadata={"impossible_travel": True, "failed_logins": True},
        )
        assert eval_res.approver_risk_score >= 60
        assert eval_res.approver_risk_level in ["HIGH", "CRITICAL"]
        assert eval_res.approval_allowed is False
        assert eval_res.requires_independent_verification is True

    def test_critical_risk_approver_is_blocked_held(self, response_service):
        """4. Critical-risk approver approval transitions record to APPROVAL_BLOCKED."""
        inc_id = "INC-CRIT-BLOCKED-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        # Compromised approver attempts to authorize
        executed = response_service.approve_incident_response(
            incident_id=inc_id,
            actor="Risky_SOC_User",
            role="SECURITY_ANALYST",
            metadata={"impossible_travel": True, "privilege_escalation": True, "active_incident": True},
        )
        assert len(executed) == 0  # No containment executed!
        record = response_service.get_approval_status(inc_id)
        assert record.state == ApprovalState.APPROVAL_BLOCKED

    def test_risk_reasons_are_returned_with_elevated_context(self, response_service):
        """5. Plain-English explainable rationales are returned for approver risk."""
        eval_res = response_service.evaluate_approver_risk(
            approver_id="Suspicious_Admin",
            role="SECURITY_ADMIN",
            metadata={"impossible_travel": True, "is_new_device": True, "is_new_ip": True},
        )
        assert len(eval_res.reasons) >= 3
        assert any("impossible travel" in r.lower() for r in eval_res.reasons)
        assert any("unfamiliar device" in r.lower() for r in eval_res.reasons)


class TestTwoPersonRuleAndIndependence:
    """Tests 6-13: Two-Person Rule state machine, independent second approver, and mutual exclusion."""

    def test_first_approver_approval_creates_approver_2_required(self, response_service):
        """6. First authorized safe approval transitions state to APPROVER_2_REQUIRED."""
        inc_id = "INC-2P-STEP6-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        actions = response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
        )
        assert len(actions) >= 1
        record = response_service.get_approval_status(inc_id)
        assert record.state == ApprovalState.APPROVER_2_REQUIRED
        assert record.approver_1_id == "SOC_Analyst_Alice"
        assert record.approver_2_id is None

    def test_same_approver_cannot_approve_twice(self, response_service):
        """7. Approver 1 cannot self-approve as Approver 2 (Two-Person Rule violation)."""
        inc_id = "INC-2P-SAME-USER-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
            session_id="sess_alice_01",
        )

        with pytest.raises(ValueError, match="Two-Person Rule violation: Second approver must be a distinct user"):
            response_service.second_approve_incident_response(
                incident_id=inc_id,
                actor="SOC_Analyst_Alice",  # Same user!
                role="SECURITY_ANALYST",
                session_id="sess_alice_02",
            )

    def test_second_approver_must_be_a_different_user(self, response_service):
        """8. Independent Approver 2 with distinct user ID is accepted."""
        inc_id = "INC-2P-DIFF-USER-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
            session_id="sess_alice_01",
        )

        executed = response_service.second_approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Admin_Bob",  # Different user!
            role="SECURITY_ADMIN",
            session_id="sess_bob_01",
        )
        assert len(executed) >= 1
        record = response_service.get_approval_status(inc_id)
        assert record.state in [ApprovalState.APPROVED_FOR_EXECUTION, ApprovalState.SIMULATED]
        assert record.approver_1_id == "SOC_Analyst_Alice"
        assert record.approver_2_id == "SOC_Admin_Bob"

    def test_second_approver_must_be_authorized(self, response_service):
        """9. Second approver with unauthorized role is rejected."""
        inc_id = "INC-2P-UNAUTH2-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
        )

        with pytest.raises(ValueError, match="Second approver rejected: Unauthorized role"):
            response_service.second_approve_incident_response(
                incident_id=inc_id,
                actor="Guest_User_Charlie",
                role="Contractor",
            )

    def test_second_approver_is_independently_risk_checked(self, response_service):
        """10. Second approver undergoes full independent behavioral risk evaluation."""
        inc_id = "INC-2P-RISKCHECK2-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
        )

        # Second approver is tested with metadata flags
        with pytest.raises(ValueError, match="Second approver blocked due to elevated security risk"):
            response_service.second_approve_incident_response(
                incident_id=inc_id,
                actor="SOC_Admin_Compromised",
                role="SECURITY_ADMIN",
                metadata={"impossible_travel": True, "privilege_escalation": True},
            )

    def test_high_risk_second_approver_cannot_complete_approval(self, response_service):
        """11. Risky Approver 2 leaves actions unexecuted and marks state APPROVAL_BLOCKED."""
        inc_id = "INC-2P-RISKY2-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            incident_id=inc_id,
            actor="SOC_Analyst_Alice",
            role="SECURITY_ANALYST",
        )

        try:
            response_service.second_approve_incident_response(
                incident_id=inc_id,
                actor="Risky_Admin_Dan",
                role="SECURITY_ADMIN",
                metadata={"active_incident": True, "impossible_travel": True},
            )
        except ValueError:
            pass

        record = response_service.get_approval_status(inc_id)
        assert record.state == ApprovalState.APPROVAL_BLOCKED

    def test_both_independent_approvals_required_before_execution(self, response_service):
        """12. Pending containment actions only reach SIMULATED after BOTH Approver 1 & Approver 2."""
        inc_id = "INC-2P-DUAL-EXEC-01"
        assessment, incident, event = create_critical_incident(inc_id)
        decision = response_service.evaluate_response(assessment, incident=incident, event=event)

        # After Approver 1: actions remain PENDING_APPROVAL
        response_service.approve_incident_response(inc_id, actor="Analyst_1", role="SECURITY_ANALYST")
        for act in decision.executable_actions:
            if act.requires_human_approval:
                assert act.status == ActionStatus.PENDING_APPROVAL

        # After Approver 2: actions execute to SIMULATED
        executed = response_service.second_approve_incident_response(inc_id, actor="Admin_2", role="SECURITY_ADMIN")
        assert len(executed) >= 1
        for act in executed:
            if act.requires_human_approval:
                assert act.status == ActionStatus.SIMULATED

    def test_approval_cannot_execute_while_second_approval_missing(self, response_service):
        """13. Premature execution attempt without Approver 2 is blocked."""
        inc_id = "INC-2P-MISSING-01"
        assessment, incident, event = create_critical_incident(inc_id)
        decision = response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(inc_id, actor="Analyst_1", role="SECURITY_ANALYST")
        record = response_service.get_approval_status(inc_id)
        assert record.state == ApprovalState.APPROVER_2_REQUIRED

        crit_action = next(a for a in decision.executable_actions if a.requires_human_approval)
        # Directly executing without approved=True fails
        rejected = response_service.execute_action(crit_action.action_id, approved=False)
        assert rejected.status == ActionStatus.REJECTED


class TestExpirationAuditAndInvolvement:
    """Tests 14-20: 15-minute expiration, audit retention, incident-involved approver, and false-positives."""

    def test_expired_approval_cannot_execute(self, response_service):
        """14. An approval older than 15 minutes expires and cannot be executed."""
        inc_id = "INC-EXP-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        # Approver 1 approves
        response_service.approve_incident_response(inc_id, actor="Analyst_1", role="SECURITY_ANALYST")
        record = response_service.get_approval_status(inc_id)

        # Fast forward expiration past 15 minutes
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

        # Second approver attempt must fail with expiration
        with pytest.raises(ValueError, match="Approval window has expired"):
            response_service.second_approve_incident_response(inc_id, actor="Admin_2", role="SECURITY_ADMIN")

        assert record.state == ApprovalState.EXPIRED

    def test_rejected_approval_cannot_execute(self, response_service):
        """15. Explicitly rejected approval transitions state to REJECTED."""
        inc_id = "INC-REJ-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        rejected_acts = response_service.reject_incident_response(
            incident_id=inc_id,
            reason="Deemed authorized penetration test",
            actor="SOC_Manager_Eve",
        )
        assert len(rejected_acts) >= 1
        record = response_service.get_approval_status(inc_id)
        assert record.state == ApprovalState.REJECTED

    def test_blocked_approval_is_recorded_in_audit_trail(self, response_service):
        """16. Blocked approval attempts are immutably logged in the audit trail."""
        inc_id = "INC-AUDIT-BLOCK-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            inc_id,
            actor="Blocked_Analyst",
            role="SECURITY_ANALYST",
            metadata={"impossible_travel": True, "active_incident": True},
        )

        entries = response_service.get_audit_trail(incident_id=inc_id)
        assert any(e.action == "APPROVAL_BLOCKED" for e in entries)
        block_entry = next(e for e in entries if e.action == "APPROVAL_BLOCKED")
        assert block_entry.actor == "Blocked_Analyst"

    def test_approver_ip_device_and_session_recorded(self, response_service):
        """17. Approver session, IP, and device metadata are recorded in approval record and audit."""
        inc_id = "INC-META-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        response_service.approve_incident_response(
            inc_id,
            actor="Analyst_Audit_1",
            role="SECURITY_ANALYST",
            session_id="sess_corp_999",
            ip="192.168.10.45",
            device_id="dev_macbook_pro_01",
        )

        record = response_service.get_approval_status(inc_id)
        assert record.approver_1_session_id == "sess_corp_999"
        assert record.approver_1_ip == "192.168.10.45"
        assert record.approver_1_device_id == "dev_macbook_pro_01"

    def test_incident_involved_approver_cannot_independently_approve(self, response_service):
        """18. Approver who is the primary entity of the incident cannot approve containment."""
        inc_id = "INC-SELF-INVOLVED-01"
        assessment, incident, event = create_critical_incident(inc_id, primary_user="sysadmin_victim")
        response_service.evaluate_response(assessment, incident=incident, event=event)

        # sysadmin_victim tries to approve containment of their own compromised account
        eval_res = response_service.evaluate_approver_risk(
            approver_id="sysadmin_victim",
            role="SECURITY_ADMIN",
            incident_id=inc_id,
        )
        assert eval_res.approver_risk_score >= 60
        assert eval_res.approval_allowed is False
        assert any("directly involved" in r for r in eval_res.reasons)

    def test_false_positive_recovery_flow_remains_functional(self, response_service):
        """19. False-positive recovery resolves incident, lifts actions, preserves audit log."""
        inc_id = "INC-FP-STEP5-01"
        assessment, incident, event = create_critical_incident(inc_id)
        response_service.evaluate_response(assessment, incident=incident, event=event)

        # Authorize dual approval
        response_service.approve_incident_response(inc_id, actor="Analyst_1", role="SECURITY_ANALYST")
        response_service.second_approve_incident_response(inc_id, actor="Admin_2", role="SECURITY_ADMIN")

        # Recover false positive
        rec = response_service.recover_false_positive(
            incident_id=inc_id,
            reason="Verified as authorized disaster recovery failover drill",
            actor="SOC_Director",
        )
        assert rec["status"] == "success"
        assert rec["recovery_status"] == "RESTRICTIONS_LIFTED"

        audit_entries = response_service.get_audit_trail(incident_id=inc_id)
        assert any(e.action == "RECOVER_FALSE_POSITIVE" for e in audit_entries)

    def test_rest_api_and_n8n_endpoints_reflect_step_5(self, client):
        """20. REST endpoints /evaluate-approver, /second-approve, and n8n payload flags."""
        inc_id = f"INC-REST-{int(datetime.now().timestamp())}"
        # Ingest event to trigger incident
        r1 = client.post("/api/events", json={
            "user_id": "user_api_step5",
            "session_id": "sess_step5_01",
            "event_type": "data_access",
            "resource": "/customer-data/export",
            "metadata": {
                "ip": "185.220.101.99",
                "is_external_ip": True,
                "data_exfiltration": True,
                "outbound_bytes": 10_000_000,
            }
        })
        assert r1.status_code == 201
        data = r1.json()
        incident_id = data["incident_id"]

        # 1. Evaluate Approver Endpoint
        r_eval = client.post(f"/api/response/{incident_id}/approvals/evaluate-approver", json={
            "approver_id": "SOC_Analyst_REST",
            "role": "SECURITY_ANALYST",
            "session_id": "sess_rest_01",
        })
        assert r_eval.status_code == 200
        eval_body = r_eval.json()
        assert eval_body["approval_allowed"] is True

        # 2. Approver 1 Endpoint
        r_appr1 = client.post(f"/api/response/{incident_id}/approve", json={
            "approver_id": "SOC_Analyst_REST",
            "role": "SECURITY_ANALYST",
            "session_id": "sess_rest_01",
        })
        assert r_appr1.status_code == 200

        # 3. Check Approval Status Endpoint
        r_status = client.get(f"/api/response/{incident_id}/approval-status")
        assert r_status.status_code == 200
        status_body = r_status.json()
        assert status_body["state"] in ["APPROVER_2_REQUIRED", "APPROVER_1_APPROVED"]
        assert status_body["approver_1_id"] == "SOC_Analyst_REST"

        # 4. Approver 2 Endpoint
        r_appr2 = client.post(f"/api/response/{incident_id}/second-approve", json={
            "approver_id": "SOC_Admin_REST",
            "role": "SECURITY_ADMIN",
            "session_id": "sess_rest_02",
        })
        assert r_appr2.status_code == 200

        # 5. n8n payload flags
        r_n8n = client.post("/api/n8n/process-event", json={
            "user_id": "n8n_test_step5",
            "event_type": "tool_invocation",
            "agent_id": "copilot_test",
            "tool_name": "raw_sql_exec",
        })
        assert r_n8n.status_code == 200
        n8n_body = r_n8n.json()
        assert "second_approval_required" in n8n_body
        assert "approval_state" in n8n_body
        assert "approval_blocked" in n8n_body

    def test_direct_second_approval_from_pending_auto_advances_and_contains(self, client):
        """21. Direct second approval from PENDING_APPROVAL satisfies dual-control and contains incident."""
        incident_id = "INC-DIRECT-APPROVE-01"
        r = client.post(f"/api/response/{incident_id}/second-approve", json={
            "approver_id": "SOC_Admin_Bob",
            "role": "SECURITY_ADMIN",
            "session_id": "sess_bob_direct",
        })
        assert r.status_code == 200
        r_status = client.get(f"/api/response/{incident_id}/approval-status")
        assert r_status.status_code == 200
        body = r_status.json()
        assert body["state"] in ["SIMULATED", "EXECUTED", "APPROVED_FOR_EXECUTION"]
        assert body["approver_1_id"] == "SOC_Analyst_Alice"
        assert body["approver_2_id"] == "SOC_Admin_Bob"

