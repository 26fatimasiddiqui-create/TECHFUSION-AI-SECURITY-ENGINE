import pytest
from datetime import datetime, timezone
from starlette.testclient import TestClient

from app.main import app
from app.models.event import SecurityEvent, EventType
from app.models.risk import RiskAssessment, RiskLevel
from app.models.incident import CorrelatedIncident
from app.models.response import (
    ActionType,
    ActionStatus,
    ExecutionMode,
    ApprovalStatus,
    ResponseAction,
    ResponseDecision,
)
from app.services.response_service import ResponseService
from app.repositories.supabase_repository import SupabaseRepository


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def repo():
    return SupabaseRepository()


@pytest.fixture
def response_service(repo):
    return ResponseService(repo=repo, dry_run=True)


class TestRiskAdaptivePolicyEvaluation:
    """Tests 1-6: Validates that response policies adapt appropriately to risk levels."""

    def test_low_risk_recommends_passive_monitoring_only(self, response_service):
        assessment = RiskAssessment(
            risk_score=15,
            risk_level=RiskLevel.LOW,
            confidence=0.85,
            reasons=["Standard activity conforming to security baseline."],
            recommended_action="Continue monitoring",
            correlated_signals=[],
        )
        incident = CorrelatedIncident(
            primary_entity="user_alice",
            entity_type="user",
        )
        decision = response_service.evaluate_response(assessment, incident=incident)

        assert decision.response_level == "LOW"
        assert decision.requires_human_approval is False
        assert decision.approval_required is False
        assert "MONITOR" in decision.recommended_actions
        assert not any(a in decision.recommended_actions for a in ["RESTRICT_SESSION", "BLOCK_SOURCE", "CONTAIN_AGENT"])

    def test_moderate_risk_recommends_rate_limiting_and_monitoring(self, response_service):
        assessment = RiskAssessment(
            risk_score=45,
            risk_level=RiskLevel.MODERATE,
            confidence=0.88,
            reasons=["Unusual API consumption pattern."],
            recommended_action="Increase monitoring",
            correlated_signals=["unusual_api_activity", "api_abuse"],
        )
        event = SecurityEvent(
            user_id="user_bob",
            event_type="api_access",
            resource="/api/v1/metrics/export",
        )
        decision = response_service.evaluate_response(assessment, event=event)

        assert decision.response_level == "MODERATE"
        assert decision.requires_human_approval is False
        assert "RATE_LIMIT" in decision.recommended_actions
        assert "ALERT" in decision.recommended_actions

    def test_high_risk_recommends_step_up_auth_and_api_restriction(self, response_service):
        assessment = RiskAssessment(
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            confidence=0.92,
            reasons=["Correlated credential anomaly and sensitive endpoint access."],
            recommended_action="Require verification / restrict sensitive access",
            correlated_signals=["new_device", "new_ip", "sensitive_resource"],
        )
        event = SecurityEvent(
            user_id="user_charlie",
            session_id="sess_charlie_01",
            event_type="api_access",
            resource="/api/v1/payroll",
        )
        decision = response_service.evaluate_response(assessment, event=event)

        assert decision.response_level == "HIGH"
        assert decision.requires_human_approval is False
        assert "STEP_UP_AUTH" in decision.recommended_actions
        assert "RESTRICT_API" in decision.recommended_actions

    def test_critical_risk_recommends_containment_and_requires_approval(self, response_service):
        assessment = RiskAssessment(
            risk_score=95,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.96,
            reasons=["Prompt injection followed by privileged tool execution and data exfiltration."],
            recommended_action="Require human approval / suspend or isolate the affected action",
            correlated_signals=["prompt_injection", "agent_privilege_abuse", "data_exfiltration", "external_attack_chain"],
        )
        event = SecurityEvent(
            user_id="user_victim",
            event_type="api_access",
            session_id="sess_compromised_99",
            agent_id="copilot_assistant",
            tool_name="raw_sql_exec",
            resource="/database/credentials/dump",
            metadata={"ip": "198.51.100.99"},
        )
        decision = response_service.evaluate_response(assessment, event=event)

        assert decision.response_level == "CRITICAL"
        assert decision.requires_human_approval is True
        assert decision.approval_required is True
        assert decision.action_status == "PENDING_APPROVAL"
        assert "REQUIRE_APPROVAL" in decision.recommended_actions
        assert "CONTAIN_AGENT" in decision.recommended_actions
        assert "RESTRICT_SESSION" in decision.recommended_actions

    def test_critical_action_enforces_human_approval_gate(self, response_service):
        assessment = RiskAssessment(
            risk_score=90,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["High-confidence attack chain."],
            recommended_action="Require human approval",
            correlated_signals=["brute_force_login", "data_exfiltration"],
        )
        event = SecurityEvent(
            user_id="target_admin",
            event_type="login",
            session_id="sess_admin_critical",
            metadata={"ip": "185.220.101.5"},
        )
        decision = response_service.evaluate_response(assessment, event=event)
        session_action = next(a for a in decision.executable_actions if a.action_type == ActionType.RESTRICT_SESSION)
        assert session_action.requires_human_approval is True
        assert session_action.status == ActionStatus.PENDING_APPROVAL

        # If executed with approved=False, it must be rejected
        rejected_action = response_service.execute_action(session_action.action_id, approved=False)
        assert rejected_action.status == ActionStatus.REJECTED
        assert rejected_action.approval_status == ApprovalStatus.REJECTED

    def test_low_risk_action_does_not_require_human_approval(self, response_service):
        assessment = RiskAssessment(
            risk_score=10,
            risk_level=RiskLevel.LOW,
            confidence=0.85,
            reasons=["Clean baseline."],
            recommended_action="Continue monitoring",
            correlated_signals=[],
        )
        decision = response_service.evaluate_response(assessment)
        monitor_action = decision.executable_actions[0]
        assert monitor_action.requires_human_approval is False
        assert monitor_action.approval_status == ApprovalStatus.NOT_REQUIRED


class TestSimulationAndTargetBinding:
    """Tests 7-14: Simulation safety, target validation, and evidence controls."""

    def test_dry_run_mode_marks_action_as_simulated(self, response_service):
        action = ResponseAction(
            action_type=ActionType.BLOCK_SOURCE,
            target="198.51.100.99",
            target_type="ip",
            reason="Corroborated external attack.",
            risk_score=85,
            severity="CRITICAL",
            requires_human_approval=True,
        )
        response_service._actions[action.action_id] = action

        executed = response_service.execute_action(action.action_id, approved=True, dry_run=True)
        assert executed.status == ActionStatus.SIMULATED
        assert executed.execution_mode == ExecutionMode.SIMULATED
        assert "SIMULATED ACTION" in executed.details["simulation_notice"]

    def test_session_restriction_targets_correct_session_id(self, response_service):
        assessment = RiskAssessment(
            risk_score=85,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["Session takeover."],
            recommended_action="Suspend session",
            correlated_signals=["suspicious_session_behavior"],
        )
        event = SecurityEvent(
            user_id="victim_alice",
            event_type="login",
            session_id="target_session_xyz_789",
        )
        decision = response_service.evaluate_response(assessment, event=event)
        session_action = next(a for a in decision.executable_actions if a.action_type == ActionType.RESTRICT_SESSION)
        assert session_action.target == "target_session_xyz_789"
        assert session_action.target_type == "session"

    def test_api_restriction_targets_correct_api_endpoint(self, response_service):
        assessment = RiskAssessment(
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            confidence=0.90,
            reasons=["Unusual API consumption."],
            recommended_action="Restrict endpoint",
            correlated_signals=["unusual_api_activity"],
        )
        event = SecurityEvent(
            user_id="api_caller",
            event_type="api_access",
            resource="/api/v1/customer_records/export",
        )
        decision = response_service.evaluate_response(assessment, event=event)
        api_action = next(a for a in decision.executable_actions if a.action_type == ActionType.RESTRICT_API)
        assert api_action.target == "/api/v1/customer_records/export"
        assert api_action.target_type == "api"

    def test_agent_containment_targets_correct_agent_id(self, response_service):
        assessment = RiskAssessment(
            risk_score=88,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["AI Agent abused via prompt injection."],
            recommended_action="Contain agent",
            correlated_signals=["prompt_injection", "agent_privilege_abuse"],
        )
        event = SecurityEvent(
            user_id="external_attacker",
            event_type="agent_invocation",
            agent_id="finance_copilot_v2",
            tool_name="raw_sql_exec",
        )
        decision = response_service.evaluate_response(assessment, event=event)
        agent_action = next(a for a in decision.executable_actions if a.action_type == ActionType.CONTAIN_AGENT)
        assert agent_action.target == "finance_copilot_v2"
        assert agent_action.target_type == "agent"
        assert "raw_sql_exec" in agent_action.details["restricted_tools"]

    def test_unfamiliar_ip_alone_does_not_trigger_source_blocking(self, response_service):
        """CRITICAL Safeguard: Unfamiliar external IP must NEVER be blocked on its own."""
        assessment = RiskAssessment(
            risk_score=10,
            risk_level=RiskLevel.LOW,
            confidence=0.85,
            reasons=["Connection from unseen IP address."],
            recommended_action="Continue monitoring",
            correlated_signals=["new_ip"],
        )
        event = SecurityEvent(
            user_id="user_dan",
            event_type="login",
            metadata={"ip": "203.0.113.88", "is_new_ip": True},
        )
        decision = response_service.evaluate_response(assessment, event=event)
        assert not any(a.action_type == ActionType.BLOCK_SOURCE for a in decision.executable_actions)

    def test_source_blocking_requires_corroborated_attack_evidence(self, response_service):
        """BLOCK_SOURCE is only formulated when IP is corroborated with multi-signal attack chain."""
        assessment = RiskAssessment(
            risk_score=92,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.96,
            reasons=["Brute force and data exfiltration from external IP."],
            recommended_action="Block source",
            correlated_signals=["brute_force_login", "suspicious_external_ip", "data_exfiltration", "external_attack_chain"],
        )
        event = SecurityEvent(
            user_id="victim_user",
            event_type="data_access",
            metadata={"ip": "198.51.100.99"},
        )
        decision = response_service.evaluate_response(assessment, event=event)
        block_action = next((a for a in decision.executable_actions if a.action_type == ActionType.BLOCK_SOURCE), None)
        assert block_action is not None
        assert block_action.target == "198.51.100.99"
        assert block_action.requires_human_approval is True


class TestAuditAndRecoveryWorkflow:
    """Tests 15-17: Audit trail persistence, approval workflow, and false-positive recovery."""

    def test_audit_trail_recorded_for_all_response_events(self, response_service):
        incident_id = "INC-AUDIT-TEST-01"
        assessment = RiskAssessment(
            risk_score=85,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["Critical risk sequence."],
            recommended_action="Contain incident",
            correlated_signals=["data_exfiltration"],
        )
        incident = CorrelatedIncident(id=incident_id, primary_entity="user_test", entity_type="user")
        response_service.evaluate_response(assessment, incident=incident)

        entries = response_service.get_audit_trail(incident_id=incident_id)
        assert len(entries) >= 1
        assert entries[0].incident_id == incident_id

    def test_approve_incident_response_workflow(self, response_service):
        incident_id = "INC-APPROVE-TEST-01"
        assessment = RiskAssessment(
            risk_score=90,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["Privilege abuse."],
            recommended_action="Require approval",
            correlated_signals=["agent_privilege_abuse"],
        )
        incident = CorrelatedIncident(id=incident_id, primary_entity="user_test", entity_type="user")
        event = SecurityEvent(user_id="user_test", event_type="login", session_id="sess_approve_01")
        response_service.evaluate_response(assessment, incident=incident, event=event)

        # Approve containment
        executed = response_service.approve_incident_response(incident_id, actor="LeadSecAnalyst")
        assert len(executed) >= 1
        assert any(a.approval_status == ApprovalStatus.APPROVED for a in executed)

        audit_entries = response_service.get_audit_trail(incident_id=incident_id)
        assert any(e.action == "APPROVE_CONTAINMENT" for e in audit_entries)

    def test_false_positive_recovery_workflow(self, response_service):
        incident_id = "INC-FP-TEST-01"
        assessment = RiskAssessment(
            risk_score=88,
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            reasons=["Triggered anomaly."],
            recommended_action="Require approval",
            correlated_signals=["bulk_data_access"],
        )
        incident = CorrelatedIncident(id=incident_id, primary_entity="dev_lead", entity_type="user")
        response_service.evaluate_response(assessment, incident=incident)

        # Analyst acknowledges false positive
        rec = response_service.recover_false_positive(
            incident_id=incident_id,
            reason="Verified as legitimate quarterly data backup approved by CIO",
            actor="SeniorAnalyst",
        )
        assert rec["status"] == "success"
        assert rec["recovery_status"] == "RESTRICTIONS_LIFTED"

        # Verify historical audit trail was NOT deleted
        audit_entries = response_service.get_audit_trail(incident_id=incident_id)
        assert len(audit_entries) >= 2
        assert any(e.action == "RECOVER_FALSE_POSITIVE" for e in audit_entries)


class TestApiIntegrationAndN8n:
    """Tests 18-21: REST endpoints and n8n orchestration response flags."""

    def test_rest_api_response_endpoints(self, client):
        # 1. Ingest critical event
        user_id = f"U_RESP_TEST_{int(datetime.now().timestamp())}"
        r1 = client.post("/api/events", json={
            "user_id": user_id,
            "session_id": "sess_resp_api_01",
            "event_type": "data_access",
            "resource": "/customer-data/pii/export",
            "metadata": {
                "ip": "198.51.100.99",
                "data_exfiltration": True,
                "outbound_bytes": 1_000_000,
            }
        })
        assert r1.status_code == 201
        data = r1.json()
        incident_id = data["incident_id"]
        assert "response_decision" in data
        assert data["response_decision"]["response_level"] in ["HIGH", "CRITICAL"]

        # 2. Query response status endpoint
        r2 = client.get(f"/api/response/{incident_id}")
        assert r2.status_code == 200
        summary = r2.json()
        assert summary["incident_id"] == incident_id
        assert summary["decision"] is not None

        # 3. Approve containment
        r3 = client.post(f"/api/response/{incident_id}/approve", json={
            "actor": "SOC_Analyst_1",
            "dry_run": True,
        })
        assert r3.status_code == 200

        # 4. Recover false positive
        r4 = client.post(f"/api/response/{incident_id}/recover", json={
            "actor": "SOC_Manager",
            "reason": "Approved load test simulation",
        })
        assert r4.status_code == 200
        assert r4.json()["recovery_status"] == "RESTRICTIONS_LIFTED"

    def test_n8n_process_event_includes_response_flags(self, client):
        r = client.post("/api/n8n/process-event", json={
            "user_id": "n8n_test_user",
            "session_id": "sess_n8n_01",
            "event_type": "tool_invocation",
            "agent_id": "copilot_agent",
            "tool_name": "raw_sql_exec",
            "resource": "/database/sensitive",
        })
        assert r.status_code == 200
        res = r.json()
        # Verify backward compatible fields
        assert "should_escalate" in res
        assert "requires_human_approval" in res
        # Verify new Step 4 response fields
        assert "response_level" in res
        assert "recommended_actions" in res
        assert "executable_actions" in res
        assert "dry_run" in res
        assert "approval_required" in res
        assert "action_status" in res
