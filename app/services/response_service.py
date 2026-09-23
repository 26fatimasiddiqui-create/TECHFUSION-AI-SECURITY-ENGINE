from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
from app.models.risk import RiskAssessment, RiskLevel
from app.models.incident import CorrelatedIncident
from app.models.event import SecurityEvent
from app.models.response import (
    ActionType,
    ActionStatus,
    ExecutionMode,
    ApprovalStatus,
    ResponseAction,
    ResponseDecision,
    AuditEntry,
    ApprovalState,
    ApproverRole,
    ApproverRiskEvaluation,
    ApprovalRecord,
)
from app.repositories.supabase_repository import SupabaseRepository

logger = logging.getLogger(__name__)


class ResponseService:
    """Centralized Risk-Adaptive Response & Containment Decision Engine.
    Evaluates existing risk scores, severity levels, detected signals, and entity contexts
    to formulate target-bound response actions with human-approval gating, safe dry-run
    simulation mode, full audit trails, and false-positive recovery.
    """

    def __init__(self, repo: Optional[SupabaseRepository] = None, dry_run: bool = True):
        self.repo = repo or SupabaseRepository()
        self.dry_run = dry_run
        # Memory storage: incident_id -> ResponseDecision
        self._decisions: Dict[str, ResponseDecision] = {}
        # Memory storage: action_id -> ResponseAction
        self._actions: Dict[str, ResponseAction] = {}
        # Memory storage: incident_id -> ApprovalRecord (Step 5 Two-Person Rule)
        self._approval_records: Dict[str, ApprovalRecord] = {}

    def evaluate_response(
        self,
        risk_assessment: RiskAssessment,
        incident: Optional[CorrelatedIncident] = None,
        event: Optional[SecurityEvent] = None,
        dry_run: Optional[bool] = None,
    ) -> ResponseDecision:
        """Centralized risk-based response policy evaluator.
        Does NOT calculate risk; receives existing assessment and formulates actions.
        """
        is_dry_run = self.dry_run if dry_run is None else dry_run
        score = risk_assessment.risk_score
        level_str = (
            risk_assessment.risk_level.value
            if hasattr(risk_assessment.risk_level, "value")
            else str(risk_assessment.risk_level)
        ).upper()

        signals = set(risk_assessment.correlated_signals)
        incident_id = incident.id if incident else None
        event_id = event.id if event else None

        # Extract real target entities from event and incident (no invented targets)
        user_id = (event.user_id if event else None) or (incident.primary_entity if incident and incident.entity_type == "user" else None)
        session_id = (event.session_id if event else None)
        agent_id = (event.agent_id if event else None)
        tool_name = (event.tool_name if event else None)
        resource = (event.resource if event else None)

        meta = (event.metadata if event else {}) or {}
        ip_val = meta.get("ip") or meta.get("client_ip") or meta.get("external_ip")
        if not ip_val and incident:
            for e in incident.events:
                e_ip = e.metadata.get("ip") or e.metadata.get("client_ip") or e.metadata.get("external_ip")
                if e_ip:
                    ip_val = e_ip
                    break

        if not session_id and incident:
            for e in incident.events:
                if e.session_id:
                    session_id = e.session_id
                    break

        if not agent_id and incident:
            for e in incident.events:
                if e.agent_id:
                    agent_id = e.agent_id
                    break

        if not tool_name and incident:
            for e in incident.events:
                if e.tool_name:
                    tool_name = e.tool_name
                    break

        if not resource and incident:
            for e in incident.events:
                if e.resource:
                    resource = e.resource
                    break

        actions: List[ResponseAction] = []
        requires_approval = False
        action_status_str = "MONITORING"

        # =====================================================================
        # CENTRAL RISK-BASED POLICY EVALUATION
        # =====================================================================

        if level_str == "LOW" or score < 30:
            response_level = "LOW"
            action_status_str = "MONITORING"
            requires_approval = False

            target_val = user_id or (f"ip:{ip_val}" if ip_val else "system")
            actions.append(
                ResponseAction(
                    action_type=ActionType.MONITOR,
                    target=target_val,
                    target_type="user" if user_id else "ip",
                    reason="Standard passive telemetry monitoring. Activity conforms to contextual baseline.",
                    risk_score=score,
                    severity="LOW",
                    status=ActionStatus.EXECUTED if not is_dry_run else ActionStatus.SIMULATED,
                    execution_mode=ExecutionMode.LIVE if not is_dry_run else ExecutionMode.SIMULATED,
                    requires_human_approval=False,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    incident_id=incident_id,
                    event_id=event_id,
                    details={"mode": "passive_telemetry"},
                )
            )

        elif level_str == "MODERATE" or (30 <= score < 60):
            response_level = "MODERATE"
            action_status_str = "SIMULATED" if is_dry_run else "EXECUTED"
            requires_approval = False

            actions.append(
                ResponseAction(
                    action_type=ActionType.MONITOR,
                    target=user_id or "system",
                    target_type="user",
                    reason="Increase monitoring window and lower anomaly detection thresholds.",
                    risk_score=score,
                    severity="MODERATE",
                    status=ActionStatus.EXECUTED if not is_dry_run else ActionStatus.SIMULATED,
                    execution_mode=ExecutionMode.LIVE if not is_dry_run else ExecutionMode.SIMULATED,
                    requires_human_approval=False,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    incident_id=incident_id,
                    event_id=event_id,
                )
            )

            # Apply Rate Limiting if API abuse or unusual API volume detected
            if any(s in signals for s in ["api_abuse", "unusual_api_activity", "unusual_api_access", "bot_automated_behavior"]):
                api_target = resource or "/api"
                actions.append(
                    ResponseAction(
                        action_type=ActionType.RATE_LIMIT,
                        target=api_target,
                        target_type="api",
                        reason=f"Apply adaptive rate limiting on endpoint '{api_target}' due to anomalous request consumption.",
                        risk_score=score,
                        severity="MODERATE",
                        status=ActionStatus.SIMULATED if is_dry_run else ActionStatus.EXECUTED,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=False,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                        incident_id=incident_id,
                        event_id=event_id,
                        details={"rate_limit_rpm": 60, "dry_run": is_dry_run},
                    )
                )

            actions.append(
                ResponseAction(
                    action_type=ActionType.ALERT,
                    target=incident_id or (event_id or "system"),
                    target_type="incident",
                    reason=f"Generate moderate risk security notification ({score}/100).",
                    risk_score=score,
                    severity="MODERATE",
                    status=ActionStatus.EXECUTED if not is_dry_run else ActionStatus.SIMULATED,
                    execution_mode=ExecutionMode.LIVE if not is_dry_run else ExecutionMode.SIMULATED,
                    requires_human_approval=False,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    incident_id=incident_id,
                    event_id=event_id,
                )
            )

        elif level_str == "HIGH" or (60 <= score < 80):
            response_level = "HIGH"
            action_status_str = "SIMULATED" if is_dry_run else "EXECUTED"
            requires_approval = False

            # 1. Step-up Authentication
            if user_id or session_id:
                actions.append(
                    ResponseAction(
                        action_type=ActionType.STEP_UP_AUTH,
                        target=session_id or user_id or "active_session",
                        target_type="session" if session_id else "user",
                        reason="Require step-up MFA verification before permitting sensitive access.",
                        risk_score=score,
                        severity="HIGH",
                        status=ActionStatus.SIMULATED if is_dry_run else ActionStatus.EXECUTED,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=False,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                        incident_id=incident_id,
                        event_id=event_id,
                        details={"challenge": "MFA_PROMPT", "dry_run": is_dry_run},
                    )
                )

            # 2. Restrict Suspicious API / Resource Access
            if resource:
                is_api = "api" in resource.lower()
                actions.append(
                    ResponseAction(
                        action_type=ActionType.RESTRICT_API if is_api else ActionType.RESTRICT_RESOURCE,
                        target=resource,
                        target_type="api" if is_api else "resource",
                        reason=f"Temporarily restrict access to '{resource}' pending identity verification.",
                        risk_score=score,
                        severity="HIGH",
                        status=ActionStatus.SIMULATED if is_dry_run else ActionStatus.EXECUTED,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=False,
                        approval_status=ApprovalStatus.NOT_REQUIRED,
                        incident_id=incident_id,
                        event_id=event_id,
                    )
                )

            actions.append(
                ResponseAction(
                    action_type=ActionType.ALERT,
                    target=incident_id or "system",
                    target_type="incident",
                    reason=f"Generate high-severity security alert and escalate to n8n ({score}/100).",
                    risk_score=score,
                    severity="HIGH",
                    status=ActionStatus.EXECUTED if not is_dry_run else ActionStatus.SIMULATED,
                    execution_mode=ExecutionMode.LIVE if not is_dry_run else ExecutionMode.SIMULATED,
                    requires_human_approval=False,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    incident_id=incident_id,
                    event_id=event_id,
                )
            )

        else:  # CRITICAL (score >= 80)
            response_level = "CRITICAL"
            requires_approval = True
            action_status_str = "PENDING_APPROVAL"

            # 1. Require Human Approval Gate
            actions.append(
                ResponseAction(
                    action_type=ActionType.REQUIRE_APPROVAL,
                    target=incident_id or "critical_containment",
                    target_type="incident",
                    reason="Destructive and high-impact containment actions require explicit human analyst authorization.",
                    risk_score=score,
                    severity="CRITICAL",
                    status=ActionStatus.PENDING_APPROVAL,
                    execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                    requires_human_approval=True,
                    approval_status=ApprovalStatus.PENDING,
                    incident_id=incident_id,
                    event_id=event_id,
                )
            )

            # 2. Session Response: Restrict / Terminate Session
            if session_id:
                actions.append(
                    ResponseAction(
                        action_type=ActionType.RESTRICT_SESSION,
                        target=session_id,
                        target_type="session",
                        reason=f"Suspend and isolate active session '{session_id}' to prevent lateral expansion.",
                        risk_score=score,
                        severity="CRITICAL",
                        status=ActionStatus.PENDING_APPROVAL,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=True,
                        approval_status=ApprovalStatus.PENDING,
                        incident_id=incident_id,
                        event_id=event_id,
                    )
                )

            # 3. AI Agent Containment & Tool Restriction
            if agent_id or any(s in signals for s in ["prompt_injection", "indirect_prompt_injection", "ai_agent_abuse", "agent_privilege_abuse"]):
                tgt_agent = agent_id or "ai_copilot"
                actions.append(
                    ResponseAction(
                        action_type=ActionType.CONTAIN_AGENT,
                        target=tgt_agent,
                        target_type="agent",
                        reason=f"Contain AI agent '{tgt_agent}' and revoke tool invocation privileges due to prompt injection / privilege abuse.",
                        risk_score=score,
                        severity="CRITICAL",
                        status=ActionStatus.PENDING_APPROVAL,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=True,
                        approval_status=ApprovalStatus.PENDING,
                        incident_id=incident_id,
                        event_id=event_id,
                        details={"restricted_tools": [tool_name] if tool_name else ["raw_sql_exec", "db_drop_tool"]},
                    )
                )

            # 4. API / Resource Restriction
            if resource:
                is_api = "api" in resource.lower()
                actions.append(
                    ResponseAction(
                        action_type=ActionType.RESTRICT_API if is_api else ActionType.RESTRICT_RESOURCE,
                        target=resource,
                        target_type="api" if is_api else "resource",
                        reason=f"Block unauthorized access to sensitive resource '{resource}'.",
                        risk_score=score,
                        severity="CRITICAL",
                        status=ActionStatus.PENDING_APPROVAL,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=True,
                        approval_status=ApprovalStatus.PENDING,
                        incident_id=incident_id,
                        event_id=event_id,
                    )
                )

            # 5. Source / IP Response: BLOCK_SOURCE
            # Safeguard: ONLY trigger source blocking if corroborated by high-confidence attack signals.
            # NEVER block solely for unfamiliar IP!
            attack_corroboration = any(
                s in signals
                for s in [
                    "brute_force_login",
                    "credential_stuffing",
                    "password_spraying",
                    "distributed_attack",
                    "suspicious_external_ip",
                    "external_attack_chain",
                    "data_exfiltration",
                ]
            )
            if ip_val and attack_corroboration:
                actions.append(
                    ResponseAction(
                        action_type=ActionType.BLOCK_SOURCE,
                        target=ip_val,
                        target_type="ip",
                        reason=f"Block malicious external source IP '{ip_val}' corroborated by multi-signal attack chain.",
                        risk_score=score,
                        severity="CRITICAL",
                        status=ActionStatus.PENDING_APPROVAL,
                        execution_mode=ExecutionMode.SIMULATED if is_dry_run else ExecutionMode.LIVE,
                        requires_human_approval=True,
                        approval_status=ApprovalStatus.PENDING,
                        incident_id=incident_id,
                        event_id=event_id,
                        details={
                            "evidence": list(signals.intersection({
                                "brute_force_login", "credential_stuffing", "password_spraying",
                                "distributed_attack", "suspicious_external_ip", "external_attack_chain",
                                "data_exfiltration"
                            })),
                            "simulation_notice": "SIMULATED ACTION - No real firewall rule was applied." if is_dry_run else "LIVE_BLOCK"
                        },
                    )
                )

            # 6. Critical Alert
            actions.append(
                ResponseAction(
                    action_type=ActionType.ALERT,
                    target=incident_id or "system",
                    target_type="incident",
                    reason=f"Generate critical incident alert and dispatch immediate n8n webhook notification ({score}/100).",
                    risk_score=score,
                    severity="CRITICAL",
                    status=ActionStatus.EXECUTED if not is_dry_run else ActionStatus.SIMULATED,
                    execution_mode=ExecutionMode.LIVE if not is_dry_run else ExecutionMode.SIMULATED,
                    requires_human_approval=False,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    incident_id=incident_id,
                    event_id=event_id,
                )
            )

        # Store actions in memory and repository
        for act in actions:
            self._actions[act.action_id] = act

        recommended_strs = list(dict.fromkeys(a.action_type.value for a in actions))

        decision = ResponseDecision(
            incident_id=incident_id,
            event_id=event_id,
            risk_score=score,
            severity=level_str,
            response_level=response_level,
            requires_human_approval=requires_approval,
            approval_required=requires_approval,
            dry_run=is_dry_run,
            recommended_actions=recommended_strs,
            executable_actions=actions,
            action_status=action_status_str,
            reasons=risk_assessment.reasons,
            primary_user=user_id,
        )

        if incident_id:
            self._decisions[incident_id] = decision

        # Log initial decision evaluation to audit trail
        self._record_audit_entry(
            incident_id=incident_id,
            event_id=event_id,
            action=f"EVALUATE_RESPONSE_{response_level}",
            target=user_id or (f"ip:{ip_val}" if ip_val else "system"),
            target_type="user" if user_id else "system",
            risk_score=score,
            severity=level_str,
            reason=f"Response decision evaluated: {response_level} ({', '.join(recommended_strs)}).",
            status=action_status_str,
            approval_status="PENDING" if requires_approval else "NOT_REQUIRED",
            execution_mode="SIMULATED" if is_dry_run else "LIVE",
            actor="ResponseEngine",
            details={
                "actions_count": len(actions),
                "requires_approval": requires_approval,
                "dry_run": is_dry_run,
            }
        )

        return decision

    def execute_action(
        self,
        action_id: str,
        approved: bool = True,
        actor: str = "SecurityAnalyst",
        dry_run: Optional[bool] = None,
    ) -> ResponseAction:
        """Executes a specific action. In safe dry-run mode, marks as SIMULATED with notice.
        Never executes without approval if requires_human_approval is True.
        """
        is_dry_run = self.dry_run if dry_run is None else dry_run
        action = self._actions.get(action_id)
        if not action:
            raise ValueError(f"Action '{action_id}' not found.")

        # Enforcement of approval requirement
        if action.requires_human_approval and not approved:
            action.status = ActionStatus.REJECTED
            action.approval_status = ApprovalStatus.REJECTED
            self._record_audit_entry(
                incident_id=action.incident_id,
                event_id=action.event_id,
                action_id=action.action_id,
                action=action.action_type.value,
                target=action.target,
                target_type=action.target_type,
                risk_score=action.risk_score,
                severity=action.severity,
                reason="Action rejected or blocked by human approval requirement.",
                status=ActionStatus.REJECTED.value,
                approval_status=ApprovalStatus.REJECTED.value,
                execution_mode="SIMULATED" if is_dry_run else "LIVE",
                actor=actor,
            )
            return action

        # Action execution logic
        action.approved_by = actor if action.requires_human_approval else "System"
        action.approval_status = ApprovalStatus.APPROVED if action.requires_human_approval else ApprovalStatus.NOT_REQUIRED
        action.executed_at = datetime.now(timezone.utc)

        if is_dry_run:
            action.status = ActionStatus.SIMULATED
            action.execution_mode = ExecutionMode.SIMULATED
            action.details["simulation_notice"] = (
                f"SIMULATED ACTION - {action.action_type.value} on {action.target} recorded safely. "
                "No real infrastructure was modified."
            )
        else:
            # Live execution pathway (if real firewall/identity provider is connected)
            action.status = ActionStatus.EXECUTED
            action.execution_mode = ExecutionMode.LIVE
            action.details["execution_notice"] = f"LIVE ACTION - {action.action_type.value} applied on {action.target}."

        self._record_audit_entry(
            incident_id=action.incident_id,
            event_id=action.event_id,
            action_id=action.action_id,
            action=action.action_type.value,
            target=action.target,
            target_type=action.target_type,
            risk_score=action.risk_score,
            severity=action.severity,
            reason=action.reason,
            status=action.status.value,
            approval_status=action.approval_status.value,
            execution_mode=action.execution_mode.value,
            actor=actor,
            details=action.details,
        )

        return action

    # --- Step 5: Compromised Approver Detection & Two-Person Rule Methods ---

    def evaluate_approver_risk(
        self,
        approver_id: str,
        role: Optional[str] = None,
        incident_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip: Optional[str] = None,
        device_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApproverRiskEvaluation:
        """Evaluates behavioral trust, role authorization, and threat context of a human approver.
        Does NOT claim the account is definitively compromised; evaluates elevated context/risk.
        """
        meta = metadata or {}
        reasons: List[str] = []
        context_signals: List[str] = []
        score = 0

        # 1. Role Authorization Verification
        authorized_roles = {
            "SECURITY_ANALYST", "SECURITY_ADMIN", "SYSTEM_OWNER",
            "ANALYST", "ADMINISTRATOR", "ADMIN", "ROOT", "SUPERUSER",
            "SOC_ANALYST", "SOC_ADMIN", "SOC_LEAD", "SECURITY_LEAD", "LEADSECANALYST"
        }

        # Check Cognee known user roles if mapped
        cognee_roles = {
            "U001": "Analyst",
            "admin_user": "Administrator",
            "A. Verma": "Software Engineer",
            "J. Singh": "HR Specialist",
            "R. Khan": "Database Administrator",
        }
        user_cognee_role = cognee_roles.get(approver_id)
        raw_role = role or user_cognee_role or "SECURITY_ANALYST"
        norm_role = raw_role.strip().upper().replace(" ", "_")

        if norm_role not in authorized_roles:
            score = 70
            reasons.append(
                f"Unauthorized role: User '{approver_id}' possesses role '{raw_role}', which is not authorized "
                "to approve critical containment actions (requires SECURITY_ANALYST, SECURITY_ADMIN, or SYSTEM_OWNER)."
            )
            return ApproverRiskEvaluation(
                approver_id=approver_id,
                approver_role=raw_role,
                approver_risk_score=score,
                approver_risk_level="HIGH",
                approval_allowed=False,
                requires_independent_verification=True,
                reasons=reasons,
                context_signals=["unauthorized_role"],
            )

        # 2. Incident-Involvement Guard (Requirement 18)
        # An approver who is directly involved in the target incident cannot independently approve its containment
        if incident_id:
            dec = self._decisions.get(incident_id)
            target_user = getattr(dec, "primary_user", None) if dec else None
            if not target_user and dec:
                for a in dec.executable_actions:
                    if a.target_type == "user":
                        target_user = a.target
            if not target_user and meta.get("primary_user"):
                target_user = meta.get("primary_user")

            if target_user and target_user == approver_id:
                    score += 65
                    reasons.append(
                        f"Approver '{approver_id}' is directly involved as an entity in incident '{incident_id}' "
                        "and cannot independently authorize its containment."
                    )
                    context_signals.append("incident_involved_approver")

        # 3. Active Incident Involving Approver
        if meta.get("has_active_incident") or meta.get("active_incident"):
            score += 55
            inc_ref = meta.get("active_incident_id") or "INC-ACTIVE-ALERT"
            reasons.append(f"Approver context has elevated risk: Approver has an active high/critical security incident ({inc_ref}).")
            context_signals.append("active_incident")

        for inc_key, decision in self._decisions.items():
            if inc_key != incident_id and decision.response_level in ["HIGH", "CRITICAL"]:
                for act in decision.executable_actions:
                    if act.target == approver_id or (act.target_type == "user" and act.target == approver_id):
                        score += 55
                        reasons.append(f"Approver context has elevated risk: Approver is primary entity in active critical incident '{inc_key}'.")
                        context_signals.append("active_incident")
                        break

        # 4. Behavioral & Contextual Telemetry Signals
        if meta.get("impossible_travel") is True or (session_id and "travel" in session_id.lower()):
            score += 45
            reasons.append("Approver context exhibited impossible travel between geographic locations within a short time window.")
            context_signals.append("impossible_travel")

        if meta.get("failed_logins") or meta.get("repeated_failed_login") or meta.get("auth_anomalies"):
            score += 30
            reasons.append("Recent repeated authentication anomalies associated with approver account.")
            context_signals.append("repeated_failed_login")

        if meta.get("privilege_escalation") or meta.get("is_elevation"):
            score += 35
            reasons.append("Recent unexpected administrative privilege escalation detected on approver account.")
            context_signals.append("privilege_escalation")

        if meta.get("suspicious_session") or meta.get("suspicious_session_behavior"):
            score += 30
            reasons.append("Approver session context has anomalous behavioral patterns.")
            context_signals.append("suspicious_session_behavior")

        if meta.get("prompt_injection") or meta.get("agent_abuse") or meta.get("agent_privilege_abuse"):
            score += 35
            reasons.append("Approver associated with suspicious AI agent prompt injection or tool abuse.")
            context_signals.append("agent_privilege_abuse")

        if meta.get("abnormal_resource_access") or meta.get("bulk_data_access"):
            score += 25
            reasons.append("Approver engaged in abnormal resource consumption outside baseline.")
            context_signals.append("abnormal_resource_access")

        if meta.get("is_new_device") or meta.get("new_device"):
            score += 15
            reasons.append("Approver logged in from an unfamiliar device.")
            context_signals.append("new_device")

        if meta.get("is_new_ip") or meta.get("new_ip"):
            score += 10
            reasons.append("Approver context indicates connection from an unfamiliar IP address.")
            context_signals.append("new_ip")

        if meta.get("abnormal_time") or meta.get("off_hours"):
            score += 15
            reasons.append("Approver authentication occurred outside historical working hours.")
            context_signals.append("abnormal_time")

        if meta.get("external_attack_chain") or meta.get("suspicious_external_ip"):
            score += 40
            reasons.append("Approver request context correlated with external perimeter threat intelligence.")
            context_signals.append("external_attack_chain")

        # 5. Final Score & Classification
        score = min(100, max(0, score))
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 26:
            level = "MODERATE"
        else:
            level = "LOW"

        # Threshold enforcement:
        if score >= 60:
            allowed = False
            requires_verification = True
            reasons.insert(0, "Elevated approver risk: Approver context requires independent verification before authorizing critical containment.")
        else:
            allowed = True
            requires_verification = False
            if not reasons:
                reasons.append("Approver identity, role authorization, and behavioral baseline verified within safe parameters.")

        return ApproverRiskEvaluation(
            approver_id=approver_id,
            approver_role=raw_role,
            approver_risk_score=score,
            approver_risk_level=level,
            approval_allowed=allowed,
            requires_independent_verification=requires_verification,
            reasons=reasons,
            context_signals=context_signals,
        )

    def get_approval_status(self, incident_id: str) -> ApprovalRecord:
        """Retrieves or initializes the active ApprovalRecord for an incident."""
        now = datetime.now(timezone.utc)
        record = self._approval_records.get(incident_id)
        if not record:
            record = ApprovalRecord(
                incident_id=incident_id,
                state=ApprovalState.PENDING_APPROVAL,
                two_person_rule_required=True,
                created_at=now,
                expires_at=now + timedelta(minutes=15),
            )
            self._approval_records[incident_id] = record
            return record

        # Check expiration (15-minute validity window)
        if now > record.expires_at and record.state not in [
            ApprovalState.SIMULATED,
            ApprovalState.EXECUTED,
            ApprovalState.REJECTED,
        ]:
            record.state = ApprovalState.EXPIRED
            record.is_expired = True

        return record

    def approve_incident_response(
        self,
        incident_id: str,
        actor: str = "SecurityAnalyst",
        role: Optional[str] = "SECURITY_ANALYST",
        session_id: Optional[str] = None,
        ip: Optional[str] = None,
        device_id: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
        require_two_person: Optional[bool] = None,
    ) -> List[ResponseAction]:
        """Approver 1 approval gateway for an incident response.
        Evaluates Approver 1 role authorization and behavioral risk.
        For critical containment actions under the Two-Person Rule, transitions state to
        APPROVER_2_REQUIRED and holds execution until independent Approver 2 authorizes.
        """
        is_dry_run = self.dry_run if dry_run is None else dry_run
        decision = self._decisions.get(incident_id)
        now = datetime.now(timezone.utc)
        record = self.get_approval_status(incident_id)

        # Check Expiration
        if record.is_expired or now > record.expires_at:
            record.state = ApprovalState.EXPIRED
            record.is_expired = True
            self._record_audit_entry(
                incident_id=incident_id,
                action="APPROVAL_EXPIRED",
                target=incident_id,
                target_type="incident",
                risk_score=decision.risk_score if decision else 80,
                severity=decision.severity if decision else "CRITICAL",
                reason="Approval attempt rejected: 15-minute approval window has expired.",
                status="EXPIRED",
                approval_status="REJECTED",
                execution_mode="SIMULATED",
                actor=actor,
            )
            raise ValueError("Approval window has expired (15 minutes). A fresh approval is required.")

        # Evaluate Approver 1 Risk & Role
        eval_res = self.evaluate_approver_risk(
            approver_id=actor,
            role=role,
            incident_id=incident_id,
            session_id=session_id,
            ip=ip,
            device_id=device_id,
            metadata=metadata,
        )

        record.approver_1_id = actor
        record.approver_1_role = eval_res.approver_role
        record.approver_1_risk_score = eval_res.approver_risk_score
        record.approver_1_risk_level = eval_res.approver_risk_level
        record.approver_1_reasons = eval_res.reasons
        record.approver_1_session_id = session_id
        record.approver_1_ip = ip
        record.approver_1_device_id = device_id

        # 1. Unauthorized approver
        if "Unauthorized role" in (eval_res.reasons[0] if eval_res.reasons else ""):
            record.state = ApprovalState.REJECTED
            record.rejection_reason = eval_res.reasons[0]
            self._record_audit_entry(
                incident_id=incident_id,
                action="APPROVER_UNAUTHORIZED",
                target=incident_id,
                target_type="incident",
                risk_score=eval_res.approver_risk_score,
                severity=eval_res.approver_risk_level,
                reason=f"Approval rejected: {eval_res.reasons[0]}",
                status="REJECTED",
                approval_status="REJECTED",
                execution_mode="SIMULATED",
                actor=actor,
                details={"approver_id": actor, "role": role},
            )
            raise ValueError(f"Approval rejected: {eval_res.reasons[0]}")

        # 2. High-Risk / Compromised Approver
        if not eval_res.approval_allowed or eval_res.approver_risk_level in ["HIGH", "CRITICAL"]:
            record.state = ApprovalState.APPROVAL_BLOCKED
            record.rejection_reason = "Elevated approver risk: Approver context requires independent verification."
            self._record_audit_entry(
                incident_id=incident_id,
                action="APPROVAL_BLOCKED",
                target=incident_id,
                target_type="incident",
                risk_score=eval_res.approver_risk_score,
                severity=eval_res.approver_risk_level,
                reason=f"Approval blocked due to elevated approver risk ({eval_res.approver_risk_level}): {eval_res.reasons[0]}",
                status="APPROVAL_BLOCKED",
                approval_status="PENDING",
                execution_mode="SIMULATED",
                actor=actor,
                details={
                    "approver_id": actor,
                    "risk_score": eval_res.approver_risk_score,
                    "risk_level": eval_res.approver_risk_level,
                    "reasons": eval_res.reasons,
                },
            )
            return []

        # 3. Authorized and Safe Approver 1
        record.approver_1_approved_at = now
        record.expires_at = now + timedelta(minutes=15)

        # Check if Two-Person Rule is required
        is_two_person = True if require_two_person is None else require_two_person
        if decision and decision.response_level not in ["CRITICAL", "HIGH"]:
            is_two_person = False

        if is_two_person:
            record.state = ApprovalState.APPROVER_2_REQUIRED
            # Mark action approval_status as APPROVED by Approver 1, but status remains PENDING_APPROVAL
            if decision:
                for action in decision.executable_actions:
                    if action.requires_human_approval:
                        action.approval_status = ApprovalStatus.APPROVED
            for action in self._actions.values():
                if action.incident_id == incident_id and action.requires_human_approval:
                    action.approval_status = ApprovalStatus.APPROVED

            self._record_audit_entry(
                incident_id=incident_id,
                action="APPROVE_CONTAINMENT",
                target=incident_id,
                target_type="incident",
                risk_score=eval_res.approver_risk_score,
                severity=eval_res.approver_risk_level,
                reason=f"Approver 1 '{actor}' authorized containment. Two-Person Rule requires independent Approver 2.",
                status="APPROVER_2_REQUIRED",
                approval_status="APPROVED",
                execution_mode="SIMULATED" if is_dry_run else "LIVE",
                actor=actor,
                details={
                    "stage": "APPROVER_1_APPROVED",
                    "approver_1": actor,
                    "approver_1_role": record.approver_1_role,
                    "approver_1_risk_score": eval_res.approver_risk_score,
                    "second_approval_required": True,
                },
            )
            return decision.executable_actions if decision else [a for a in self._actions.values() if a.incident_id == incident_id]

        # Non-two-person flow: execute immediately
        record.state = ApprovalState.APPROVED_FOR_EXECUTION
        executed_actions: List[ResponseAction] = []
        if decision:
            decision.action_status = "APPROVED"
            for action in decision.executable_actions:
                if action.status == ActionStatus.PENDING_APPROVAL:
                    executed = self.execute_action(action.action_id, approved=True, actor=actor, dry_run=is_dry_run)
                    executed_actions.append(executed)
        for action in self._actions.values():
            if action.incident_id == incident_id and action.status == ActionStatus.PENDING_APPROVAL:
                if action not in executed_actions:
                    executed = self.execute_action(action.action_id, approved=True, actor=actor, dry_run=is_dry_run)
                    executed_actions.append(executed)

        record.state = ApprovalState.SIMULATED if is_dry_run else ApprovalState.EXECUTED
        self._record_audit_entry(
            incident_id=incident_id,
            action="APPROVE_CONTAINMENT",
            target=incident_id,
            target_type="incident",
            risk_score=eval_res.approver_risk_score,
            severity=eval_res.approver_risk_level,
            reason=f"Human analyst '{actor}' granted authorization for containment actions.",
            status="APPROVED",
            approval_status="APPROVED",
            execution_mode="SIMULATED" if is_dry_run else "LIVE",
            actor=actor,
            details={"approved_actions_count": len(executed_actions)},
        )
        return executed_actions

    def second_approve_incident_response(
        self,
        incident_id: str,
        actor: str = "SecurityAdmin",
        role: Optional[str] = "SECURITY_ADMIN",
        session_id: Optional[str] = None,
        ip: Optional[str] = None,
        device_id: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> List[ResponseAction]:
        """Independent Approver 2 gateway for Two-Person Rule.
        Enforces independent user, independent session, role authorization, and safe risk score.
        Upon approval, executes all pending containment actions in safe simulation or live mode.
        """
        is_dry_run = self.dry_run if dry_run is None else dry_run
        decision = self._decisions.get(incident_id)
        now = datetime.now(timezone.utc)
        record = self.get_approval_status(incident_id)

        # Check Expiration
        if record.is_expired or now > record.expires_at:
            record.state = ApprovalState.EXPIRED
            record.is_expired = True
            self._record_audit_entry(
                incident_id=incident_id,
                action="APPROVAL_EXPIRED",
                target=incident_id,
                target_type="incident",
                risk_score=decision.risk_score if decision else 80,
                severity=decision.severity if decision else "CRITICAL",
                reason="Second approval rejected: 15-minute approval window has expired.",
                status="EXPIRED",
                approval_status="REJECTED",
                execution_mode="SIMULATED",
                actor=actor,
            )
            raise ValueError("Approval window has expired (15 minutes). A fresh approval is required.")

        # Check State
        if record.state not in [ApprovalState.APPROVER_2_REQUIRED, ApprovalState.APPROVER_1_APPROVED]:
            raise ValueError(f"Cannot perform second approval: current approval state is '{record.state.value}' (expected 'APPROVER_2_REQUIRED').")

        # Two-Person Rule Enforcement: Approver 1 != Approver 2
        if actor == record.approver_1_id:
            self._record_audit_entry(
                incident_id=incident_id,
                action="TWO_PERSON_RULE_VIOLATION",
                target=incident_id,
                target_type="incident",
                risk_score=record.approver_1_risk_score or 50,
                severity="HIGH",
                reason=f"Two-Person Rule violation: User '{actor}' cannot satisfy both Approver 1 and Approver 2.",
                status="REJECTED",
                approval_status="REJECTED",
                execution_mode="SIMULATED",
                actor=actor,
                details={"approver_1": record.approver_1_id, "attempted_approver_2": actor},
            )
            raise ValueError(f"Two-Person Rule violation: Second approver must be a distinct user (Approver 1 '{record.approver_1_id}' cannot self-approve as Approver 2).")

        # Session independence check (if both provided)
        if session_id and record.approver_1_session_id and session_id == record.approver_1_session_id:
            raise ValueError(f"Two-Person Rule violation: Second approver session '{session_id}' matches Approver 1 session.")

        # Evaluate Approver 2 Risk & Role
        eval_res = self.evaluate_approver_risk(
            approver_id=actor,
            role=role,
            incident_id=incident_id,
            session_id=session_id,
            ip=ip,
            device_id=device_id,
            metadata=metadata,
        )

        record.approver_2_id = actor
        record.approver_2_role = eval_res.approver_role
        record.approver_2_risk_score = eval_res.approver_risk_score
        record.approver_2_risk_level = eval_res.approver_risk_level
        record.approver_2_reasons = eval_res.reasons
        record.approver_2_session_id = session_id
        record.approver_2_ip = ip
        record.approver_2_device_id = device_id

        # 1. Unauthorized second approver
        if "Unauthorized role" in (eval_res.reasons[0] if eval_res.reasons else ""):
            self._record_audit_entry(
                incident_id=incident_id,
                action="SECOND_APPROVER_UNAUTHORIZED",
                target=incident_id,
                target_type="incident",
                risk_score=eval_res.approver_risk_score,
                severity=eval_res.approver_risk_level,
                reason=f"Second approval rejected: {eval_res.reasons[0]}",
                status="REJECTED",
                approval_status="REJECTED",
                execution_mode="SIMULATED",
                actor=actor,
            )
            raise ValueError(f"Second approver rejected: {eval_res.reasons[0]}")

        # 2. High-Risk Second Approver
        if not eval_res.approval_allowed or eval_res.approver_risk_level in ["HIGH", "CRITICAL"]:
            record.state = ApprovalState.APPROVAL_BLOCKED
            self._record_audit_entry(
                incident_id=incident_id,
                action="SECOND_APPROVER_BLOCKED",
                target=incident_id,
                target_type="incident",
                risk_score=eval_res.approver_risk_score,
                severity=eval_res.approver_risk_level,
                reason=f"Second approver blocked due to elevated security risk ({eval_res.approver_risk_level}): {eval_res.reasons[0]}",
                status="APPROVAL_BLOCKED",
                approval_status="PENDING",
                execution_mode="SIMULATED",
                actor=actor,
                details={
                    "approver_2": actor,
                    "risk_score": eval_res.approver_risk_score,
                    "risk_level": eval_res.approver_risk_level,
                    "reasons": eval_res.reasons,
                },
            )
            raise ValueError(f"Second approver blocked due to elevated security risk: {eval_res.reasons[0]}")

        # 3. Independent & Authorized Approver 2 -> Execute Containment!
        record.approver_2_approved_at = now
        record.state = ApprovalState.APPROVED_FOR_EXECUTION

        executed_actions: List[ResponseAction] = []
        dual_actor = f"{record.approver_1_id}+{actor}"
        if decision:
            decision.action_status = "APPROVED"
            for action in decision.executable_actions:
                if action.status == ActionStatus.PENDING_APPROVAL:
                    executed = self.execute_action(action.action_id, approved=True, actor=dual_actor, dry_run=is_dry_run)
                    executed_actions.append(executed)

        for action in self._actions.values():
            if action.incident_id == incident_id and action.status == ActionStatus.PENDING_APPROVAL:
                if action not in executed_actions:
                    executed = self.execute_action(action.action_id, approved=True, actor=dual_actor, dry_run=is_dry_run)
                    executed_actions.append(executed)

        record.state = ApprovalState.SIMULATED if is_dry_run else ApprovalState.EXECUTED
        self._record_audit_entry(
            incident_id=incident_id,
            action="FINAL_CONTAINMENT_AUTHORIZED",
            target=incident_id,
            target_type="incident",
            risk_score=decision.risk_score if decision else 80,
            severity=decision.severity if decision else "CRITICAL",
            reason=f"Two-Person Rule satisfied: Approver 1 '{record.approver_1_id}' and Approver 2 '{actor}' authorized containment.",
            status="APPROVED",
            approval_status="APPROVED",
            execution_mode="SIMULATED" if is_dry_run else "LIVE",
            actor=dual_actor,
            details={
                "approver_1": record.approver_1_id,
                "approver_1_risk": record.approver_1_risk_score,
                "approver_2": actor,
                "approver_2_risk": eval_res.approver_risk_score,
                "executed_actions_count": len(executed_actions),
            },
        )

        return executed_actions

    def reject_incident_response(
        self,
        incident_id: str,
        reason: str = "Manual analyst override / deemed benign",
        actor: str = "SecurityAnalyst",
    ) -> List[ResponseAction]:
        """Rejects pending containment actions for the incident."""
        decision = self._decisions.get(incident_id)
        record = self.get_approval_status(incident_id)
        record.state = ApprovalState.REJECTED
        record.rejection_reason = reason
        rejected_actions: List[ResponseAction] = []

        if decision:
            decision.action_status = "REJECTED"
            for action in decision.executable_actions:
                if action.status == ActionStatus.PENDING_APPROVAL:
                    rejected = self.execute_action(action.action_id, approved=False, actor=actor)
                    rejected_actions.append(rejected)

        for action in self._actions.values():
            if action.incident_id == incident_id and action.status == ActionStatus.PENDING_APPROVAL:
                if action not in rejected_actions:
                    rejected = self.execute_action(action.action_id, approved=False, actor=actor)
                    rejected_actions.append(rejected)

        self._record_audit_entry(
            incident_id=incident_id,
            action="REJECT_CONTAINMENT",
            target=incident_id,
            target_type="incident",
            risk_score=decision.risk_score if decision else 80,
            severity=decision.severity if decision else "CRITICAL",
            reason=f"Containment rejected by '{actor}': {reason}",
            status="REJECTED",
            approval_status="REJECTED",
            execution_mode="SIMULATED",
            actor=actor,
            details={"rejected_actions_count": len(rejected_actions)},
        )

        return rejected_actions

    def recover_false_positive(
        self,
        incident_id: str,
        reason: str = "Analyst verified benign false-positive activity",
        actor: str = "SecurityAnalyst",
    ) -> Dict[str, Any]:
        """False-Positive Recovery Workflow:
        1. Acknowledges false positive without erasing historical telemetry.
        2. Lifts simulated or live restrictions on sessions, APIs, agents, and source IPs.
        3. Updates action status to RESOLVED.
        4. Preserves the incident and logs recovery to the audit trail.
        """
        decision = self._decisions.get(incident_id)
        resolved_actions_count = 0

        if decision:
            decision.action_status = "RESOLVED"
            for action in decision.executable_actions:
                action.status = ActionStatus.RESOLVED
                action.details["resolved_by"] = actor
                action.details["resolution_reason"] = reason
                resolved_actions_count += 1

        for action in self._actions.values():
            if action.incident_id == incident_id:
                action.status = ActionStatus.RESOLVED
                action.details["resolved_by"] = actor
                action.details["resolution_reason"] = reason

        self._record_audit_entry(
            incident_id=incident_id,
            action="RECOVER_FALSE_POSITIVE",
            target=incident_id,
            target_type="incident",
            risk_score=decision.risk_score if decision else 0,
            severity=decision.severity if decision else "RESOLVED",
            reason=f"False positive acknowledged by '{actor}': {reason}. Restrictions lifted. Evidence preserved.",
            status="RESOLVED",
            approval_status="APPROVED",
            execution_mode="SIMULATED",
            actor=actor,
            details={
                "recovery_status": "RESTRICTIONS_LIFTED",
                "evidence_preserved": True,
                "resolved_actions_count": resolved_actions_count,
            },
        )

        return {
            "status": "success",
            "incident_id": incident_id,
            "recovery_status": "RESTRICTIONS_LIFTED",
            "message": f"False positive recovered by {actor}. All restrictions lifted. Historical evidence preserved in audit log.",
            "resolved_actions_count": resolved_actions_count,
        }

    def get_incident_response(self, incident_id: str) -> Optional[ResponseDecision]:
        """Fetches the active response decision for an incident."""
        return self._decisions.get(incident_id)

    def get_audit_trail(self, incident_id: Optional[str] = None, limit: int = 100) -> List[AuditEntry]:
        """Fetches chronological audit trail entries."""
        if not hasattr(self, "_memory_audit_trail"):
            self._memory_audit_trail = []
        entries = list(self._memory_audit_trail)
        if incident_id:
            entries = [e for e in entries if e.incident_id == incident_id]
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]

    def _record_audit_entry(
        self,
        incident_id: Optional[str] = None,
        event_id: Optional[str] = None,
        action_id: Optional[str] = None,
        action: str = "",
        target: str = "",
        target_type: Optional[str] = None,
        risk_score: int = 0,
        severity: str = "LOW",
        reason: str = "",
        status: str = "SIMULATED",
        approval_status: str = "NOT_REQUIRED",
        execution_mode: str = "SIMULATED",
        actor: str = "System",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            incident_id=incident_id,
            event_id=event_id,
            action_id=action_id,
            action=action,
            target=target,
            target_type=target_type,
            risk_score=risk_score,
            severity=severity,
            reason=reason,
            status=status,
            approval_status=approval_status,
            execution_mode=execution_mode,
            actor=actor,
            details=details or {},
        )
        if not hasattr(self, "_memory_audit_trail"):
            self._memory_audit_trail = []
        self._memory_audit_trail.append(entry)
        return entry
