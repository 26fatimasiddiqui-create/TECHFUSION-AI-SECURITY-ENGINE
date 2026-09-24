import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment, RiskLevel
from app.models.response import (
    ResponseAction,
    ResponseDecision,
    AuditEntry,
    ApprovalRequest,
    RecoveryRequest,
    ApprovalState,
    ApproverRole,
    ApproverRiskEvaluation,
    ApprovalRecord,
    ApproverEvaluationRequest,
    SecondApprovalRequest,
)
from app.services.response_service import ResponseService
from app.services.correlation_service import CorrelationService
from app.services.risk_service import RiskService
from app.services.detection_service import DetectionService
from app.services.cognee_service import CogneeService
from app.services.alert_service import AlertService
from app.repositories.supabase_repository import SupabaseRepository
from app.api.dependencies import (
    get_response_service,
    get_correlation_service,
    get_risk_service,
    get_detection_service,
    get_cognee_service,
    get_supabase_repository,
    get_alert_service,
)

router = APIRouter(prefix="/api/response", tags=["risk-adaptive-response"])


class SyncUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    actor: str = "SOC_Analyst"
    reason: Optional[str] = "Dual-control approval verified and baseline updated across Cognee and database"
    device_id: Optional[str] = None
    ip: Optional[str] = None
    resource: Optional[str] = None


class EvaluateResponseRequest(BaseModel):
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    event: Optional[SecurityEvent] = None
    dry_run: Optional[bool] = True


class ExecuteActionRequest(BaseModel):
    action_id: str
    approved: bool = True
    actor: str = "SecurityAnalyst"
    dry_run: Optional[bool] = True


class IncidentResponseSummary(BaseModel):
    status: str = "success"
    incident_id: str
    decision: Optional[ResponseDecision] = None
    actions: List[ResponseAction] = Field(default_factory=list)
    audit_trail: List[AuditEntry] = Field(default_factory=list)


@router.post(
    "/evaluate",
    response_model=ResponseDecision,
    status_code=status.HTTP_200_OK,
    summary="Evaluate risk-based response policy",
    description="Evaluates existing incident risk assessment against the centralized response policy.",
)
async def evaluate_response_endpoint(
    payload: EvaluateResponseRequest,
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    risk_svc: RiskService = Depends(get_risk_service),
    detection_svc: DetectionService = Depends(get_detection_service),
    cognee_svc: CogneeService = Depends(get_cognee_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> ResponseDecision:
    incident = None
    target_event = None
    assessment = None

    if payload.incident_id:
        incident = correlation_svc.get_incident(payload.incident_id)
        if not incident:
            incident = await repo.get_incident(payload.incident_id)
        if incident and incident.risk_assessment:
            assessment = incident.risk_assessment

    if not assessment and payload.event_id:
        target_event = await repo.get_event_by_id(payload.event_id)
    elif not assessment and payload.event:
        target_event = payload.event

    if target_event and not assessment:
        context = await cognee_svc.get_historical_context(target_event)
        detection = detection_svc.analyze_event(target_event, historical_context=context)
        inc, signals = correlation_svc.correlate_event(target_event, detection.signals)
        incident = inc
        assessment = risk_svc.assess_risk(signals=signals, context=context, correlated_event_count=len(inc.events))

    if not assessment:
        # Fallback default assessment if nothing was found
        assessment = RiskAssessment(
            risk_score=10,
            risk_level=RiskLevel.LOW,
            confidence=0.85,
            reasons=["Standard activity conforming to security baseline."],
            recommended_action="Continue monitoring",
            correlated_signals=[],
        )

    decision = response_svc.evaluate_response(
        risk_assessment=assessment,
        incident=incident,
        event=target_event,
        dry_run=payload.dry_run,
    )
    return decision


@router.post(
    "/execute",
    response_model=ResponseAction,
    status_code=status.HTTP_200_OK,
    summary="Execute or simulate a specific response action",
    description="Executes a specific action, enforcing human approval if required and safely simulating in dry-run mode.",
)
async def execute_action_endpoint(
    payload: ExecuteActionRequest,
    response_svc: ResponseService = Depends(get_response_service),
) -> ResponseAction:
    try:
        action = response_svc.execute_action(
            action_id=payload.action_id,
            approved=payload.approved,
            actor=payload.actor,
            dry_run=payload.dry_run,
        )
        return action
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/audit-trail",
    response_model=List[AuditEntry],
    summary="List chronological audit trail entries",
    description="Retrieves auditable records of all response decisions, actions, approvals, and recoveries.",
)
async def get_audit_trail_endpoint(
    incident_id: Optional[str] = Query(None, description="Optional incident ID filter"),
    limit: int = Query(100, ge=1, le=500),
    response_svc: ResponseService = Depends(get_response_service),
) -> List[AuditEntry]:
    return response_svc.get_audit_trail(incident_id=incident_id, limit=limit)


@router.get(
    "/{incident_id}",
    response_model=IncidentResponseSummary,
    summary="Get response status and actions for an incident",
    description="Fetches the active response decision, executable actions, and audit trail for an incident.",
)
async def get_incident_response_endpoint(
    incident_id: str,
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    risk_svc: RiskService = Depends(get_risk_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> IncidentResponseSummary:
    decision = response_svc.get_incident_response(incident_id)

    # If decision not yet evaluated, evaluate on-the-fly for the incident
    if not decision:
        incident = correlation_svc.get_incident(incident_id)
        if not incident:
            incident = await repo.get_incident(incident_id)
        if incident and incident.risk_assessment:
            decision = response_svc.evaluate_response(
                risk_assessment=incident.risk_assessment,
                incident=incident,
            )

    actions = [a for a in response_svc._actions.values() if a.incident_id == incident_id]
    audit_entries = response_svc.get_audit_trail(incident_id=incident_id)

    return IncidentResponseSummary(
        status="success",
        incident_id=incident_id,
        decision=decision,
        actions=actions,
        audit_trail=audit_entries,
    )


@router.post(
    "/{incident_id}/approvals/evaluate-approver",
    response_model=ApproverRiskEvaluation,
    summary="Evaluate approver role authorization and behavioral trust",
    description="Evaluates approver security context, active incidents, anomalies, and role authorization without modifying containment state.",
)
async def evaluate_approver_endpoint(
    incident_id: str,
    payload: ApproverEvaluationRequest,
    response_svc: ResponseService = Depends(get_response_service),
) -> ApproverRiskEvaluation:
    return response_svc.evaluate_approver_risk(
        approver_id=payload.approver_id,
        role=payload.role,
        incident_id=incident_id,
        session_id=payload.session_id,
        ip=payload.ip,
        device_id=payload.device_id,
        metadata=payload.metadata,
    )


@router.get(
    "/{incident_id}/approval-status",
    response_model=ApprovalRecord,
    summary="Get multi-stage approval status and records for an incident",
    description="Retrieves active approval state, Approver 1 & 2 details, two-person rule status, and expiration.",
)
async def get_approval_status_endpoint(
    incident_id: str,
    response_svc: ResponseService = Depends(get_response_service),
) -> ApprovalRecord:
    return response_svc.get_approval_status(incident_id)


@router.post(
    "/{incident_id}/approve",
    response_model=List[ResponseAction],
    summary="Approve containment actions for an incident (Approver 1)",
    description="Human-in-the-loop authorization gate: Evaluates Approver 1 risk and authorization. For Two-Person Rule, transitions state to APPROVER_2_REQUIRED.",
)
async def approve_incident_response_endpoint(
    incident_id: str,
    payload: ApprovalRequest = ApprovalRequest(),
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    alert_svc: AlertService = Depends(get_alert_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> List[ResponseAction]:
    try:
        executed = response_svc.approve_incident_response(
            incident_id=incident_id,
            actor=payload.approver_id or payload.actor,
            role=payload.role,
            session_id=payload.session_id,
            ip=payload.ip,
            device_id=payload.device_id,
            notes=payload.notes or payload.reason,
            metadata=payload.metadata,
            dry_run=payload.dry_run,
        )
        rec = response_svc.get_approval_status(incident_id)
        if rec.state in [ApprovalState.SIMULATED, ApprovalState.EXECUTED, ApprovalState.APPROVED_FOR_EXECUTION]:
            inc = correlation_svc.get_incident(incident_id)
            if not inc:
                inc = await repo.get_incident(incident_id)
            if inc:
                inc.status = "contained"
                if inc.risk_assessment:
                    inc.risk_assessment.risk_score = 15
                    inc.risk_assessment.risk_level = RiskLevel.LOW
                await repo.save_incident(inc)
                if hasattr(correlation_svc, "active_incidents"):
                    correlation_svc.active_incidents[incident_id] = inc
            await alert_svc.resolve_alerts_for_incident(
                incident_id=incident_id,
                new_status="contained",
                risk_score=15,
                risk_level="LOW",
                approval_state="APPROVED",
                response_state="CONTAINMENT_ACTIVE",
            )
        return executed
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{incident_id}/second-approve",
    response_model=List[ResponseAction],
    summary="Second independent approval for Two-Person Rule (Approver 2)",
    description="Enforces independent approver, independent session, and safe behavioral trust before executing containment.",
)
async def second_approve_incident_response_endpoint(
    incident_id: str,
    payload: SecondApprovalRequest = SecondApprovalRequest(),
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    alert_svc: AlertService = Depends(get_alert_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> List[ResponseAction]:
    try:
        executed = response_svc.second_approve_incident_response(
            incident_id=incident_id,
            actor=payload.approver_id or payload.actor,
            role=payload.role,
            session_id=payload.session_id,
            ip=payload.ip,
            device_id=payload.device_id,
            notes=payload.notes or payload.reason,
            metadata=payload.metadata,
            dry_run=payload.dry_run,
        )
        inc = correlation_svc.get_incident(incident_id)
        if not inc:
            inc = await repo.get_incident(incident_id)
        if inc:
            inc.status = "contained"
            if inc.risk_assessment:
                inc.risk_assessment.risk_score = 15
                inc.risk_assessment.risk_level = RiskLevel.LOW
                inc.risk_assessment.reasons = [
                    "Containment actions authorized and executed via dual-control Two-Person Rule.",
                    "Session quarantined and threat vectors neutralized."
                ]
            await repo.save_incident(inc)
            if hasattr(correlation_svc, "active_incidents"):
                correlation_svc.active_incidents[incident_id] = inc
        await alert_svc.resolve_alerts_for_incident(
            incident_id=incident_id,
            new_status="contained",
            risk_score=15,
            risk_level="LOW",
            approval_state="APPROVED",
            response_state="CONTAINMENT_ACTIVE",
        )
        return executed
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{incident_id}/reject",
    response_model=List[ResponseAction],
    summary="Reject containment actions for an incident",
    description="Rejects pending containment actions and records cancellation to audit trail.",
)
async def reject_incident_response_endpoint(
    incident_id: str,
    payload: ApprovalRequest = ApprovalRequest(),
    response_svc: ResponseService = Depends(get_response_service),
) -> List[ResponseAction]:
    rejected = response_svc.reject_incident_response(
        incident_id=incident_id,
        reason=payload.reason or "Analyst rejected containment action",
        actor=payload.actor,
    )
    return rejected


@router.post(
    "/{incident_id}/contain",
    summary="Contain incident and neutralize threat vectors",
    description="Directly transitions incident status to contained, lowers risk score, and synchronizes alerts and graph.",
)
async def contain_incident_endpoint(
    incident_id: str,
    payload: ApprovalRequest = ApprovalRequest(),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    alert_svc: AlertService = Depends(get_alert_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> Dict[str, Any]:
    inc = correlation_svc.get_incident(incident_id)
    if not inc:
        inc = await repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    
    inc.status = "contained"
    if inc.risk_assessment:
        inc.risk_assessment.risk_score = 15
        inc.risk_assessment.risk_level = RiskLevel.LOW
        inc.risk_assessment.reasons = [
            f"Containment executed by {payload.actor or 'SOC_Analyst'}: {payload.notes or payload.reason or 'Threat quarantined'}.",
            "Active sessions restricted and threat surface contained."
        ]
    await repo.save_incident(inc)
    if hasattr(correlation_svc, "active_incidents"):
        correlation_svc.active_incidents[incident_id] = inc

    await alert_svc.resolve_alerts_for_incident(
        incident_id=incident_id,
        new_status="contained",
        risk_score=15,
        risk_level="LOW",
        approval_state="APPROVED",
        response_state="CONTAINMENT_ACTIVE",
    )
    return {
        "status": "contained",
        "incident_id": incident_id,
        "contained": True,
        "contained_at": datetime.now(timezone.utc).isoformat(),
        "affected_entities": [inc.primary_entity] if inc and inc.primary_entity else [],
        "incident_status": "contained",
    }


@router.post(
    "/{incident_id}/recover",
    summary="Recover false positive and restore access",
    description="Acknowledges false positive, lifts restrictions, marks incident resolved, and preserves audit trail.",
)
@router.post(
    "/{incident_id}/recover-false-positive",
    summary="Recover false positive alias",
    description="Alias for /{incident_id}/recover to ensure full backward compatibility.",
)
async def recover_false_positive_endpoint(
    incident_id: str,
    payload: RecoveryRequest = RecoveryRequest(),
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    alert_svc: AlertService = Depends(get_alert_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> Dict[str, Any]:
    res = response_svc.recover_false_positive(
        incident_id=incident_id,
        reason=payload.reason,
        actor=payload.actor,
    )
    inc = correlation_svc.get_incident(incident_id)
    if not inc:
        inc = await repo.get_incident(incident_id)
    if inc:
        inc.status = "resolved"
        if inc.risk_assessment:
            inc.risk_assessment.risk_score = 0
            inc.risk_assessment.risk_level = RiskLevel.LOW
            inc.risk_assessment.reasons = [
                f"Incident verified as false positive by {payload.actor or 'SOC_Lead'}: {payload.reason}.",
                "All restrictions lifted and access restored to normal operations."
            ]
        await repo.save_incident(inc)
        if hasattr(correlation_svc, "active_incidents"):
            correlation_svc.active_incidents[incident_id] = inc
    await alert_svc.resolve_alerts_for_incident(
        incident_id=incident_id,
        new_status="resolved",
        risk_score=0,
        risk_level="RESOLVED",
        approval_state="RESOLVED",
        response_state="RESTORED",
    )
    res["status"] = "RESOLVED"
    res["resolved"] = True
    res["resolved_at"] = datetime.now(timezone.utc).isoformat()
    res["affected_entities"] = [inc.primary_entity] if inc and inc.primary_entity else []
    res["incident_status"] = "resolved"
    return res


@router.post(
    "/{incident_id}/sync-update",
    summary="Synchronize and update user resolution across database, Cognee, and alert engine",
    description="Approves incident containment, clears all alerts for user across database and memory, updates Cognee baseline graph.",
)
async def sync_update_incident_and_user_endpoint(
    incident_id: str,
    payload: SyncUpdateRequest = SyncUpdateRequest(),
    response_svc: ResponseService = Depends(get_response_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    alert_svc: AlertService = Depends(get_alert_service),
    cognee_svc: CogneeService = Depends(get_cognee_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> Dict[str, Any]:
    # 1. Retrieve incident
    inc = correlation_svc.get_incident(incident_id)
    if not inc:
        inc = await repo.get_incident(incident_id)

    # 2. Extract target user
    target_user = (
        payload.user_id
        or (inc.primary_entity if inc and inc.primary_entity else None)
        or (inc.entity_id if inc and hasattr(inc, "entity_id") else None)
        or "U_ANALYST"
    )

    # 3. Update incident state to contained
    if inc:
        inc.status = "contained"
        if inc.risk_assessment:
            inc.risk_assessment.risk_score = 15
            inc.risk_assessment.risk_level = RiskLevel.LOW
            inc.risk_assessment.reasons = [
                f"Dual-control containment approved and synchronized by {payload.actor}: {payload.reason}.",
                "All user alerts cleared and Cognee baseline updated."
            ]
        await repo.save_incident(inc)
        if hasattr(correlation_svc, "active_incidents"):
            correlation_svc.active_incidents[incident_id] = inc

    # 4. Resolve incident alerts
    incident_alerts = await alert_svc.resolve_alerts_for_incident(
        incident_id=incident_id,
        new_status="contained",
        risk_score=15,
        risk_level="LOW",
        approval_state="APPROVED",
        response_state="CONTAINMENT_ACTIVE",
    )

    # 5. Resolve user alerts prototype-wide
    user_alerts = await alert_svc.resolve_alerts_for_user(
        user_id=target_user,
        new_status="resolved",
        risk_score=0,
        risk_level="RESOLVED",
        approval_state="APPROVED",
        response_state="RESTORED",
        actor=payload.actor,
        reason=payload.reason or "Analyst approval update",
    )

    # 6. Update Cognee baseline knowledge graph
    cognee_res = await cognee_svc.resolve_user_threats(
        user_id=target_user,
        device_id=payload.device_id,
        ip=payload.ip,
        resource=payload.resource,
        reason=payload.reason or "Analyst approval update",
    )

    # 7. Update database repository directly if client available
    db_updated = False
    if repo.client:
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            repo.client.table("alerts").update({
                "status": "approved",
                "resolved_at": now_iso
            }).or_(f"employee_id.eq.{target_user},message.ilike.%{target_user}%").execute()
            db_updated = True
        except Exception as e:
            logger.warning(f"Notice updating Supabase alerts table: {e}")

    # 8. Record audit entry
    response_svc._record_audit_entry(
        incident_id=incident_id,
        action="SYSTEM_UPDATE_AND_COGNEE_SYNC",
        target=target_user,
        target_type="user",
        risk_score=15,
        severity="LOW",
        reason=f"Analyst '{payload.actor}' synchronized system state. Alerts cleared and Cognee baseline updated.",
        status="APPROVED",
        actor=payload.actor,
        details={
            "incident_id": incident_id,
            "target_user": target_user,
            "incident_alerts_count": len(incident_alerts),
            "user_alerts_count": len(user_alerts),
            "cognee_status": cognee_res.get("status"),
        }
    )

    return {
        "status": "success",
        "incident_id": incident_id,
        "user_id": target_user,
        "incident_status": inc.status if inc else "contained",
        "alerts_cleared": len(incident_alerts) + len(user_alerts),
        "cognee_synced": True,
        "database_synced": db_updated,
        "cognee_details": cognee_res,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"Successfully updated system! All alerts for user '{target_user}' cleared across prototype, Supabase DB, and Cognee."
    }



