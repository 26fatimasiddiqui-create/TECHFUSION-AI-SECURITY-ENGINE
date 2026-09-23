from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment, RiskLevel
from app.models.alert import SecurityAlert
from app.models.incident import CorrelatedIncident
from app.models.response import ResponseAction
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.alert_service import AlertService
from app.services.response_service import ResponseService
from app.repositories.supabase_repository import SupabaseRepository
from app.api.dependencies import (
    get_detection_service,
    get_correlation_service,
    get_cognee_service,
    get_risk_service,
    get_alert_service,
    get_response_service,
    get_supabase_repository,
)

router = APIRouter(prefix="/api/n8n", tags=["n8n-automation"])


class N8nProcessEventRequest(BaseModel):
    """Event payload received from an n8n trigger node (webhook, scheduler, poller)."""
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    event_type: str
    resource: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class N8nProcessEventResponse(BaseModel):
    status: str = "processed"
    # Clean booleans designed for direct evaluation in n8n IF / Switch nodes
    should_escalate: bool
    requires_human_approval: bool
    approval_required: bool = False
    alert_created: bool
    
    # Intelligence assessment results
    risk_level: str
    risk_score: int
    confidence: float
    reasons: List[str]
    recommended_action: str
    notification_summary: str

    # Step 4: Structured Response & Containment fields for n8n
    response_level: str
    recommended_actions: List[str] = Field(default_factory=list)
    executable_actions: List[Dict[str, Any]] = Field(default_factory=list)
    dry_run: bool = True
    action_status: str = "RECOMMENDED"

    # Step 5: Compromised Approver & Two-Person Rule fields for n8n
    approval_state: Optional[str] = None
    approver_risk_level: Optional[str] = None
    approver_risk_score: Optional[int] = None
    second_approval_required: bool = False
    second_approval_status: Optional[str] = None
    approval_blocked: bool = False
    independent_verification_required: bool = False

    # Attached records
    event_id: str
    incident_id: str
    alert: Optional[SecurityAlert] = None


@router.post(
    "/process-event",
    response_model=N8nProcessEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Process security event for n8n orchestration",
    description=(
        "Core n8n automation entrypoint. Executes full pipeline: "
        "Detection -> Correlation -> Cognee -> Risk Scoring -> Supabase -> Alert Generation. "
        "Returns orchestration flags for n8n branching (should_escalate, requires_human_approval)."
    ),
)
async def process_event_for_n8n(
    payload: N8nProcessEventRequest,
    detection_svc: DetectionService = Depends(get_detection_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    cognee_svc: CogneeService = Depends(get_cognee_service),
    risk_svc: RiskService = Depends(get_risk_service),
    alert_svc: AlertService = Depends(get_alert_service),
    response_svc: ResponseService = Depends(get_response_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> N8nProcessEventResponse:
    # 1. Normalize and instantiate SecurityEvent
    event = SecurityEvent(
        user_id=payload.user_id,
        device_id=payload.device_id,
        session_id=payload.session_id,
        event_type=payload.event_type,
        resource=payload.resource,
        agent_id=payload.agent_id,
        tool_name=payload.tool_name,
        metadata=payload.metadata,
    )

    # 2. Persist event to Supabase
    await repo.insert_event(event)

    # 3. Retrieve Cognee historical baseline context
    context = await cognee_svc.get_historical_context(event)

    # 4. Detect suspicious signals
    recent_history = await repo.list_events(limit=50)
    recent_events = [e for e in recent_history if e.id != event.id]
    detection = detection_svc.analyze_event(
        event,
        historical_context=context,
        recent_events=recent_events,
    )

    # 5. Correlate with sliding time-window and active incident
    incident, correlated_signals = correlation_svc.correlate_event(event, detection.signals)

    # 6. Assess risk and generate explanation
    assessment: RiskAssessment = risk_svc.assess_risk(
        signals=correlated_signals,
        context=context,
        correlated_event_count=len(incident.events),
    )
    incident.risk_assessment = assessment

    # 7. Update Cognee graph memory
    await cognee_svc.store_event_context(event)

    # 8. Evaluate Risk-Adaptive Response Decision & Actions
    decision = response_svc.evaluate_response(
        risk_assessment=assessment,
        incident=incident,
        event=event,
    )

    # 9. Fetch approval status for Two-Person Rule and approver risk
    approval_rec = response_svc.get_approval_status(incident.id)
    is_two_person = decision.requires_human_approval and decision.response_level in ["CRITICAL", "HIGH"]
    appr_state_str = approval_rec.state.value if approval_rec else decision.action_status

    # 10. Alert generation & persistence if risk warrants
    alert: Optional[SecurityAlert] = None
    level_str = assessment.risk_level.value if hasattr(assessment.risk_level, "value") else str(assessment.risk_level)
    should_escalate = level_str in ["HIGH", "CRITICAL"]

    if alert_svc.should_generate_alert(assessment):
        alert = await alert_svc.create_alert(
            incident_id=incident.id,
            risk_assessment=assessment,
            event_id=event.id,
            primary_entity=incident.primary_entity,
            approval_required=decision.requires_human_approval,
            approval_state=appr_state_str,
            response_state=decision.response_level,
            recommended_actions=decision.recommended_actions,
        )

    # 11. Format notification summary for n8n alerts (Slack/Discord/Email)
    summary_lines = [
        f"🚨 PS-8 Security Incident: {level_str} (Risk Score: {assessment.risk_score}/100)",
        f"Entity: {incident.primary_entity} ({incident.entity_type})",
        f"Response Level: {decision.response_level} | Status: {decision.action_status}",
        f"Recommended: {', '.join(decision.recommended_actions)}",
        "Reasons:",
    ]
    for r in assessment.reasons:
        summary_lines.append(f"  • {r}")
    notification_summary = "\n".join(summary_lines)

    return N8nProcessEventResponse(
        status="processed",
        should_escalate=should_escalate,
        requires_human_approval=decision.requires_human_approval,
        approval_required=decision.requires_human_approval,
        alert_created=alert is not None,
        risk_level=level_str,
        risk_score=assessment.risk_score,
        confidence=assessment.confidence,
        reasons=assessment.reasons,
        recommended_action=assessment.recommended_action,
        notification_summary=notification_summary,
        response_level=decision.response_level,
        recommended_actions=decision.recommended_actions,
        executable_actions=[a.model_dump(mode="json") for a in decision.executable_actions],
        dry_run=decision.dry_run,
        action_status=decision.action_status,
        approval_state=approval_rec.state.value if approval_rec else None,
        approver_risk_level=approval_rec.approver_1_risk_level if approval_rec else None,
        approver_risk_score=approval_rec.approver_1_risk_score if approval_rec else None,
        second_approval_required=is_two_person,
        second_approval_status=approval_rec.state.value if approval_rec and is_two_person else "NOT_REQUIRED",
        approval_blocked=approval_rec.state == "APPROVAL_BLOCKED" if approval_rec else False,
        independent_verification_required=is_two_person,
        event_id=event.id,
        incident_id=incident.id,
        alert=alert,
    )
