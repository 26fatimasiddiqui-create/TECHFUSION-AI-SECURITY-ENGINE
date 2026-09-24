from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment
from app.models.alert import SecurityAlert
from app.models.response import ResponseDecision
from app.repositories.supabase_repository import SupabaseRepository
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.alert_service import AlertService
from app.services.response_service import ResponseService
from app.api.dependencies import (
    get_supabase_repository,
    get_detection_service,
    get_correlation_service,
    get_cognee_service,
    get_risk_service,
    get_alert_service,
    get_response_service,
)

router = APIRouter(prefix="/api/events", tags=["events"])


class EventIngestResponse(BaseModel):
    status: str = "success"
    message: str = "Security event ingested successfully"
    event: SecurityEvent
    incident_id: Optional[str] = None
    risk_assessment: Optional[RiskAssessment] = None
    alert: Optional[SecurityAlert] = None
    response_decision: Optional[ResponseDecision] = None


class EventListResponse(BaseModel):
    status: str = "success"
    count: int
    events: List[SecurityEvent]


@router.post(
    "",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security event",
    description="Validates, normalizes, assigns/preserves event ID, runs intelligence analysis, and persists event to Supabase.",
)
async def ingest_event(
    event: SecurityEvent,
    repo: SupabaseRepository = Depends(get_supabase_repository),
    detection_svc: DetectionService = Depends(get_detection_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    cognee_svc: CogneeService = Depends(get_cognee_service),
    risk_svc: RiskService = Depends(get_risk_service),
    alert_svc: AlertService = Depends(get_alert_service),
    response_svc: ResponseService = Depends(get_response_service),
) -> EventIngestResponse:
    """1. Receives and validates security event payload.
    2. Persists the event via Supabase repository.
    3. Retrieves historical Cognee baseline context.
    4. Evaluates detection signals.
    5. Correlates event with sliding window & active incident.
    6. Calculates risk score, confidence, reasons, and recommended action.
    7. Generates and persists alert if risk warrants.
    8. Returns clean JSON response.
    """
    # Persist event
    persisted_event = await repo.insert_event(event)

    # Historical context & baseline check
    context = await cognee_svc.get_historical_context(persisted_event)

    # Fetch prior recent events to evaluate transitions (impossible travel, brute-force, password spraying, bot bursts)
    recent_history = await repo.list_events(limit=50)
    recent_events = [e for e in recent_history if e.id != persisted_event.id]

    # Detect signals
    detection = detection_svc.analyze_event(
        persisted_event,
        historical_context=context,
        recent_events=recent_events,
    )

    # Correlate into incident
    incident, correlated_signals = correlation_svc.correlate_event(persisted_event, detection.signals)

    # Assess risk
    assessment: RiskAssessment = risk_svc.assess_risk(
        signals=correlated_signals,
        context=context,
        correlated_event_count=len(incident.events),
    )
    incident.risk_assessment = assessment
    await repo.save_incident(incident)

    # Store context into Cognee
    await cognee_svc.store_event_context(persisted_event)

    # Evaluate risk-adaptive response decision
    response_decision = response_svc.evaluate_response(
        risk_assessment=assessment,
        incident=incident,
        event=persisted_event,
    )

    # Fetch approval status if exists
    appr_rec = response_svc.get_approval_status(incident.id)
    appr_state_str = appr_rec.state.value if appr_rec else response_decision.action_status

    # Generate or escalate alert if warranted
    alert: Optional[SecurityAlert] = None
    if alert_svc.should_generate_alert(assessment):
        alert = await alert_svc.create_alert(
            incident_id=incident.id,
            risk_assessment=assessment,
            event_id=persisted_event.id,
            primary_entity=incident.primary_entity,
            approval_required=response_decision.requires_human_approval,
            approval_state=appr_state_str,
            response_state=response_decision.response_level,
            recommended_actions=response_decision.recommended_actions,
        )

    return EventIngestResponse(
        status="success",
        message="Security event ingested successfully",
        event=persisted_event,
        incident_id=incident.id,
        risk_assessment=assessment,
        alert=alert,
        response_decision=response_decision,
    )


@router.get(
    "/{event_id}",
    response_model=SecurityEvent,
    summary="Retrieve an event by ID",
    description="Fetches a single security event by its unique ID from the Supabase repository.",
)
async def get_event(
    event_id: str,
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> SecurityEvent:
    """Retrieves an event by its ID."""
    event = await repo.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' not found.",
        )
    return event


@router.get(
    "",
    response_model=EventListResponse,
    summary="List security events",
    description="Retrieves a list of recent security events with optional filtering.",
)
async def list_events(
    limit: int = Query(default=50, ge=1, le=200, description="Max number of events to return"),
    offset: int = Query(default=0, ge=0, description="Number of events to skip"),
    user_id: Optional[str] = Query(default=None, description="Filter by user_id"),
    event_type: Optional[str] = Query(default=None, description="Filter by event_type"),
    agent_id: Optional[str] = Query(default=None, description="Filter by agent_id"),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> EventListResponse:
    """Lists stored security events with optional filtering."""
    events = await repo.list_events(
        limit=limit,
        offset=offset,
        user_id=user_id,
        event_type=event_type,
        agent_id=agent_id,
    )
    return EventListResponse(
        status="success",
        count=len(events),
        events=events,
    )
