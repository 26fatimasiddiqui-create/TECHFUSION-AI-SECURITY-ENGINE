from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment, DetectionResult
from app.models.incident import CorrelatedIncident
from app.services.detection_service import DetectionService
from app.services.correlation_service import CorrelationService
from app.services.cognee_service import CogneeService
from app.services.risk_service import RiskService
from app.services.agent_security_service import AgentSecurityService, AgentSecurityAnalysis
from app.services.external_threat_service import ExternalThreatService, ExternalThreatAnalysis
from app.repositories.supabase_repository import SupabaseRepository
from app.api.dependencies import (
    get_detection_service,
    get_correlation_service,
    get_cognee_service,
    get_risk_service,
    get_supabase_repository,
    get_agent_security_service,
    get_external_threat_service,
)

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


class AnalyzeRequest(BaseModel):
    event_id: Optional[str] = Field(default=None, description="ID of an existing stored event to analyze")
    event: Optional[SecurityEvent] = Field(default=None, description="Direct event object payload to analyze")

    # Allow flat event fields directly in root payload
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    event_type: Optional[str] = None
    resource: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class IncidentSummary(BaseModel):
    id: str
    primary_entity: str
    entity_type: str
    event_count: int
    signals_detected: List[str]


class AnalyzeResponse(BaseModel):
    status: str = "success"
    event: SecurityEvent
    detected_signals: List[str]
    detection: Optional[DetectionResult] = None
    correlated_incident: IncidentSummary
    relevant_context: Dict[str, Any]
    risk_score: int
    risk_level: str
    confidence: float
    reasons: List[str]
    recommended_action: str
    agent_analysis: Optional[AgentSecurityAnalysis] = None
    external_analysis: Optional[ExternalThreatAnalysis] = None


@router.post(
    "",
    response_model=AnalyzeResponse,
    summary="Analyze security event through intelligence pipeline",
    description=(
        "Transforms a security event through the PS-8 Intelligence Pipeline: "
        "Event -> Detection -> Correlation -> Cognee Historical Context -> Risk Scoring -> Explanation."
    ),
)
async def analyze_event(
    request: AnalyzeRequest,
    detection_svc: DetectionService = Depends(get_detection_service),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
    cognee_svc: CogneeService = Depends(get_cognee_service),
    risk_svc: RiskService = Depends(get_risk_service),
    agent_sec_svc: AgentSecurityService = Depends(get_agent_security_service),
    external_threat_svc: ExternalThreatService = Depends(get_external_threat_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
) -> AnalyzeResponse:
    # 1. Resolve target event: either from event_id or from provided payload
    target_event: Optional[SecurityEvent] = None

    if request.event_id:
        target_event = await repo.get_event_by_id(request.event_id)
        if not target_event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security event with ID '{request.event_id}' not found in database.",
            )
    elif request.event:
        target_event = request.event
    elif request.event_type:
        # User passed flat event fields in root payload
        target_event = SecurityEvent(
            user_id=request.user_id,
            device_id=request.device_id,
            session_id=request.session_id,
            event_type=request.event_type,
            resource=request.resource,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            metadata=request.metadata or {},
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'event_id', an 'event' object, or valid event fields (including 'event_type') must be provided.",
        )

    # 2. Historical Context (Cognee / baseline knowledge graph)
    context = await cognee_svc.get_historical_context(target_event)

    # 3. Detection Engine
    detection = detection_svc.analyze_event(target_event, historical_context=context)

    # 4. Correlation Engine (matches time window & entity chain)
    incident, correlated_signals = correlation_svc.correlate_event(target_event, detection.signals)

    # 5. Deep Security Analysis: AI Agent (Area 2)
    agent_res: Optional[AgentSecurityAnalysis] = None
    if target_event.agent_id or target_event.tool_name or (target_event.metadata and any(k in str(target_event.metadata).lower() for k in ["agent", "prompt", "tool"])):
        agent_res = agent_sec_svc.analyze_agent_event(target_event, incident.events)
        for sig in agent_res.detected_signals:
            if sig not in correlated_signals:
                correlated_signals.append(sig)

    # 6. Deep Security Analysis: External Threat (Area 3)
    external_res: Optional[ExternalThreatAnalysis] = None
    ext_ip = external_threat_svc.extract_ip(target_event)
    if ext_ip or target_event.metadata.get("ip") or target_event.metadata.get("client_ip"):
        external_res = external_threat_svc.analyze_external_threat(target_event, incident.events)
        if external_res.threat_type and external_res.threat_type not in correlated_signals:
            correlated_signals.append(external_res.threat_type)

    # 7. Risk Scoring & Explanation Engine
    assessment: RiskAssessment = risk_svc.assess_risk(
        signals=correlated_signals,
        context=context,
        correlated_event_count=len(incident.events),
    )

    incident_summary = IncidentSummary(
        id=incident.id,
        primary_entity=incident.primary_entity,
        entity_type=incident.entity_type,
        event_count=len(incident.events),
        signals_detected=incident.signals_detected,
    )

    return AnalyzeResponse(
        status="success",
        event=target_event,
        detected_signals=detection.signals,
        detection=detection,
        correlated_incident=incident_summary,
        relevant_context=context,
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level.value,
        confidence=assessment.confidence,
        reasons=assessment.reasons,
        recommended_action=assessment.recommended_action,
        agent_analysis=agent_res,
        external_analysis=external_res,
    )


@router.get("/agents", summary="List tracked AI agents and baselines")
async def list_agents(
    agent_sec_svc: AgentSecurityService = Depends(get_agent_security_service),
):
    return {"status": "success", "agents": agent_sec_svc.list_tracked_agents()}


@router.get("/agent/{agent_id}", response_model=AgentSecurityAnalysis, summary="Deep security analysis for AI agent")
async def get_agent_analysis(
    agent_id: str,
    agent_sec_svc: AgentSecurityService = Depends(get_agent_security_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
):
    events = await repo.list_events(limit=50)
    agent_events = [e for e in events if (e.agent_id or "").lower() == agent_id.lower() or (e.tool_name and "agent" in agent_id.lower())]
    if agent_events:
        target_event = agent_events[-1]
    else:
        target_event = SecurityEvent(
            user_id="U_ANALYST",
            agent_id=agent_id,
            tool_name="hr_directory_lookup" if "hr" in agent_id.lower() else "doc_search",
            event_type="agent_invocation",
            resource="/api/hr/profile" if "hr" in agent_id.lower() else "/api/docs",
            metadata={"status": "baseline"},
        )
    return agent_sec_svc.analyze_agent_event(target_event, agent_events)


@router.get("/external-threats", summary="List external threat source profiles")
async def list_external_threats(
    external_threat_svc: ExternalThreatService = Depends(get_external_threat_service),
):
    return {"status": "success", "sources": external_threat_svc.list_threat_profiles()}


@router.get("/external/{source_ip}", response_model=ExternalThreatAnalysis, summary="Deep behavioral progression analysis for external source")
async def get_external_threat_analysis(
    source_ip: str,
    external_threat_svc: ExternalThreatService = Depends(get_external_threat_service),
    repo: SupabaseRepository = Depends(get_supabase_repository),
):
    events = await repo.list_events(limit=50)
    ip_events = [e for e in events if external_threat_svc.extract_ip(e) == source_ip]
    if ip_events:
        target_event = ip_events[-1]
    else:
        target_event = SecurityEvent(
            user_id="U_ANALYST",
            device_id="Unknown Device",
            event_type="login",
            resource="/auth/login",
            metadata={"ip": source_ip, "origin_ip": source_ip},
        )
    return external_threat_svc.analyze_external_threat(target_event, ip_events)
