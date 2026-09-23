from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.models.alert import SecurityAlert, AlertAcknowledgeRequest, AlertReplayRequest
from app.services.alert_service import AlertService
from app.api.dependencies import get_alert_service

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: 'acknowledged', 'resolved', 'escalated', 'active'")


@router.get("", response_model=List[SecurityAlert], summary="List security alerts")
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    risk_level: Optional[str] = Query(default=None, description="Filter by risk_level: LOW, MODERATE, HIGH, CRITICAL"),
    status: Optional[str] = Query(default=None, description="Filter by status: active, escalated, acknowledged, resolved"),
    acknowledged: Optional[bool] = Query(default=None, description="Filter by acknowledgement state"),
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Retrieve structured security alerts persisted in the system."""
    return await alert_svc.list_alerts(limit=limit, risk_level=risk_level, status=status, acknowledged=acknowledged)


@router.get("/active-critical", response_model=Optional[SecurityAlert], summary="Get active unacknowledged critical alert")
async def get_active_critical_alert(
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Retrieves the most recent active/unacknowledged critical security alert for banner rendering."""
    return await alert_svc.get_active_critical_alert()


@router.get("/{alert_id}", response_model=SecurityAlert, summary="Get security alert by ID")
async def get_alert(
    alert_id: str,
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Retrieve details of a single security alert."""
    alert = await alert_svc.get_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return alert


@router.patch("/{alert_id}", response_model=SecurityAlert, summary="Update alert status")
async def update_alert(
    alert_id: str,
    payload: AlertStatusUpdate,
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Update status of a security alert (e.g. acknowledge or resolve an incident)."""
    updated_alert = await alert_svc.update_alert_status(alert_id, payload.status)
    if not updated_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return updated_alert


@router.post("/{alert_id}/acknowledge", response_model=SecurityAlert, summary="Acknowledge security alert")
async def acknowledge_alert_endpoint(
    alert_id: str,
    payload: AlertAcknowledgeRequest = AlertAcknowledgeRequest(),
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Acknowledges a security alert. Confirms operator notice without resolving the underlying incident."""
    alert = await alert_svc.acknowledge_alert(
        alert_id=alert_id,
        actor=payload.actor,
        notes=payload.notes,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return alert


@router.post("/{alert_id}/replay-voice", response_model=SecurityAlert, summary="Replay voice alert")
async def replay_voice_endpoint(
    alert_id: str,
    payload: AlertReplayRequest = AlertReplayRequest(),
    alert_svc: AlertService = Depends(get_alert_service),
):
    """Records alert replay event in audit trail and returns voice message."""
    alert = await alert_svc.replay_alert(
        alert_id=alert_id,
        actor=payload.actor,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return alert
