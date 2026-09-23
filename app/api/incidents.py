from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.models.incident import CorrelatedIncident
from app.repositories.supabase_repository import SupabaseRepository
from app.services.correlation_service import CorrelationService
from app.api.dependencies import get_supabase_repository, get_correlation_service

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=List[CorrelatedIncident])
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    repo: SupabaseRepository = Depends(get_supabase_repository),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
):
    """Retrieve all correlated security incidents."""
    incidents = await repo.list_incidents(limit=limit)
    if not incidents:
        # Fallback to in-memory active incidents in correlation service
        incidents = correlation_svc.list_incidents()[:limit]
    return incidents


@router.get("/{incident_id}", response_model=CorrelatedIncident)
async def get_incident(
    incident_id: str,
    repo: SupabaseRepository = Depends(get_supabase_repository),
    correlation_svc: CorrelationService = Depends(get_correlation_service),
):
    """Retrieve details and correlated timeline of a specific security incident."""
    incident = await repo.get_incident(incident_id)
    if not incident:
        incident = correlation_svc.get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found"
        )
    return incident
