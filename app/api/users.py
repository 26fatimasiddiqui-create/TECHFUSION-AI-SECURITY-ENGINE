from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import get_activity_graph_service
from app.models.graph import UserActivityGraphResponse, UserSummary
from app.services.activity_graph_service import ActivityGraphService

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get(
    "",
    response_model=List[UserSummary],
    summary="List all tracked users",
    description="Retrieves a list of all distinct users with activity summaries, event counts, and risk levels.",
)
async def list_users(
    service: ActivityGraphService = Depends(get_activity_graph_service),
) -> List[UserSummary]:
    """Lists distinct active users discovered across events and incidents."""
    return await service.list_users()


@router.get(
    "/{user_id}/activity-graph",
    response_model=UserActivityGraphResponse,
    summary="Retrieve User Activity Graph",
    description="Constructs and returns an individual user's connected activity graph over time, preserving chronology and evaluating baseline anomalies.",
)
async def get_user_activity_graph(
    user_id: str,
    start_time: Optional[datetime] = Query(default=None, description="Filter events on or after this timestamp"),
    end_time: Optional[datetime] = Query(default=None, description="Filter events on or before this timestamp"),
    limit: int = Query(default=100, ge=1, le=500, description="Max number of events to analyze"),
    service: ActivityGraphService = Depends(get_activity_graph_service),
) -> UserActivityGraphResponse:
    """Returns the connected User Activity Graph containing nodes, edges, chronological timeline,
    risk metadata, and linked incidents for the selected user.
    """
    return await service.build_user_activity_graph(
        user_id=user_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )
