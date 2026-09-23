from datetime import datetime, timezone
from typing import List, Optional
import uuid
from pydantic import BaseModel, Field
from app.models.event import SecurityEvent
from app.models.risk import RiskAssessment


class CorrelatedIncident(BaseModel):
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    primary_entity: str
    entity_type: str  # user, device, session, agent
    event_ids: List[str] = Field(default_factory=list)
    events: List[SecurityEvent] = Field(default_factory=list)
    signals_detected: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_assessment: Optional[RiskAssessment] = None
    status: str = "active"  # active, mitigated, archived
