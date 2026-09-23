from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field, ConfigDict
from app.models.risk import RiskLevel


class SecurityAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    risk_level: str
    risk_score: int
    reasons: List[str] = Field(default_factory=list)
    recommended_action: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"  # active, escalated, acknowledged, resolved
    simulated_action_taken: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Step 6: Voice Alerts + High-Risk Alert UX fields
    threat_type: Optional[str] = None
    message: Optional[str] = None
    voice_message: Optional[str] = None
    voice_alert_required: bool = False
    voice_played: bool = False
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    approval_required: bool = False
    approval_state: Optional[str] = None
    response_state: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    affected_entity: Optional[str] = None

    # Convenience aliases
    @property
    def id(self) -> str:
        return self.alert_id

    @property
    def severity(self) -> str:
        return self.risk_level

    @property
    def created_at(self) -> datetime:
        return self.timestamp

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "alert_id": "ALT-A1B2C3D4",
                "incident_id": "INC-7E8F9A0B",
                "risk_level": "HIGH",
                "risk_score": 75,
                "threat_type": "External attack chain",
                "message": "High security alert. External attack chain detected. Risk score 75. Review required.",
                "voice_message": "HIGH security alert. External attack chain detected for user Aarav. Risk score 75. Review recommended.",
                "voice_alert_required": True,
                "acknowledged": False,
                "approval_required": True,
                "approval_state": "PENDING_APPROVAL",
                "reasons": [
                    "Login originated from an unknown device",
                    "Sensitive API was accessed",
                    "Agent invoked an unusual tool"
                ],
                "recommended_action": "Require verification / restrict sensitive access",
                "timestamp": "2026-09-22T01:45:00Z",
                "status": "active",
                "simulated_action_taken": "Simulated restriction on endpoint /api/customer-data"
            }
        }
    )


class AlertAcknowledgeRequest(BaseModel):
    actor: str = "SOC_Analyst"
    notes: Optional[str] = None


class AlertReplayRequest(BaseModel):
    actor: str = "SOC_Analyst"
