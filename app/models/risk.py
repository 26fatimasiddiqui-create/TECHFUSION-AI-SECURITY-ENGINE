from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionResult(BaseModel):
    is_suspicious: bool = False
    signals: List[str] = Field(default_factory=list)
    details: dict = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    recommended_action: str
    correlated_signals: List[str] = Field(default_factory=list)
