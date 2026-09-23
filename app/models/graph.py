from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    USER = "User"
    LOGIN = "Login"
    SESSION = "Session"
    DEVICE = "Device"
    IP = "IP"
    API = "API"
    AI_AGENT = "AI Agent"
    TOOL = "Tool"
    RESOURCE = "Resource"
    DATABASE = "Database"


class RelationshipType(str, Enum):
    USER_PERFORMED_LOGIN = "USER_PERFORMED_LOGIN"
    USER_USED_DEVICE = "USER_USED_DEVICE"
    DEVICE_CONNECTED_FROM_IP = "DEVICE_CONNECTED_FROM_IP"
    USER_CREATED_SESSION = "USER_CREATED_SESSION"
    USER_CALLED_API = "USER_CALLED_API"
    USER_INVOKED_AGENT = "USER_INVOKED_AGENT"
    AGENT_USED_TOOL = "AGENT_USED_TOOL"
    API_ACCESSED_RESOURCE = "API_ACCESSED_RESOURCE"
    TOOL_ACCESSED_RESOURCE = "TOOL_ACCESSED_RESOURCE"
    # External threat relationships
    EXTERNAL_SOURCE = "EXTERNAL_SOURCE"
    TARGETED = "TARGETED"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    CALLED = "CALLED"
    INVOKED = "INVOKED"
    USED_TOOL = "USED_TOOL"
    ACCESSED = "ACCESSED"
    EXFILTRATED = "EXFILTRATED"


class ActivityRiskLevel(str, Enum):
    NORMAL = "normal"
    UNUSUAL = "unusual"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high-risk"


class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    risk_level: ActivityRiskLevel = ActivityRiskLevel.NORMAL
    first_seen: datetime
    last_seen: datetime
    event_ids: List[str] = Field(default_factory=list)
    event_types: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: RelationshipType
    risk_level: ActivityRiskLevel = ActivityRiskLevel.NORMAL
    signals: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    timestamp: datetime
    sequence_order: int
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TimelineStep(BaseModel):
    step: int
    timestamp: datetime
    event_id: str
    event_type: str
    source_node: str
    target_node: str
    relationship: RelationshipType
    risk_level: ActivityRiskLevel = ActivityRiskLevel.NORMAL
    signals: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    description: str
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphSummary(BaseModel):
    user_id: str
    total_events: int
    node_count: int
    edge_count: int
    risk_level: ActivityRiskLevel = ActivityRiskLevel.NORMAL
    risk_score: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    incident_ids: List[str] = Field(default_factory=list)
    dominant_signals: List[str] = Field(default_factory=list)


class UserActivityGraphResponse(BaseModel):
    status: str = "success"
    user_id: str
    summary: GraphSummary
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    timeline: List[TimelineStep]
    incidents: List[Dict[str, Any]] = Field(default_factory=list)


class UserSummary(BaseModel):
    user_id: str
    event_count: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    highest_risk_level: ActivityRiskLevel = ActivityRiskLevel.NORMAL
    incident_count: int = 0
