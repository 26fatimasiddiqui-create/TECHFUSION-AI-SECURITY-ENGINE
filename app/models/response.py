from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    MONITOR = "MONITOR"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RESTRICT_SESSION = "RESTRICT_SESSION"
    TERMINATE_SESSION = "TERMINATE_SESSION"
    RESTRICT_API = "RESTRICT_API"
    BLOCK_SOURCE = "BLOCK_SOURCE"
    RESTRICT_RESOURCE = "RESTRICT_RESOURCE"
    CONTAIN_AGENT = "CONTAIN_AGENT"
    CREATE_INCIDENT = "CREATE_INCIDENT"
    CREATE_AUDIT_ENTRY = "CREATE_AUDIT_ENTRY"


class ActionStatus(str, Enum):
    RECOMMENDED = "RECOMMENDED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    SIMULATED = "SIMULATED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    RESOLVED = "RESOLVED"


class ExecutionMode(str, Enum):
    SIMULATED = "SIMULATED"
    LIVE = "LIVE"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}")
    action_type: ActionType
    target: str
    target_type: str  # "user", "session", "ip", "api", "agent", "tool", "resource"
    reason: str
    risk_score: int = Field(ge=0, le=100)
    severity: str  # "LOW", "MODERATE", "HIGH", "CRITICAL"
    status: ActionStatus = ActionStatus.RECOMMENDED
    execution_mode: ExecutionMode = ExecutionMode.SIMULATED
    requires_human_approval: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    requested_by: str = "RiskEngine"
    approved_by: Optional[str] = None
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executed_at: Optional[datetime] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ResponseDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: f"DEC-{uuid.uuid4().hex[:8].upper()}")
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    risk_score: int = Field(ge=0, le=100)
    severity: str
    response_level: str  # "LOW", "MODERATE", "HIGH", "CRITICAL"
    requires_human_approval: bool = False
    approval_required: bool = False  # Explicit alias for direct n8n IF/Switch evaluation
    dry_run: bool = True
    recommended_actions: List[str] = Field(default_factory=list)
    executable_actions: List[ResponseAction] = Field(default_factory=list)
    action_status: str = "RECOMMENDED"  # "MONITORING", "PENDING_APPROVAL", "SIMULATED", "EXECUTED", "RESOLVED"
    reasons: List[str] = Field(default_factory=list)
    primary_user: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    audit_id: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    action_id: Optional[str] = None
    action: str
    target: str
    target_type: Optional[str] = None
    risk_score: int = Field(ge=0, le=100)
    severity: str
    reason: str
    status: str
    approval_status: str = "NOT_REQUIRED"
    execution_mode: str = "SIMULATED"
    actor: str = "System"  # "System", "RiskEngine", "SecurityAnalyst", "n8n"
    details: Dict[str, Any] = Field(default_factory=dict)


class ApprovalState(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVER_1_REVIEW = "APPROVER_1_REVIEW"
    APPROVER_1_APPROVED = "APPROVER_1_APPROVED"
    APPROVER_2_REQUIRED = "APPROVER_2_REQUIRED"
    APPROVER_2_REVIEW = "APPROVER_2_REVIEW"
    APPROVED_FOR_EXECUTION = "APPROVED_FOR_EXECUTION"
    APPROVAL_BLOCKED = "APPROVAL_BLOCKED"
    REQUIRES_INDEPENDENT_VERIFICATION = "REQUIRES_INDEPENDENT_VERIFICATION"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    SIMULATED = "SIMULATED"
    EXECUTED = "EXECUTED"
    RESOLVED = "RESOLVED"


class ApproverRole(str, Enum):
    SECURITY_ANALYST = "SECURITY_ANALYST"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SYSTEM_OWNER = "SYSTEM_OWNER"


class ApproverRiskEvaluation(BaseModel):
    approver_id: str
    approver_role: str
    approver_risk_score: int = Field(ge=0, le=100)
    approver_risk_level: str  # "LOW", "MODERATE", "HIGH", "CRITICAL"
    approval_allowed: bool
    requires_independent_verification: bool
    reasons: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context_signals: List[str] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"APPR-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    state: ApprovalState = ApprovalState.PENDING_APPROVAL
    two_person_rule_required: bool = True
    approver_1_id: Optional[str] = None
    approver_1_role: Optional[str] = None
    approver_1_risk_score: Optional[int] = None
    approver_1_risk_level: Optional[str] = None
    approver_1_approved_at: Optional[datetime] = None
    approver_1_reasons: List[str] = Field(default_factory=list)
    approver_1_session_id: Optional[str] = None
    approver_1_ip: Optional[str] = None
    approver_1_device_id: Optional[str] = None
    approver_2_id: Optional[str] = None
    approver_2_role: Optional[str] = None
    approver_2_risk_score: Optional[int] = None
    approver_2_risk_level: Optional[str] = None
    approver_2_approved_at: Optional[datetime] = None
    approver_2_reasons: List[str] = Field(default_factory=list)
    approver_2_session_id: Optional[str] = None
    approver_2_ip: Optional[str] = None
    approver_2_device_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_expired: bool = False
    rejection_reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApproverEvaluationRequest(BaseModel):
    approver_id: str
    role: str = "SECURITY_ANALYST"
    session_id: Optional[str] = None
    ip: Optional[str] = None
    device_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    actor: str = "SecurityAnalyst"
    approver_id: Optional[str] = None
    role: Optional[str] = "SECURITY_ANALYST"
    session_id: Optional[str] = None
    ip: Optional[str] = None
    device_id: Optional[str] = None
    notes: Optional[str] = None
    reason: Optional[str] = None
    dry_run: Optional[bool] = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecondApprovalRequest(BaseModel):
    actor: str = "SecurityAdmin"
    approver_id: Optional[str] = None
    role: Optional[str] = "SECURITY_ADMIN"
    session_id: Optional[str] = None
    ip: Optional[str] = None
    device_id: Optional[str] = None
    notes: Optional[str] = None
    reason: Optional[str] = None
    dry_run: Optional[bool] = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RecoveryRequest(BaseModel):
    actor: str = "SecurityAnalyst"
    reason: str = "Analyst verified benign false-positive activity"

