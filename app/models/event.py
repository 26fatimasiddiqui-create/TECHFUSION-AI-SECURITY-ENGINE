from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, ConfigDict, field_validator


class EventType(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    API_ACCESS = "api_access"
    PRIVILEGE_CHANGE = "privilege_change"
    AGENT_INVOCATION = "agent_invocation"
    TOOL_INVOCATION = "tool_invocation"
    DATABASE_ACCESS = "database_access"
    DATA_ACCESS = "data_access"
    DEVICE_CHANGE = "device_change"
    CUSTOM = "custom"


def default_timestamp() -> datetime:
    return datetime.now(timezone.utc)


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    event_type: str
    timestamp: datetime = Field(default_factory=default_timestamp)
    resource: Optional[str] = None
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def normalize_id(cls, v: Any) -> str:
        if v is None or (isinstance(v, str) and not v.strip()):
            return str(uuid.uuid4())
        return str(v).strip()

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, v: Any) -> str:
        if not v or not str(v).strip():
            raise ValueError("event_type is required and cannot be blank")
        return str(v).strip().lower()

    @field_validator("user_id", "device_id", "session_id", "resource", "agent_id", "tool_name", mode="before")
    @classmethod
    def normalize_string_fields(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s if s else None

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        if v is None:
            return default_timestamp()
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, str):
            # Parse ISO string
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass
        return v

    @field_validator("metadata", mode="before")
    @classmethod
    def normalize_metadata(cls, v: Any) -> Dict[str, Any]:
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        raise ValueError("metadata must be a key-value dictionary")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "user_id": "U001",
                "device_id": "D001",
                "session_id": "sess_123",
                "event_type": "api_access",
                "timestamp": "2026-09-22T10:30:00Z",
                "resource": "/api/customer-data",
                "agent_id": None,
                "tool_name": None,
                "metadata": {}
            }
        }
    )
