import logging
from typing import Any, Dict, List, Optional
from app.core.supabase import get_supabase_client
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


class SupabaseRepository:
    """Data access repository for interacting with Supabase.
    Encapsulates database operations for security events with robust error handling
    and an in-memory fallback for local development and testing.
    """

    TABLE_NAME = "events"

    def __init__(self):
        # In-memory storage cache used for fallback or testing
        self._memory_events: Dict[str, SecurityEvent] = {}

    @property
    def client(self):
        """Lazy access to initialized Supabase client."""
        return get_supabase_client()

    async def insert_event(self, event: SecurityEvent) -> SecurityEvent:
        """Persists a normalized security event into the Supabase 'events' table.
        Falls back safely to in-memory store if database is unreachable or unconfigured.
        """
        # Always maintain in memory store
        self._memory_events[event.id] = event

        client = self.client
        if client:
            try:
                row_data = {
                    "id": event.id,
                    "user_id": event.user_id,
                    "device_id": event.device_id,
                    "session_id": event.session_id,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp.isoformat(),
                    "resource": event.resource,
                    "agent_id": event.agent_id,
                    "tool_name": event.tool_name,
                    "metadata": event.metadata,
                }
                client.table(self.TABLE_NAME).insert(row_data).execute()
                logger.debug(f"Event {event.id} persisted to Supabase table '{self.TABLE_NAME}'.")
            except Exception as e:
                logger.error(f"Error persisting event {event.id} to Supabase: {e}")
                # Preserved in-memory, do not crash ingestion
        return event

    async def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Retrieves an event by its unique ID."""
        client = self.client
        if client:
            try:
                resp = client.table(self.TABLE_NAME).select("*").eq("id", event_id).execute()
                if resp.data and len(resp.data) > 0:
                    return SecurityEvent(**resp.data[0])
            except Exception as e:
                logger.error(f"Error fetching event {event_id} from Supabase: {e}")

        return self._memory_events.get(event_id)

    async def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Lists events with optional filtering by user_id, event_type, or agent_id."""
        client = self.client
        if client:
            try:
                query = client.table(self.TABLE_NAME).select("*").order("timestamp", desc=True)
                if user_id:
                    query = query.eq("user_id", user_id)
                if event_type:
                    query = query.eq("event_type", event_type.lower())
                if agent_id:
                    query = query.eq("agent_id", agent_id)
                
                resp = query.range(offset, offset + limit - 1).execute()
                if resp.data is not None:
                    return [SecurityEvent(**item) for item in resp.data]
            except Exception as e:
                logger.error(f"Error listing events from Supabase: {e}")

        # In-memory fallback with filtering
        events = list(self._memory_events.values())
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        if event_type:
            events = [e for e in events if e.event_type.lower() == event_type.lower()]
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]

        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[offset : offset + limit]

    async def list_distinct_users(self) -> List[str]:
        """Returns a list of distinct user IDs found in events and incidents."""
        users = set()
        client = self.client
        if client:
            try:
                resp = client.table(self.TABLE_NAME).select("user_id").execute()
                if resp.data:
                    for row in resp.data:
                        if row.get("user_id"):
                            users.add(str(row["user_id"]))
            except Exception as e:
                logger.error(f"Error fetching distinct users from Supabase: {e}")

        for e in self._memory_events.values():
            if e.user_id:
                users.add(e.user_id)

        if hasattr(self, "_memory_incidents"):
            for inc in self._memory_incidents.values():
                if getattr(inc, "primary_entity", None) and getattr(inc, "entity_type", None) == "user":
                    users.add(inc.primary_entity)

        return sorted(list(users))

    # --- Incidents ---

    async def save_incident(self, incident: Any) -> Any:
        """Saves a correlated security incident to Supabase and memory fallback."""
        if not hasattr(self, "_memory_incidents"):
            self._memory_incidents = {}
        self._memory_incidents[incident.id] = incident

        client = self.client
        if client:
            try:
                row_data = {
                    "id": incident.id,
                    "primary_entity": incident.primary_entity,
                    "entity_type": incident.entity_type,
                    "event_ids": incident.event_ids,
                    "signals_detected": incident.signals_detected,
                    "created_at": incident.created_at.isoformat(),
                    "updated_at": incident.updated_at.isoformat(),
                    "risk_assessment": incident.risk_assessment.model_dump(mode="json") if incident.risk_assessment else None,
                    "status": incident.status,
                }
                client.table("incidents").upsert(row_data).execute()
            except Exception as e:
                logger.error(f"Error saving incident {incident.id} to Supabase: {e}")

        return incident

    async def get_incident(self, incident_id: str) -> Optional[Any]:
        """Fetches an incident by ID."""
        client = self.client
        if client:
            try:
                resp = client.table("incidents").select("*").eq("id", incident_id).execute()
                if resp.data and len(resp.data) > 0:
                    from app.models.incident import CorrelatedIncident
                    return CorrelatedIncident(**resp.data[0])
            except Exception as e:
                logger.error(f"Error fetching incident {incident_id} from Supabase: {e}")

        if not hasattr(self, "_memory_incidents"):
            self._memory_incidents = {}
        return self._memory_incidents.get(incident_id)

    async def list_incidents(self, limit: int = 50) -> List[Any]:
        """Lists incidents from Supabase."""
        client = self.client
        if client:
            try:
                resp = client.table("incidents").select("*").order("updated_at", desc=True).limit(limit).execute()
                if resp.data is not None:
                    from app.models.incident import CorrelatedIncident
                    return [CorrelatedIncident(**item) for item in resp.data]
            except Exception as e:
                logger.error(f"Error listing incidents from Supabase: {e}")

        if not hasattr(self, "_memory_incidents"):
            self._memory_incidents = {}
        return list(self._memory_incidents.values())[:limit]

    # --- Alerts ---

    async def save_alert(self, alert: Any) -> Any:
        """Saves a security alert to Supabase and memory fallback."""
        alert_id = getattr(alert, "alert_id", getattr(alert, "id", None))
        if not hasattr(self, "_memory_alerts"):
            self._memory_alerts = {}
        self._memory_alerts[alert_id] = alert

        client = self.client
        if client:
            try:
                row_data = {
                    "id": alert_id,
                    "incident_id": alert.incident_id,
                    "event_id": alert.event_id,
                    "title": alert.title,
                    "description": alert.description,
                    "risk_level": alert.risk_level,
                    "risk_score": alert.risk_score,
                    "reasons": alert.reasons,
                    "recommended_action": alert.recommended_action,
                    "created_at": alert.timestamp.isoformat(),
                    "status": alert.status,
                    "metadata": alert.metadata,
                }
                client.table("alerts").upsert(row_data).execute()
            except Exception as e:
                logger.error(f"Error saving alert {alert_id} to Supabase: {e}")

        return alert

    async def get_alert(self, alert_id: str) -> Optional[Any]:
        """Fetches an alert by ID."""
        client = self.client
        if client:
            try:
                resp = client.table("alerts").select("*").eq("id", alert_id).execute()
                if resp.data and len(resp.data) > 0:
                    from app.models.alert import SecurityAlert
                    item = resp.data[0]
                    # Map 'id' column back to alert_id
                    item["alert_id"] = item.get("id")
                    if "created_at" in item:
                        item["timestamp"] = item["created_at"]
                    return SecurityAlert(**item)
            except Exception as e:
                logger.error(f"Error fetching alert {alert_id} from Supabase: {e}")

        if not hasattr(self, "_memory_alerts"):
            self._memory_alerts = {}
        return self._memory_alerts.get(alert_id)

    async def list_alerts(
        self,
        limit: int = 50,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Any]:
        """Lists alerts from Supabase with optional risk_level or status filtering."""
        client = self.client
        if client:
            try:
                query = client.table("alerts").select("*").order("created_at", desc=True)
                if risk_level:
                    query = query.eq("risk_level", risk_level.upper())
                if status:
                    query = query.eq("status", status)
                resp = query.limit(limit).execute()
                if resp.data is not None:
                    from app.models.alert import SecurityAlert
                    results = []
                    for item in resp.data:
                        item["alert_id"] = item.get("id")
                        if "created_at" in item:
                            item["timestamp"] = item["created_at"]
                        results.append(SecurityAlert(**item))
                    return results
            except Exception as e:
                logger.error(f"Error listing alerts from Supabase: {e}")

        if not hasattr(self, "_memory_alerts"):
            self._memory_alerts = {}
        alerts = list(self._memory_alerts.values())
        if risk_level:
            alerts = [a for a in alerts if a.risk_level.upper() == risk_level.upper()]
        if status:
            alerts = [a for a in alerts if a.status.lower() == status.lower()]
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts[:limit]

    # --- Response Actions & Audit Logs (Step 4) ---

    async def save_response_action(self, action: Any) -> Any:
        action_id = getattr(action, "action_id", None)
        if not hasattr(self, "_memory_response_actions"):
            self._memory_response_actions = {}
        if action_id:
            self._memory_response_actions[action_id] = action

        client = self.client
        if client:
            try:
                row_data = {
                    "id": action_id,
                    "action_type": action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type),
                    "target": action.target,
                    "target_type": action.target_type,
                    "reason": action.reason,
                    "risk_score": action.risk_score,
                    "severity": action.severity,
                    "status": action.status.value if hasattr(action.status, "value") else str(action.status),
                    "execution_mode": action.execution_mode.value if hasattr(action.execution_mode, "value") else str(action.execution_mode),
                    "requires_human_approval": action.requires_human_approval,
                    "approval_status": action.approval_status.value if hasattr(action.approval_status, "value") else str(action.approval_status),
                    "requested_by": action.requested_by,
                    "approved_by": action.approved_by,
                    "incident_id": action.incident_id,
                    "event_id": action.event_id,
                    "created_at": action.timestamp.isoformat(),
                    "details": action.details,
                }
                client.table("response_actions").upsert(row_data).execute()
            except Exception as e:
                logger.error(f"Error saving response action {action_id} to Supabase: {e}")

        return action

    async def get_response_action(self, action_id: str) -> Optional[Any]:
        client = self.client
        if client:
            try:
                resp = client.table("response_actions").select("*").eq("id", action_id).execute()
                if resp.data and len(resp.data) > 0:
                    from app.models.response import ResponseAction
                    item = resp.data[0]
                    item["action_id"] = item.get("id")
                    if "created_at" in item:
                        item["timestamp"] = item["created_at"]
                    return ResponseAction(**item)
            except Exception as e:
                logger.error(f"Error fetching response action {action_id} from Supabase: {e}")

        if not hasattr(self, "_memory_response_actions"):
            self._memory_response_actions = {}
        return self._memory_response_actions.get(action_id)

    async def list_response_actions(self, incident_id: Optional[str] = None) -> List[Any]:
        client = self.client
        if client:
            try:
                query = client.table("response_actions").select("*").order("created_at", desc=True)
                if incident_id:
                    query = query.eq("incident_id", incident_id)
                resp = query.execute()
                if resp.data is not None:
                    from app.models.response import ResponseAction
                    results = []
                    for item in resp.data:
                        item["action_id"] = item.get("id")
                        if "created_at" in item:
                            item["timestamp"] = item["created_at"]
                        results.append(ResponseAction(**item))
                    return results
            except Exception as e:
                logger.error(f"Error listing response actions from Supabase: {e}")

        if not hasattr(self, "_memory_response_actions"):
            self._memory_response_actions = {}
        actions = list(self._memory_response_actions.values())
        if incident_id:
            actions = [a for a in actions if a.incident_id == incident_id]
        actions.sort(key=lambda a: a.timestamp, reverse=True)
        return actions

    async def save_audit_entry(self, entry: Any) -> Any:
        audit_id = getattr(entry, "audit_id", None)
        if not hasattr(self, "_memory_audit_trail"):
            self._memory_audit_trail = []
        self._memory_audit_trail.append(entry)

        client = self.client
        if client:
            try:
                row_data = {
                    "id": audit_id,
                    "incident_id": entry.incident_id,
                    "event_id": entry.event_id,
                    "action_id": entry.action_id,
                    "action": entry.action,
                    "target": entry.target,
                    "target_type": entry.target_type,
                    "risk_score": entry.risk_score,
                    "severity": entry.severity,
                    "reason": entry.reason,
                    "status": entry.status,
                    "approval_status": entry.approval_status,
                    "execution_mode": entry.execution_mode,
                    "actor": entry.actor,
                    "created_at": entry.timestamp.isoformat(),
                    "details": entry.details,
                }
                client.table("audit_logs").insert(row_data).execute()
            except Exception as e:
                logger.error(f"Error saving audit entry {audit_id} to Supabase: {e}")

        return entry

    async def list_audit_entries(self, incident_id: Optional[str] = None, limit: int = 100) -> List[Any]:
        client = self.client
        if client:
            try:
                query = client.table("audit_logs").select("*").order("created_at", desc=True)
                if incident_id:
                    query = query.eq("incident_id", incident_id)
                resp = query.limit(limit).execute()
                if resp.data is not None:
                    from app.models.response import AuditEntry
                    results = []
                    for item in resp.data:
                        item["audit_id"] = item.get("id")
                        if "created_at" in item:
                            item["timestamp"] = item["created_at"]
                        results.append(AuditEntry(**item))
                    return results
            except Exception as e:
                logger.error(f"Error listing audit logs from Supabase: {e}")

        if not hasattr(self, "_memory_audit_trail"):
            self._memory_audit_trail = []
        entries = list(self._memory_audit_trail)
        if incident_id:
            entries = [e for e in entries if e.incident_id == incident_id]
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]

    # --- Step 5: Approval Records (Two-Person Rule & Compromised Approver) ---

    async def save_approval_record(self, record: Any) -> Any:
        incident_id = getattr(record, "incident_id", None)
        if not hasattr(self, "_memory_approval_records"):
            self._memory_approval_records = {}
        if incident_id:
            self._memory_approval_records[incident_id] = record

        client = self.client
        if client:
            try:
                row_data = {
                    "id": record.approval_id,
                    "incident_id": record.incident_id,
                    "state": record.state.value if hasattr(record.state, "value") else str(record.state),
                    "two_person_rule_required": record.two_person_rule_required,
                    "approver_1_id": record.approver_1_id,
                    "approver_1_role": record.approver_1_role,
                    "approver_1_risk_score": record.approver_1_risk_score,
                    "approver_1_risk_level": record.approver_1_risk_level,
                    "approver_1_approved_at": record.approver_1_approved_at.isoformat() if record.approver_1_approved_at else None,
                    "approver_2_id": record.approver_2_id,
                    "approver_2_role": record.approver_2_role,
                    "approver_2_risk_score": record.approver_2_risk_score,
                    "approver_2_risk_level": record.approver_2_risk_level,
                    "approver_2_approved_at": record.approver_2_approved_at.isoformat() if record.approver_2_approved_at else None,
                    "created_at": record.created_at.isoformat(),
                    "expires_at": record.expires_at.isoformat(),
                    "rejection_reason": record.rejection_reason,
                    "metadata": record.metadata,
                }
                client.table("response_approval_records").upsert(row_data).execute()
            except Exception as e:
                logger.error(f"Error saving approval record to Supabase: {e}")

        return record

    async def get_approval_record(self, incident_id: str) -> Optional[Any]:
        client = self.client
        if client:
            try:
                resp = client.table("response_approval_records").select("*").eq("incident_id", incident_id).execute()
                if resp.data and len(resp.data) > 0:
                    from app.models.response import ApprovalRecord
                    item = resp.data[0]
                    item["approval_id"] = item.get("id")
                    return ApprovalRecord(**item)
            except Exception as e:
                logger.error(f"Error fetching approval record for {incident_id} from Supabase: {e}")

        if not hasattr(self, "_memory_approval_records"):
            self._memory_approval_records = {}
        return self._memory_approval_records.get(incident_id)

