from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from app.models.event import SecurityEvent, EventType
from app.models.incident import CorrelatedIncident
from app.core.config import settings


class CorrelationService:
    """Correlates security events within sliding time windows across entities
    (user, session, device, agent, resource).
    Transforms discrete events into a unified incident context.
    """

    def __init__(self, time_window_minutes: Optional[int] = None):
        self.time_window = timedelta(minutes=time_window_minutes or settings.CORRELATION_WINDOW_MINUTES)
        # Incident storage: incident_id -> CorrelatedIncident
        self.active_incidents: Dict[str, CorrelatedIncident] = {}
        # Entity mapping to active incident_id: entity_key -> incident_id
        self.entity_incident_map: Dict[str, str] = {}

    def correlate_event(
        self,
        event: SecurityEvent,
        detected_signals: List[str]
    ) -> Tuple[CorrelatedIncident, List[str]]:
        """Finds or creates an incident for the event, correlates related events,
        and aggregates collective signals across the entire incident sequence.
        """
        now = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)

        # Entity candidate keys for correlation (user, session, device, IP, agent)
        candidate_keys = []
        if event.session_id:
            candidate_keys.append(f"session:{event.session_id}")
        if event.user_id:
            candidate_keys.append(f"user:{event.user_id}")
        if event.device_id:
            candidate_keys.append(f"device:{event.device_id}")
        if event.agent_id:
            candidate_keys.append(f"agent:{event.agent_id}")

        target_user = event.metadata.get("target_user") or event.metadata.get("targeted_user")
        if target_user:
            candidate_keys.append(f"user:{target_user}")

        ip_val = (
            event.metadata.get("ip")
            or event.metadata.get("ip_address")
            or event.metadata.get("client_ip")
            or event.metadata.get("source_ip")
            or event.metadata.get("external_ip")
        )
        if ip_val:
            candidate_keys.append(f"ip:{str(ip_val).strip()}")

        matched_incident: Optional[CorrelatedIncident] = None

        # Check for active incident matching any candidate key
        for key in candidate_keys:
            if key in self.entity_incident_map:
                inc_id = self.entity_incident_map[key]
                inc = self.active_incidents.get(inc_id)
                if inc and inc.status == "active":
                    last_update = inc.updated_at if inc.updated_at.tzinfo else inc.updated_at.replace(tzinfo=timezone.utc)
                    if (now - last_update) <= self.time_window:
                        matched_incident = inc
                        break
                    else:
                        inc.status = "archived"

        # If no active incident exists, initialize a new one
        if not matched_incident:
            primary_entity = (
                event.user_id or event.agent_id or event.device_id or event.session_id or (f"ip:{ip_val}" if ip_val else "unknown")
            )
            entity_type = (
                "user" if event.user_id else
                "agent" if event.agent_id else
                "device" if event.device_id else
                "session" if event.session_id else
                "ip" if ip_val else "system"
            )
            matched_incident = CorrelatedIncident(
                primary_entity=primary_entity,
                entity_type=entity_type,
                event_ids=[],
                events=[],
                signals_detected=[],
                created_at=now,
                updated_at=now
            )
            self.active_incidents[matched_incident.id] = matched_incident

        # Update matched incident
        if event.id not in matched_incident.event_ids:
            matched_incident.event_ids.append(event.id)
            matched_incident.events.append(event)
        matched_incident.updated_at = now

        # Map all candidate keys to this incident for subsequent lookup
        for key in candidate_keys:
            self.entity_incident_map[key] = matched_incident.id

        # Merge newly detected signals
        for sig in detected_signals:
            if sig not in matched_incident.signals_detected:
                matched_incident.signals_detected.append(sig)

        # Correlation Pattern Check: Repeated failed logins
        failed_logins = sum(
            1 for e in matched_incident.events
            if e.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]
        )
        if failed_logins >= 2 and "repeated_failed_login" not in matched_incident.signals_detected:
            matched_incident.signals_detected.append("repeated_failed_login")

        # Correlation Pattern Check: Abnormal sequence
        # Escalating multi-step sequence containing suspicious signals across auth/device, access, and agent/tool
        event_types_in_incident = [e.event_type.lower() for e in matched_incident.events]
        has_auth_or_device = any(t in event_types_in_incident for t in ["login", "device_change"])
        has_access = any(t in event_types_in_incident for t in ["api_access", "data_access", "database_access"])
        has_agent_tool = any(t in event_types_in_incident for t in ["agent_invocation", "tool_invocation"])
        has_suspicious_signals = any(
            s in matched_incident.signals_detected
            for s in [
                "unknown_device", "sensitive_resource", "unexpected_tool_usage",
                "unusual_api_access", "privilege_escalation", "failed_login",
                "bulk_data_access", "impossible_travel", "brute_force_login",
                "credential_stuffing", "password_spraying", "distributed_attack",
                "suspicious_external_ip", "api_abuse", "prompt_injection",
                "indirect_prompt_injection", "ai_agent_abuse", "agent_privilege_abuse",
                "data_exfiltration"
            ]
        )

        if has_suspicious_signals and ((has_auth_or_device and has_access and has_agent_tool) or len(matched_incident.events) >= 4):
            if "abnormal_event_sequence" not in matched_incident.signals_detected:
                matched_incident.signals_detected.append("abnormal_event_sequence")

        # Check for attack chain: Auth anomaly + sensitive/bulk data
        has_auth_deviation = any(
            s in matched_incident.signals_detected
            for s in ["new_device", "unknown_device", "new_ip", "impossible_travel", "abnormal_login_time"]
        )
        has_data_deviation = any(
            s in matched_incident.signals_detected
            for s in ["sensitive_resource", "bulk_data_access", "privilege_escalation", "unusual_api_activity", "unusual_api_access"]
        )
        if has_auth_deviation and has_data_deviation:
            if "suspicious_session_behavior" not in matched_incident.signals_detected:
                matched_incident.signals_detected.append("suspicious_session_behavior")

        # Check for external attack chain: External origin + Agent/API abuse + Resource/Data exfiltration
        has_external_origin = any(
            s in matched_incident.signals_detected
            for s in [
                "suspicious_external_ip",
                "brute_force_login",
                "credential_stuffing",
                "password_spraying",
                "distributed_attack",
                "bot_automated_behavior",
                "new_ip",
            ]
        )
        has_abuse = any(
            s in matched_incident.signals_detected
            for s in [
                "api_abuse",
                "prompt_injection",
                "indirect_prompt_injection",
                "ai_agent_abuse",
                "agent_privilege_abuse",
                "unexpected_agent_activity",
                "unexpected_tool_usage",
            ]
        )
        has_exfil = any(
            s in matched_incident.signals_detected
            for s in [
                "data_exfiltration",
                "sensitive_resource",
                "bulk_data_access",
            ]
        )
        if has_external_origin and has_abuse and has_exfil:
            if "external_attack_chain" not in matched_incident.signals_detected:
                matched_incident.signals_detected.append("external_attack_chain")

        return matched_incident, matched_incident.signals_detected

    def get_incident(self, incident_id: str) -> Optional[CorrelatedIncident]:
        return self.active_incidents.get(incident_id)

    def list_incidents(self) -> List[CorrelatedIncident]:
        return list(self.active_incidents.values())
