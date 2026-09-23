from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.event import SecurityEvent, EventType
from app.models.graph import (
    ActivityRiskLevel,
    GraphEdge,
    GraphNode,
    GraphSummary,
    NodeType,
    RelationshipType,
    TimelineStep,
    UserActivityGraphResponse,
    UserSummary,
)
from app.models.incident import CorrelatedIncident
from app.repositories.supabase_repository import SupabaseRepository
from app.services.cognee_service import CogneeService
from app.services.correlation_service import CorrelationService
from app.services.detection_service import DetectionService
from app.services.risk_service import RiskService

logger = logging.getLogger(__name__)


class ActivityGraphService:
    """Service to construct an individual user's Activity Graph over time,
    connecting related entities across authentication, devices, network IPs,
    sessions, APIs, AI agents, agent tools, and databases.
    Preserves event chronology, evaluates baseline deviations, classifies risk
    transparently, and links to correlated incidents.
    """

    def __init__(
        self,
        repo: SupabaseRepository,
        detection_svc: DetectionService,
        correlation_svc: CorrelationService,
        cognee_svc: CogneeService,
        risk_svc: RiskService,
    ):
        self.repo = repo
        self.detection_svc = detection_svc
        self.correlation_svc = correlation_svc
        self.cognee_svc = cognee_svc
        self.risk_svc = risk_svc

    async def list_users(self) -> List[UserSummary]:
        """Lists all known users with activity summaries and risk ratings."""
        distinct_user_ids = await self.repo.list_distinct_users()
        
        # Also check correlation service active incidents
        for inc in self.correlation_svc.list_incidents():
            if inc.primary_entity and inc.entity_type == "user":
                if inc.primary_entity not in distinct_user_ids:
                    distinct_user_ids.append(inc.primary_entity)

        distinct_user_ids = sorted(list(set(distinct_user_ids)))
        summaries: List[UserSummary] = []

        for uid in distinct_user_ids:
            events = await self.repo.list_events(user_id=uid, limit=100)
            if not events:
                summaries.append(
                    UserSummary(
                        user_id=uid,
                        event_count=0,
                        highest_risk_level=ActivityRiskLevel.NORMAL,
                        incident_count=0,
                    )
                )
                continue

            events.sort(key=lambda e: e.timestamp)
            first_seen = events[0].timestamp
            last_seen = events[-1].timestamp
            
            # Check incidents for this user
            incidents = await self._find_user_incidents(uid, events)
            
            highest_risk = ActivityRiskLevel.NORMAL
            for inc in incidents:
                if inc.risk_assessment:
                    lvl = inc.risk_assessment.risk_level.value.lower()
                    if lvl == "critical" or lvl == "high":
                        highest_risk = ActivityRiskLevel.HIGH_RISK
                    elif lvl == "moderate" and highest_risk != ActivityRiskLevel.HIGH_RISK:
                        highest_risk = ActivityRiskLevel.SUSPICIOUS

            summaries.append(
                UserSummary(
                    user_id=uid,
                    event_count=len(events),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    highest_risk_level=highest_risk,
                    incident_count=len(incidents),
                )
            )

        return summaries

    async def build_user_activity_graph(
        self,
        user_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> UserActivityGraphResponse:
        """Derives graph nodes, directed relationships, and chronological timeline
        for the specified user without loading the entire security dataset.
        """
        # Query events specifically for this user
        events = await self.repo.list_events(user_id=user_id, limit=limit)
        
        # Apply time filtering if provided
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]

        # Sort chronologically ascending to preserve event sequence
        events.sort(key=lambda e: e.timestamp)

        # Handle empty user activity gracefully
        if not events:
            return UserActivityGraphResponse(
                status="success",
                user_id=user_id,
                summary=GraphSummary(
                    user_id=user_id,
                    total_events=0,
                    node_count=0,
                    edge_count=0,
                    risk_level=ActivityRiskLevel.NORMAL,
                    risk_score=0,
                ),
                nodes=[],
                edges=[],
                timeline=[],
                incidents=[],
            )

        # Find correlated incidents associated with this user and their events
        user_incidents = await self._find_user_incidents(user_id, events)
        event_id_to_incident: Dict[str, CorrelatedIncident] = {}
        for inc in user_incidents:
            for eid in inc.event_ids:
                event_id_to_incident[eid] = inc

        # Node storage: node_id -> GraphNode
        nodes_map: Dict[str, GraphNode] = {}
        edges_list: List[GraphEdge] = []
        timeline_steps: List[TimelineStep] = []
        dominant_signals_set: Set[str] = set()

        # Session tracking state across events
        session_devices: Dict[str, str] = {}
        session_agents: Dict[str, str] = {}
        session_tools: Dict[str, str] = {}
        session_apis: Dict[str, str] = {}

        # 1. Initialize Primary User Node
        first_event_time = events[0].timestamp
        last_event_time = events[-1].timestamp
        user_node_id = f"user:{user_id}"
        nodes_map[user_node_id] = GraphNode(
            id=user_node_id,
            type=NodeType.USER,
            label=f"User: {user_id}",
            risk_level=ActivityRiskLevel.NORMAL,
            first_seen=first_event_time,
            last_seen=last_event_time,
            event_ids=[e.id for e in events],
            event_types=list(dict.fromkeys(e.event_type for e in events)),
            signals=[],
            reasons=[],
            metadata={"user_id": user_id},
        )

        sequence_counter = 1

        # 2. Iterate chronologically over each event to derive nodes, edges & timeline
        for event in events:
            # Baseline evaluation & detection signals
            context = await self.cognee_svc.get_historical_context(event)
            detection = self.detection_svc.analyze_event(event, historical_context=context)
            signals = detection.signals
            for sig in signals:
                dominant_signals_set.add(sig)

            # Link to incident if present
            associated_incident = event_id_to_incident.get(event.id)
            incident_id = associated_incident.id if associated_incident else None

            # Calculate risk classification for this specific event step
            step_risk, reasons = self._classify_event_risk(event, signals, detection.details, context, user_incidents)

            # Update session context
            sess_id = event.session_id
            if sess_id:
                if event.device_id:
                    session_devices[sess_id] = event.device_id
                if event.agent_id:
                    session_agents[sess_id] = event.agent_id
                if event.tool_name:
                    session_tools[sess_id] = event.tool_name
                if event.resource and ("api" in event.resource.lower() or event.event_type == EventType.API_ACCESS.value):
                    session_apis[sess_id] = event.resource

            active_device = event.device_id or (session_devices.get(sess_id) if sess_id else None)
            active_agent = event.agent_id or (session_agents.get(sess_id) if sess_id else None)
            active_tool = event.tool_name or (session_tools.get(sess_id) if sess_id else None)

            # Extract IP from metadata if present
            ip_val = (
                event.metadata.get("ip")
                or event.metadata.get("ip_address")
                or event.metadata.get("client_ip")
                or event.metadata.get("source_ip")
                or event.metadata.get("external_ip")
            )

            # --- Entity Node & Edge Derivation by Event Type ---

            # A. LOGIN & AUTHENTICATION
            if event.event_type in [EventType.LOGIN.value, EventType.FAILED_LOGIN.value, EventType.LOGOUT.value, "login", "failed_login", "logout"]:
                login_node_id = f"login:{event.id}"
                is_failed = "failed" in event.event_type.lower()
                self._upsert_node(
                    nodes_map,
                    login_node_id,
                    NodeType.LOGIN,
                    f"Failed Login" if is_failed else f"Login ({event.id[:8]})",
                    step_risk,
                    event,
                    signals,
                    reasons,
                )

                # Relationship: USER_PERFORMED_LOGIN
                edge = self._create_edge(
                    source=user_node_id,
                    target=login_node_id,
                    relationship=RelationshipType.USER_PERFORMED_LOGIN,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=user_node_id,
                        target_node=login_node_id,
                        relationship=RelationshipType.USER_PERFORMED_LOGIN,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=reasons,
                        description=f"User performed authentication ({'FAILED' if is_failed else 'SUCCESS'})",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

                # If device is present in login
                dev_node_id = None
                if active_device:
                    dev_node_id = f"device:{active_device}"
                    has_dev_signal = any(s in ["unknown_device", "new_device", "device_anomaly"] for s in signals)
                    dev_risk = ActivityRiskLevel.UNUSUAL if has_dev_signal else ActivityRiskLevel.NORMAL
                    dev_reasons = ["New device or device anomaly"] if has_dev_signal else []
                    self._upsert_node(nodes_map, dev_node_id, NodeType.DEVICE, f"Device: {active_device}", dev_risk, event, signals, dev_reasons)

                    dev_edge = self._create_edge(
                        source=user_node_id,
                        target=dev_node_id,
                        relationship=RelationshipType.USER_USED_DEVICE,
                        risk_level=dev_risk,
                        signals=[s for s in ["unknown_device", "new_device", "device_anomaly"] if s in signals],
                        reasons=dev_reasons,
                        timestamp=event.timestamp,
                        seq_order=sequence_counter,
                        event=event,
                        incident_id=incident_id,
                    )
                    edges_list.append(dev_edge)
                    sequence_counter += 1

                # If IP address is present in login
                if ip_val:
                    ip_node_id = f"ip:{ip_val}"
                    has_ip_signal = any(
                        s in ["new_ip", "impossible_travel", "suspicious_external_ip", "brute_force_login", "credential_stuffing"]
                        for s in signals
                    ) or event.metadata.get("is_new_ip") or event.metadata.get("is_suspicious_ip")
                    ip_risk = (
                        ActivityRiskLevel.HIGH_RISK
                        if any(s in ["suspicious_external_ip", "brute_force_login", "credential_stuffing"] for s in signals)
                        else (ActivityRiskLevel.UNUSUAL if has_ip_signal else ActivityRiskLevel.NORMAL)
                    )
                    ip_reasons = [r for r in reasons if "IP" in r or "ip" in r or "External" in r or "attack" in r] or (
                        ["External origin IP"] if has_ip_signal else []
                    )
                    self._upsert_node(nodes_map, ip_node_id, NodeType.IP, f"IP: {ip_val}", ip_risk, event, signals, ip_reasons)

                    if dev_node_id:
                        ip_edge = self._create_edge(
                            source=dev_node_id,
                            target=ip_node_id,
                            relationship=RelationshipType.DEVICE_CONNECTED_FROM_IP,
                            risk_level=ip_risk,
                            signals=[s for s in ["new_ip", "impossible_travel"] if s in signals],
                            reasons=ip_reasons,
                            timestamp=event.timestamp,
                            seq_order=sequence_counter,
                            event=event,
                            incident_id=incident_id,
                        )
                        edges_list.append(ip_edge)
                    else:
                        rel = RelationshipType.TARGETED if is_failed else RelationshipType.EXTERNAL_SOURCE
                        ext_edge = self._create_edge(
                            source=ip_node_id,
                            target=user_node_id,
                            relationship=rel,
                            risk_level=ip_risk,
                            signals=signals,
                            reasons=ip_reasons,
                            timestamp=event.timestamp,
                            seq_order=sequence_counter,
                            event=event,
                            incident_id=incident_id,
                        )
                        edges_list.append(ext_edge)
                    sequence_counter += 1

                # If session_id present in login
                if sess_id:
                    sess_node_id = f"session:{sess_id}"
                    self._upsert_node(nodes_map, sess_node_id, NodeType.SESSION, f"Session: {sess_id}", ActivityRiskLevel.NORMAL, event, [], [])
                    sess_edge = self._create_edge(
                        source=user_node_id,
                        target=sess_node_id,
                        relationship=RelationshipType.USER_CREATED_SESSION,
                        risk_level=ActivityRiskLevel.NORMAL,
                        signals=[],
                        reasons=[],
                        timestamp=event.timestamp,
                        seq_order=sequence_counter,
                        event=event,
                        incident_id=incident_id,
                    )
                    edges_list.append(sess_edge)
                    sequence_counter += 1

            # B. DEVICE CHANGE / UNKNOWN DEVICE
            elif event.event_type in [EventType.DEVICE_CHANGE.value, "device_change"]:
                dev_node_id = f"device:{active_device or 'unknown_device'}"
                dev_risk = ActivityRiskLevel.UNUSUAL if "unknown_device" in signals else ActivityRiskLevel.NORMAL
                dev_reasons = ["New device"] if "unknown_device" in signals else []
                self._upsert_node(nodes_map, dev_node_id, NodeType.DEVICE, f"Device: {active_device or 'Unknown'}", dev_risk, event, signals, dev_reasons)

                dev_edge = self._create_edge(
                    source=user_node_id,
                    target=dev_node_id,
                    relationship=RelationshipType.USER_USED_DEVICE,
                    risk_level=dev_risk,
                    signals=["unknown_device"] if "unknown_device" in signals else [],
                    reasons=dev_reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(dev_edge)

                if ip_val:
                    ip_node_id = f"ip:{ip_val}"
                    ip_reasons = ["Previously unseen IP"]
                    self._upsert_node(nodes_map, ip_node_id, NodeType.IP, f"IP: {ip_val}", ActivityRiskLevel.UNUSUAL, event, signals, ip_reasons)
                    ip_edge = self._create_edge(
                        source=dev_node_id,
                        target=ip_node_id,
                        relationship=RelationshipType.DEVICE_CONNECTED_FROM_IP,
                        risk_level=ActivityRiskLevel.UNUSUAL,
                        signals=signals,
                        reasons=ip_reasons,
                        timestamp=event.timestamp,
                        seq_order=sequence_counter,
                        event=event,
                        incident_id=incident_id,
                    )
                    edges_list.append(ip_edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=user_node_id,
                        target_node=dev_node_id,
                        relationship=RelationshipType.USER_USED_DEVICE,
                        risk_level=dev_risk,
                        signals=signals,
                        reasons=dev_reasons,
                        description=f"User switched to device {active_device or 'unknown'}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

            # C. API ACCESS
            elif event.event_type in [EventType.API_ACCESS.value, "api_access", "data_access"]:
                api_target = event.resource or "/api/default"
                api_node_id = f"api:{api_target}"
                
                # Check for sensitive resource or unusual API usage
                api_reasons = []
                if "unusual_api_access" in signals:
                    api_reasons.append("Unusual API usage")
                if "sensitive_resource" in signals:
                    api_reasons.append("Sensitive resource access")

                self._upsert_node(nodes_map, api_node_id, NodeType.API, f"API: {api_target}", step_risk, event, signals, api_reasons)

                api_edge = self._create_edge(
                    source=user_node_id,
                    target=api_node_id,
                    relationship=RelationshipType.USER_CALLED_API,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=api_reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(api_edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=user_node_id,
                        target_node=api_node_id,
                        relationship=RelationshipType.USER_CALLED_API,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=api_reasons,
                        description=f"User invoked API endpoint {api_target}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

                # If resource accessed is also a backend data store or resource target
                if "customer-data" in api_target.lower() or "export" in api_target.lower():
                    res_node_id = f"res:{api_target}"
                    res_reasons = ["Sensitive resource access"] if "sensitive_resource" in signals else []
                    self._upsert_node(nodes_map, res_node_id, NodeType.RESOURCE, f"Resource: {api_target.split('/')[-1]}", step_risk, event, signals, res_reasons)
                    
                    res_edge = self._create_edge(
                        source=api_node_id,
                        target=res_node_id,
                        relationship=RelationshipType.API_ACCESSED_RESOURCE,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=res_reasons,
                        timestamp=event.timestamp,
                        seq_order=sequence_counter,
                        event=event,
                        incident_id=incident_id,
                    )
                    edges_list.append(res_edge)
                    sequence_counter += 1

            # D. AI AGENT INVOCATION
            elif event.event_type in [EventType.AGENT_INVOCATION.value, "agent_invocation"]:
                agent_target = event.agent_id or "agent_copilot"
                agent_node_id = f"agent:{agent_target}"
                agent_reasons = []
                if "unexpected_agent_activity" in signals:
                    agent_reasons.append("Unexpected AI agent execution")

                self._upsert_node(nodes_map, agent_node_id, NodeType.AI_AGENT, f"AI Agent: {agent_target}", step_risk, event, signals, agent_reasons)

                agent_edge = self._create_edge(
                    source=user_node_id,
                    target=agent_node_id,
                    relationship=RelationshipType.USER_INVOKED_AGENT,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=agent_reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(agent_edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=user_node_id,
                        target_node=agent_node_id,
                        relationship=RelationshipType.USER_INVOKED_AGENT,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=agent_reasons,
                        description=f"User invoked AI agent {agent_target}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

            # E. AGENT TOOL INVOCATION
            elif event.event_type in [EventType.TOOL_INVOCATION.value, "tool_invocation"]:
                tool_target = event.tool_name or "raw_sql_exec"
                tool_node_id = f"tool:{tool_target}"
                source_agent_id = f"agent:{active_agent or 'agent_copilot'}"

                # Ensure source agent node exists
                if source_agent_id not in nodes_map:
                    self._upsert_node(nodes_map, source_agent_id, NodeType.AI_AGENT, f"AI Agent: {active_agent or 'agent_copilot'}", ActivityRiskLevel.NORMAL, event, [], [])

                tool_reasons = []
                if "unexpected_tool_usage" in signals or "restricted_tool" in signals:
                    tool_reasons.append(f"Restricted tool '{tool_target}' outside known baseline")

                self._upsert_node(nodes_map, tool_node_id, NodeType.TOOL, f"Tool: {tool_target}", step_risk, event, signals, tool_reasons)

                tool_edge = self._create_edge(
                    source=source_agent_id,
                    target=tool_node_id,
                    relationship=RelationshipType.AGENT_USED_TOOL,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=tool_reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(tool_edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=source_agent_id,
                        target_node=tool_node_id,
                        relationship=RelationshipType.AGENT_USED_TOOL,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=tool_reasons,
                        description=f"Agent invoked tool {tool_target}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

            # F. DATABASE ACCESS / SENSITIVE RESOURCE ACCESS
            elif event.event_type in [EventType.DATABASE_ACCESS.value, "database_access"]:
                db_target = event.resource or "/database/customer_credentials/dump"
                db_node_id = f"db:{db_target}"
                
                db_reasons = []
                if "sensitive_resource" in signals:
                    db_reasons.append("Sensitive resource access")
                if "privilege_escalation" in signals:
                    db_reasons.append("Privilege elevation attempted")

                self._upsert_node(nodes_map, db_node_id, NodeType.DATABASE, f"Database: {db_target.split('/')[-1]}", step_risk, event, signals, db_reasons)

                # Source entity can be the active Tool (if previously invoked) or API or User
                if active_tool:
                    source_node = f"tool:{active_tool}"
                    if source_node not in nodes_map:
                        self._upsert_node(nodes_map, source_node, NodeType.TOOL, f"Tool: {active_tool}", ActivityRiskLevel.NORMAL, event, [], [])
                    rel = RelationshipType.TOOL_ACCESSED_RESOURCE
                elif sess_id and session_apis.get(sess_id):
                    source_node = f"api:{session_apis[sess_id]}"
                    rel = RelationshipType.API_ACCESSED_RESOURCE
                else:
                    source_node = user_node_id
                    rel = RelationshipType.USER_CALLED_API

                db_edge = self._create_edge(
                    source=source_node,
                    target=db_node_id,
                    relationship=rel,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=db_reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(db_edge)

                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=source_node,
                        target_node=db_node_id,
                        relationship=rel,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=db_reasons,
                        description=f"Accessed database resource {db_target}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

            # G. GENERIC / OTHER EVENTS
            else:
                target_res = event.resource or f"res_{event.event_type}"
                is_db = any(k in target_res.lower() for k in ["database", "db", "sql"])
                node_type = NodeType.DATABASE if is_db else NodeType.RESOURCE
                prefix = "db" if is_db else "res"
                res_node_id = f"{prefix}:{target_res}"

                self._upsert_node(nodes_map, res_node_id, node_type, f"Resource: {target_res}", step_risk, event, signals, reasons)
                generic_edge = self._create_edge(
                    source=user_node_id,
                    target=res_node_id,
                    relationship=RelationshipType.USER_CALLED_API,
                    risk_level=step_risk,
                    signals=signals,
                    reasons=reasons,
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(generic_edge)
                timeline_steps.append(
                    TimelineStep(
                        step=len(timeline_steps) + 1,
                        timestamp=event.timestamp,
                        event_id=event.id,
                        event_type=event.event_type,
                        source_node=user_node_id,
                        target_node=res_node_id,
                        relationship=RelationshipType.USER_CALLED_API,
                        risk_level=step_risk,
                        signals=signals,
                        reasons=reasons,
                        description=f"Action on {target_res}",
                        incident_id=incident_id,
                        metadata=event.metadata,
                    )
                )
                sequence_counter += 1

            # Check for data exfiltration link
            if "data_exfiltration" in signals or event.metadata.get("data_exfiltration") is True:
                dest_val = event.metadata.get("destination") or event.metadata.get("external_destination") or "untrusted_external_host"
                exfil_dest_id = f"ip:{dest_val}"
                self._upsert_node(
                    nodes_map,
                    exfil_dest_id,
                    NodeType.IP,
                    f"Exfil Destination: {dest_val}",
                    ActivityRiskLevel.HIGH_RISK,
                    event,
                    signals,
                    ["Active outbound data exfiltration destination"],
                )
                source_exfil = user_node_id
                if event.resource:
                    res_prefix = "db" if any(k in event.resource.lower() for k in ["database", "db", "sql"]) else "res"
                    candidate_res = f"{res_prefix}:{event.resource}"
                    if candidate_res in nodes_map:
                        source_exfil = candidate_res
                exfil_edge = self._create_edge(
                    source=source_exfil,
                    target=exfil_dest_id,
                    relationship=RelationshipType.EXFILTRATED,
                    risk_level=ActivityRiskLevel.HIGH_RISK,
                    signals=["data_exfiltration"],
                    reasons=["Outbound data exfiltrated to external destination"],
                    timestamp=event.timestamp,
                    seq_order=sequence_counter,
                    event=event,
                    incident_id=incident_id,
                )
                edges_list.append(exfil_edge)
                sequence_counter += 1

        # 3. Overall User Risk Aggregation
        overall_risk_score, overall_risk_level = self._compute_overall_user_risk(
            dominant_signals=list(dominant_signals_set),
            incidents=user_incidents,
            events_count=len(events),
        )

        nodes_map[user_node_id].risk_level = overall_risk_level
        nodes_map[user_node_id].signals = sorted(list(dominant_signals_set))

        # Format incidents for response
        formatted_incidents = []
        for inc in user_incidents:
            formatted_incidents.append({
                "id": inc.id,
                "primary_entity": inc.primary_entity,
                "entity_type": inc.entity_type,
                "signals_detected": inc.signals_detected,
                "status": inc.status,
                "risk_score": inc.risk_assessment.risk_score if inc.risk_assessment else 0,
                "risk_level": inc.risk_assessment.risk_level.value if inc.risk_assessment else "LOW",
                "recommended_action": inc.risk_assessment.recommended_action if inc.risk_assessment else "",
                "created_at": inc.created_at.isoformat(),
            })

        summary = GraphSummary(
            user_id=user_id,
            total_events=len(events),
            node_count=len(nodes_map),
            edge_count=len(edges_list),
            risk_level=overall_risk_level,
            risk_score=overall_risk_score,
            first_seen=first_event_time,
            last_seen=last_event_time,
            incident_ids=[inc.id for inc in user_incidents],
            dominant_signals=sorted(list(dominant_signals_set)),
        )

        return UserActivityGraphResponse(
            status="success",
            user_id=user_id,
            summary=summary,
            nodes=list(nodes_map.values()),
            edges=edges_list,
            timeline=timeline_steps,
            incidents=formatted_incidents,
        )

    # --- Internal Helpers ---

    async def _find_user_incidents(
        self,
        user_id: str,
        user_events: List[SecurityEvent],
    ) -> List[CorrelatedIncident]:
        """Finds incidents linked to this user or any of the user's events."""
        event_ids_set = {e.id for e in user_events}
        all_incidents: List[CorrelatedIncident] = []

        # From repository
        repo_incidents = await self.repo.list_incidents(limit=100)
        all_incidents.extend(repo_incidents)

        # From correlation service active in-memory store
        active_incidents = self.correlation_svc.list_incidents()
        for inc in active_incidents:
            if not any(existing.id == inc.id for existing in all_incidents):
                all_incidents.append(inc)

        matched: List[CorrelatedIncident] = []
        for inc in all_incidents:
            is_match = (
                inc.primary_entity == user_id
                or any(eid in event_ids_set for eid in inc.event_ids)
            )
            if is_match and not any(m.id == inc.id for m in matched):
                matched.append(inc)

        return matched

    def _classify_event_risk(
        self,
        event: SecurityEvent,
        signals: List[str],
        details: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        incidents: List[CorrelatedIncident],
    ) -> Tuple[ActivityRiskLevel, List[str]]:
        """Classifies risk level for an individual event step, strictly enforcing:
        A new IP or new device by itself must NOT automatically be classified as a threat.
        It should be treated as a risk signal (unusual) and evaluated with other behavior.
        """
        reasons: List[str] = []

        if not signals:
            return ActivityRiskLevel.NORMAL, reasons

        # Extract genuine reasons from detection details and existing risk signals
        for sig in signals:
            if sig in details:
                reasons.append(str(details[sig]))
            elif sig in self.risk_svc.SIGNAL_EXPLANATIONS:
                reasons.append(self.risk_svc.SIGNAL_EXPLANATIONS[sig])

        # If Cognee context flagged anomaly
        if context and context.get("is_anomaly") and context.get("summary"):
            if context["summary"] not in reasons:
                reasons.append(context["summary"])

        # Check for Critical/High-risk signals
        critical_signals = {
            "unexpected_tool_usage", "privilege_escalation", "abnormal_event_sequence",
            "bulk_data_access", "impossible_travel", "suspicious_session_behavior"
        }
        suspicious_signals = {
            "sensitive_resource", "unusual_api_access", "unusual_api_activity",
            "unexpected_agent_activity", "repeated_failed_login", "abnormal_resource_access",
            "device_anomaly"
        }
        
        has_critical = any(s in signals for s in critical_signals)
        has_suspicious = any(s in signals for s in suspicious_signals)

        # Isolated weak signals: new device, new IP, abnormal login time, or failed login
        weak_signals = {"unknown_device", "new_device", "new_ip", "abnormal_login_time", "failed_login"}
        only_weak_signals = all(s in weak_signals for s in signals)

        if has_critical:
            return ActivityRiskLevel.HIGH_RISK, reasons
        elif has_suspicious:
            # If corroborating signals exist or incident is active
            if any(inc.risk_assessment and inc.risk_assessment.risk_score >= 60 for inc in incidents):
                return ActivityRiskLevel.HIGH_RISK, reasons
            return ActivityRiskLevel.SUSPICIOUS, reasons
        elif only_weak_signals:
            # Strictly Treated as an unusual risk signal, NOT a critical threat
            return ActivityRiskLevel.UNUSUAL, reasons
        
        return ActivityRiskLevel.UNUSUAL, reasons

    def _compute_overall_user_risk(
        self,
        dominant_signals: List[str],
        incidents: List[CorrelatedIncident],
        events_count: int,
    ) -> Tuple[int, ActivityRiskLevel]:
        """Calculates bounded user risk score (0-100) and category."""
        if not dominant_signals and not incidents:
            return 0, ActivityRiskLevel.NORMAL

        # If incidents exist, use highest incident score as baseline
        incident_scores = [
            inc.risk_assessment.risk_score
            for inc in incidents
            if inc.risk_assessment is not None
        ]
        max_inc_score = max(incident_scores) if incident_scores else 0

        # Assess signals via RiskService
        assessment = self.risk_svc.assess_risk(dominant_signals, correlated_event_count=events_count)
        final_score = max(max_inc_score, assessment.risk_score)

        # Critical check: if ONLY weak signals (unknown_device, new_device, new_ip, abnormal_login_time), cap score so it remains 'unusual'
        weak_set = {"unknown_device", "new_device", "new_ip", "abnormal_login_time"}
        if dominant_signals and all(s in weak_set for s in dominant_signals) and not incident_scores:
            final_score = min(25, final_score)
            return final_score, ActivityRiskLevel.UNUSUAL

        if final_score >= 80:
            return final_score, ActivityRiskLevel.HIGH_RISK
        elif final_score >= 60:
            return final_score, ActivityRiskLevel.HIGH_RISK
        elif final_score >= 30:
            return final_score, ActivityRiskLevel.SUSPICIOUS
        elif final_score > 0:
            return final_score, ActivityRiskLevel.UNUSUAL

        return 0, ActivityRiskLevel.NORMAL

    def _upsert_node(
        self,
        nodes_map: Dict[str, GraphNode],
        node_id: str,
        node_type: NodeType,
        label: str,
        risk_level: ActivityRiskLevel,
        event: SecurityEvent,
        signals: List[str],
        reasons: List[str],
    ):
        """Creates or updates a node in the graph map."""
        if node_id not in nodes_map:
            nodes_map[node_id] = GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                risk_level=risk_level,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_ids=[event.id],
                event_types=[event.event_type],
                signals=list(dict.fromkeys(signals)),
                reasons=list(dict.fromkeys(reasons)),
                metadata={"resource": event.resource, "metadata": event.metadata},
            )
        else:
            node = nodes_map[node_id]
            node.last_seen = max(node.last_seen, event.timestamp)
            if event.id not in node.event_ids:
                node.event_ids.append(event.id)
            if event.event_type not in node.event_types:
                node.event_types.append(event.event_type)
            for s in signals:
                if s not in node.signals:
                    node.signals.append(s)
            for r in reasons:
                if r not in node.reasons:
                    node.reasons.append(r)
            # Elevate risk if new event has higher severity
            if self._risk_rank(risk_level) > self._risk_rank(node.risk_level):
                node.risk_level = risk_level

    def _create_edge(
        self,
        source: str,
        target: str,
        relationship: RelationshipType,
        risk_level: ActivityRiskLevel,
        signals: List[str],
        reasons: List[str],
        timestamp: datetime,
        seq_order: int,
        event: SecurityEvent,
        incident_id: Optional[str] = None,
    ) -> GraphEdge:
        edge_id = f"edge:{source}->{target}:{relationship.value}:{event.id}"
        return GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            relationship=relationship,
            risk_level=risk_level,
            signals=signals,
            reasons=reasons,
            timestamp=timestamp,
            sequence_order=seq_order,
            event_id=event.id,
            event_type=event.event_type,
            incident_id=incident_id,
            metadata=event.metadata,
        )

    def _risk_rank(self, level: ActivityRiskLevel) -> int:
        ranks = {
            ActivityRiskLevel.NORMAL: 0,
            ActivityRiskLevel.UNUSUAL: 1,
            ActivityRiskLevel.SUSPICIOUS: 2,
            ActivityRiskLevel.HIGH_RISK: 3,
        }
        return ranks.get(level, 0)
