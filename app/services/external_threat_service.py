from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.models.event import SecurityEvent, EventType
from app.services.agent_security_service import RiskContribution

logger = logging.getLogger(__name__)


class BehavioralProgressionStep(BaseModel):
    step: int
    stage: str  # SOURCE, TARGET, ACTION, RESULT, FOLLOW_UP, IMPACT
    description: str
    entity: str
    timestamp: str


class BehavioralProgression(BaseModel):
    source: str = ""
    target: str = ""
    action: str = ""
    result: str = ""
    follow_up_action: str = ""
    impact: str = ""
    steps: List[BehavioralProgressionStep] = Field(default_factory=list)
    summary: str = ""


class ExternalSourceProfile(BaseModel):
    source_ip: str
    source_identity: str = "External Client"
    asn: str = "AS15169 (Google LLC)"
    country: str = "Unknown"
    city: str = "Unknown"
    ip_reputation: str = "clean"  # clean, suspicious, malicious
    first_seen: datetime
    last_seen: datetime
    total_requests: int = 1
    failed_requests: int = 0
    success_requests: int = 1
    success_rate: float = 1.0
    targeted_users: List[str] = Field(default_factory=list)
    targeted_devices: List[str] = Field(default_factory=list)
    targeted_sessions: List[str] = Field(default_factory=list)
    targeted_apis: List[str] = Field(default_factory=list)
    targeted_agents: List[str] = Field(default_factory=list)
    targeted_tools: List[str] = Field(default_factory=list)
    targeted_resources: List[str] = Field(default_factory=list)
    action_sequence: List[str] = Field(default_factory=list)
    total_volume_bytes: int = 0
    destinations: List[str] = Field(default_factory=list)


class ExternalThreatAnalysis(BaseModel):
    threat_type: str = "suspicious_external_ip"
    source: str = ""
    target: str = ""
    affected_user: Optional[str] = None
    device: Optional[str] = None
    session: Optional[str] = None
    ai_agent: Optional[str] = None
    tool: Optional[str] = None
    api: Optional[str] = None
    resource: Optional[str] = None
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    behavioral_deviation: str = ""
    correlation_chain: str = ""
    risk_contributions: List[RiskContribution] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    explanation: str = ""
    behavioral_progression: BehavioralProgression = Field(default_factory=BehavioralProgression)
    profile: Optional[ExternalSourceProfile] = None


class ExternalThreatService:
    """Deep behavioral and attack-chain analysis for external sources and perimeter threats.
    Builds comprehensive external source profiles, detects 13 external threat types,
    models the SOURCE -> TARGET -> ACTION -> RESULT -> FOLLOW-UP -> IMPACT progression,
    and explicitly correlates external threats reaching AI agents, tools, APIs, and databases.
    """

    KNOWN_EXTERNAL_REPUTATION = {
        "185.220.101.33": {"identity": "Tor Exit Node (Relay #412)", "country": "DE", "city": "Frankfurt", "asn": "AS206264", "reputation": "malicious"},
        "203.0.113.195": {"identity": "Kali Linux Scanner VPS", "country": "NL", "city": "Amsterdam", "asn": "AS49981", "reputation": "malicious"},
        "198.51.100.44": {"identity": "Automated Scraping Botnet", "country": "RU", "city": "Moscow", "asn": "AS12389", "reputation": "malicious"},
        "45.33.32.156": {"identity": "Credential Stuffing Proxy", "country": "US", "city": "Fremont", "asn": "AS63949", "reputation": "suspicious"},
        "192.168.1.50": {"identity": "Internal Corporate Subnet", "country": "IN", "city": "New Delhi", "asn": "Internal", "reputation": "clean"},
    }

    THREAT_WEIGHTS: Dict[str, int] = {
        "brute_force_login": 25,
        "credential_stuffing": 30,
        "password_spraying": 30,
        "distributed_attack": 30,
        "suspicious_external_ip": 15,
        "bot_automated_behavior": 20,
        "api_abuse": 20,
        "prompt_injection": 25,
        "indirect_prompt_injection": 30,
        "ai_agent_abuse": 20,
        "agent_privilege_abuse": 25,
        "data_exfiltration": 30,
        "external_attack_chain": 25,
    }

    def __init__(self):
        # Map source_ip -> ExternalSourceProfile
        self.profiles: Dict[str, ExternalSourceProfile] = {}
        # Map source_ip -> List[SecurityEvent]
        self.ip_events: Dict[str, List[SecurityEvent]] = {}

    def extract_ip(self, event: SecurityEvent) -> str:
        meta = event.metadata or {}
        return (
            meta.get("ip")
            or meta.get("client_ip")
            or meta.get("source_ip")
            or meta.get("external_ip")
            or meta.get("origin_ip")
            or "203.0.113.195"
        )

    def get_or_create_profile(self, ip: str, event: SecurityEvent) -> ExternalSourceProfile:
        if ip in self.profiles:
            profile = self.profiles[ip]
            profile.last_seen = max(profile.last_seen, event.timestamp)
            profile.total_requests += 1
            return profile

        rep_info = self.KNOWN_EXTERNAL_REPUTATION.get(ip, {
            "identity": f"External Host ({ip})",
            "country": "US",
            "city": "Unknown",
            "asn": "AS15169",
            "reputation": "suspicious" if any(p in ip for p in ["185.", "203.", "198."]) else "clean"
        })

        profile = ExternalSourceProfile(
            source_ip=ip,
            source_identity=rep_info["identity"],
            asn=rep_info["asn"],
            country=rep_info["country"],
            city=rep_info["city"],
            ip_reputation=rep_info["reputation"],
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            total_requests=1,
            failed_requests=0,
            success_requests=1,
            success_rate=1.0,
        )
        self.profiles[ip] = profile
        return profile

    def update_profile_with_event(self, profile: ExternalSourceProfile, event: SecurityEvent):
        meta = event.metadata or {}
        evt_type = (event.event_type or "").lower()

        if "fail" in evt_type or meta.get("login_success") is False:
            profile.failed_requests += 1
        else:
            profile.success_requests += 1

        total = profile.failed_requests + profile.success_requests
        profile.success_rate = round(profile.success_requests / total, 2) if total > 0 else 1.0

        if event.user_id and event.user_id not in profile.targeted_users:
            profile.targeted_users.append(event.user_id)
        if event.device_id and event.device_id not in profile.targeted_devices:
            profile.targeted_devices.append(event.device_id)
        if event.session_id and event.session_id not in profile.targeted_sessions:
            profile.targeted_sessions.append(event.session_id)
        if event.agent_id and event.agent_id not in profile.targeted_agents:
            profile.targeted_agents.append(event.agent_id)
        if event.tool_name and event.tool_name not in profile.targeted_tools:
            profile.targeted_tools.append(event.tool_name)

        res = event.resource
        if res:
            if "api" in res.lower() and res not in profile.targeted_apis:
                profile.targeted_apis.append(res)
            elif res not in profile.targeted_resources:
                profile.targeted_resources.append(res)

        action_desc = f"{event.event_type} on {res or event.tool_name or event.device_id or 'auth'}"
        profile.action_sequence.append(action_desc)

        bytes_val = meta.get("outbound_bytes") or meta.get("bytes_transferred") or 0
        profile.total_volume_bytes += bytes_val

        dest = meta.get("destination") or meta.get("external_destination")
        if dest and dest not in profile.destinations:
            profile.destinations.append(dest)

    def analyze_external_threat(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> ExternalThreatAnalysis:
        """Deep behavioral and attack-chain analysis for an external threat."""
        source_ip = self.extract_ip(event)
        recent_events = recent_events or []
        profile = self.get_or_create_profile(source_ip, event)

        # Track IP event history
        if source_ip not in self.ip_events:
            self.ip_events[source_ip] = []
        self.ip_events[source_ip].append(event)

        self.update_profile_with_event(profile, event)

        meta = event.metadata or {}
        signals: List[str] = []
        evidence: List[str] = []
        contributions: List[RiskContribution] = []
        now_str = event.timestamp.isoformat() if event.timestamp else datetime.now(timezone.utc).isoformat()

        # Find all events from this IP in the session / correlation window
        correlated_ip_events = [e for e in recent_events if self.extract_ip(e) == source_ip] + [event]
        # Deduplicate by ID
        seen_eids = set()
        dedup_events = []
        for e in correlated_ip_events:
            if e.id not in seen_eids:
                seen_eids.add(e.id)
                dedup_events.append(e)
        dedup_events.sort(key=lambda x: x.timestamp)

        # 1. Threat Type Classification
        # Check Brute Force / Credential Stuffing / Password Spraying
        failed_logins = [e for e in dedup_events if "failed" in (e.event_type or "").lower()]
        target_users = list(dict.fromkeys(e.user_id for e in dedup_events if e.user_id))

        if len(failed_logins) >= 3 and len(target_users) == 1:
            sig = "brute_force_login"
            signals.append(sig)
            ev = f"Rapid repeated failed authentication attempts ({len(failed_logins)}) targeting user '{target_users[0]}'."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        if len(failed_logins) >= 2 and len(target_users) >= 2:
            sig = "password_spraying"
            signals.append(sig)
            ev = f"Password spraying observed from origin {source_ip} targeting {len(target_users)} distinct users ({', '.join(target_users)})."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        if meta.get("credential_stuffing") or (len(failed_logins) >= 5 and profile.ip_reputation == "malicious"):
            sig = "credential_stuffing"
            signals.append(sig)
            ev = f"Automated credential stuffing pattern corroborated by malicious source reputation."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check Suspicious External IP
        if profile.ip_reputation == "malicious" or meta.get("is_suspicious_ip") or meta.get("ip_reputation") == "malicious":
            sig = "suspicious_external_ip"
            signals.append(sig)
            ev = f"Origin IP {source_ip} matches threat intelligence record: {profile.source_identity} ({profile.country}, {profile.asn})."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check Bot / Automated Behavior
        user_agent = meta.get("user_agent") or meta.get("client_header") or ""
        if any(b in user_agent.lower() for b in ["curl", "python", "postman", "nikto", "sqlmap", "zaproxy"]) or meta.get("is_bot"):
            sig = "bot_automated_behavior"
            signals.append(sig)
            ev = f"Automated scanner tool or bot client detected: '{user_agent or 'Automated Client'}'."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check API Abuse
        if meta.get("api_abuse") or meta.get("rate_limit_exceeded") or (event.event_type == "api_access" and meta.get("unusual_api")):
            sig = "api_abuse"
            signals.append(sig)
            ev = f"Anomalous API consumption rate or access to unauthorized endpoints from external caller."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check Prompt Injection (Direct & Indirect)
        prompt = meta.get("prompt") or meta.get("user_prompt") or ""
        if any(k in prompt.lower() for k in ["ignore previous", "system override", "dan mode", "jailbreak", "dump credentials"]):
            sig = "prompt_injection"
            signals.append(sig)
            ev = f"External payload contained direct prompt injection attack vector targeting AI Agent."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        doc_content = meta.get("document_content") or meta.get("retrieved_text") or meta.get("scraped_content") or ""
        if any(k in doc_content.lower() for k in ["<!-- instruction:", "note for ai:", "system prompt override:"]):
            sig = "indirect_prompt_injection"
            signals.append(sig)
            ev = f"Indirect prompt injection vector discovered in external content ingested by AI Agent."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check AI Agent Abuse & Privilege Abuse
        if event.agent_id:
            sig = "ai_agent_abuse"
            signals.append(sig)
            ev = f"External source invoked AI agent '{event.agent_id}' to execute privileged actions."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        if event.tool_name and event.tool_name.lower() in ["raw_sql_exec", "db_drop_tool", "bash_shell", "memory_dump"]:
            sig = "agent_privilege_abuse"
            signals.append(sig)
            ev = f"External caller induced AI agent to execute restricted tool '{event.tool_name}'."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check Data Exfiltration
        if meta.get("data_exfiltration") or (profile.total_volume_bytes > 100000 and len(profile.destinations) > 0):
            sig = "data_exfiltration"
            signals.append(sig)
            dest_target = profile.destinations[0] if profile.destinations else "external_destination"
            ev = f"Active bulk data transmission outbound to external destination '{dest_target}' ({profile.total_volume_bytes} bytes)."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # Check Multi-Step Attack Chain
        has_auth = any(e.event_type in ["login", "failed_login"] for e in dedup_events)
        has_agent = any(e.agent_id or e.tool_name for e in dedup_events)
        has_sensitive = any(
            any(s in (e.resource or "").lower() for s in ["customer", "credential", "database", "dump", "payroll"])
            for e in dedup_events
        )
        has_external_chain = has_auth and (has_agent or has_sensitive) and len(dedup_events) >= 3

        if has_external_chain or meta.get("external_attack_chain"):
            sig = "external_attack_chain"
            signals.append(sig)
            ev = "End-to-end coordinated attack progression: External Auth/Recon -> AI Agent/API Abuse -> Sensitive Data Access."
            evidence.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.THREAT_WEIGHTS[sig], evidence=ev, entity=source_ip, timestamp=now_str))

        # 2. Build Behavioral Progression Model:
        # SOURCE -> TARGET -> ACTION -> RESULT -> FOLLOW-UP -> IMPACT
        progression_steps: List[BehavioralProgressionStep] = []
        step_num = 1

        # Stage 1: SOURCE
        source_desc = f"External IP {source_ip} [{profile.source_identity}, {profile.country}]"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="SOURCE", description=source_desc, entity=source_ip, timestamp=now_str))
        step_num += 1

        # Stage 2: TARGET
        target_entity = event.user_id or event.agent_id or "Enterprise Perimeter"
        target_desc = f"Targeted identity '{target_entity}' on endpoint device '{event.device_id or 'Gateway'}'"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="TARGET", description=target_desc, entity=target_entity, timestamp=now_str))
        step_num += 1

        # Stage 3: ACTION
        action_name = event.event_type or "connection_attempt"
        action_desc = f"Executed {action_name} requesting resource '{event.resource or event.tool_name or 'auth'}'"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="ACTION", description=action_desc, entity=action_name, timestamp=now_str))
        step_num += 1

        # Stage 4: RESULT
        is_success = "fail" not in (event.event_type or "").lower() and meta.get("login_success") is not False
        result_desc = "Authentication / Operation SUCCEEDED; session established" if is_success else "Authentication REJECTED; trigger brute-force evaluation"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="RESULT", description=result_desc, entity=str(is_success), timestamp=now_str))
        step_num += 1

        # Stage 5: FOLLOW-UP ACTION
        if event.agent_id:
            follow_up = f"Invoked autonomous agent '{event.agent_id}' with tool '{event.tool_name or 'default'}'"
        elif event.resource:
            follow_up = f"Targeted backend resource '{event.resource}'"
        else:
            follow_up = "Continued reconnaissance across adjacent enterprise endpoints"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="FOLLOW_UP", description=follow_up, entity=event.agent_id or event.resource or "recon", timestamp=now_str))
        step_num += 1

        # Stage 6: IMPACT
        if "data_exfiltration" in signals or "agent_privilege_abuse" in signals:
            impact_desc = "CRITICAL: Sensitive database reached and bulk data exfiltration triggered to external destination"
        elif "prompt_injection" in signals or "ai_agent_abuse" in signals:
            impact_desc = "HIGH: AI Agent guardrails compromised via malicious instruction injection"
        elif "brute_force_login" in signals or "password_spraying" in signals:
            impact_desc = "MODERATE: Perimeter authentication spray active against user credentials"
        else:
            impact_desc = "LOW: Monitored external connection exhibiting baseline deviation"
        progression_steps.append(BehavioralProgressionStep(step=step_num, stage="IMPACT", description=impact_desc, entity="Perimeter Impact", timestamp=now_str))

        behavioral_prog = BehavioralProgression(
            source=source_desc,
            target=target_desc,
            action=action_desc,
            result=result_desc,
            follow_up_action=follow_up,
            impact=impact_desc,
            steps=progression_steps,
            summary=f"{source_ip} → {target_entity} → {action_name} → {result_desc.split(';')[0]} → {follow_up} → {impact_desc.split(':')[0]}",
        )

        # 3. Calculate Risk Score
        raw_score = sum(c.weight for c in contributions)
        final_score = min(100, max(raw_score, 15 if signals else 0))

        if final_score >= 80:
            risk_level = "CRITICAL"
        elif final_score >= 60:
            risk_level = "HIGH"
        elif final_score >= 30:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"

        # Primary threat type (prioritize specific attack techniques over generic IP reputation)
        threat_priority = [
            "external_attack_chain",
            "data_exfiltration",
            "indirect_prompt_injection",
            "prompt_injection",
            "agent_privilege_abuse",
            "credential_stuffing",
            "password_spraying",
            "brute_force_login",
            "api_abuse",
            "ai_agent_abuse",
            "bot_automated_behavior",
            "suspicious_external_ip",
        ]
        primary_threat = "suspicious_external_ip"
        if signals:
            matched = False
            for candidate in threat_priority:
                if candidate in signals:
                    primary_threat = candidate
                    matched = True
                    break
            if not matched:
                primary_threat = signals[0]

        # Correlation Chain string
        chain_parts = [f"External Source ({source_ip})"]
        if event.user_id:
            chain_parts.append(f"User ({event.user_id})")
        if event.session_id:
            chain_parts.append(f"Session ({event.session_id})")
        if event.agent_id:
            chain_parts.append(f"AI Agent ({event.agent_id})")
        if event.tool_name:
            chain_parts.append(f"Tool ({event.tool_name})")
        if event.resource:
            chain_parts.append(f"Resource ({event.resource})")
        if profile.destinations:
            chain_parts.append(f"Exfiltration Destination ({profile.destinations[0]})")
        correlation_chain_str = " → ".join(chain_parts)

        # Behavioral deviation text
        dev_text = (
            f"Source {source_ip} deviated from standard perimeter access: "
            f"{len(signals)} threat signals detected ({', '.join(signals)}). "
            f"Targeted {len(profile.targeted_users)} user(s), {len(profile.targeted_agents)} agent(s), "
            f"and {len(profile.targeted_resources)} resource(s)."
        )

        # Explanation
        explanation_str = (
            f"External threat '{primary_threat}' identified from {source_ip} ({profile.source_identity}). "
            f"Progression: {behavioral_prog.summary}. Corroborated by {len(evidence)} evidence points: "
            f"{'; '.join(evidence)}."
        )

        # Timeline entries
        timeline_entries = []
        for idx, e in enumerate(dedup_events):
            timeline_entries.append({
                "step": idx + 1,
                "timestamp": e.timestamp.isoformat() if e.timestamp else now_str,
                "event_type": e.event_type,
                "resource": e.resource,
                "user_id": e.user_id,
                "agent_id": e.agent_id,
                "tool_name": e.tool_name,
                "description": f"{e.event_type} on {e.resource or e.tool_name or 'auth'}",
            })

        return ExternalThreatAnalysis(
            threat_type=primary_threat,
            source=source_ip,
            target=target_entity,
            affected_user=event.user_id,
            device=event.device_id,
            session=event.session_id,
            ai_agent=event.agent_id,
            tool=event.tool_name,
            api=event.resource if (event.resource and "api" in event.resource.lower()) else None,
            resource=event.resource,
            timeline=timeline_entries,
            evidence=evidence,
            behavioral_deviation=dev_text,
            correlation_chain=correlation_chain_str,
            risk_contributions=contributions,
            risk_score=final_score,
            risk_level=risk_level,
            explanation=explanation_str,
            behavioral_progression=behavioral_prog,
            profile=profile,
        )

    def list_threat_profiles(self) -> List[Dict[str, Any]]:
        """Lists all known external threat source profiles."""
        result = []
        for ip, p in self.profiles.items():
            result.append({
                "source_ip": p.source_ip,
                "source_identity": p.source_identity,
                "country": p.country,
                "city": p.city,
                "asn": p.asn,
                "ip_reputation": p.ip_reputation,
                "total_requests": p.total_requests,
                "failed_requests": p.failed_requests,
                "success_requests": p.success_requests,
                "success_rate": p.success_rate,
                "targeted_users": p.targeted_users,
                "targeted_agents": p.targeted_agents,
                "targeted_resources": p.targeted_resources,
                "action_sequence": p.action_sequence,
                "total_volume_bytes": p.total_volume_bytes,
                "first_seen": p.first_seen.isoformat(),
                "last_seen": p.last_seen.isoformat(),
            })
        return result
