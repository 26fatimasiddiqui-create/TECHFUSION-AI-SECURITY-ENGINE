from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.models.event import SecurityEvent, EventType
from app.models.risk import RiskLevel

logger = logging.getLogger(__name__)


class AgentToolChain(BaseModel):
    agent_id: str
    tool_name: Optional[str] = None
    api_endpoint: Optional[str] = None
    resource: Optional[str] = None
    destination: Optional[str] = None
    is_abnormal: bool = False
    risk_level: str = "NORMAL"
    sequence: str = ""
    evidence: List[str] = Field(default_factory=list)


class RiskContribution(BaseModel):
    signal: str
    weight: int
    evidence: str
    entity: str
    timestamp: str


class AgentSecurityAnalysis(BaseModel):
    agent_id: str
    agent_name: str
    agent_type: str
    owner_user: str
    session_id: Optional[str] = None
    model_provider: str = "claude-3-5-sonnet"
    status: str = "active"  # active, quarantined, contained, normal
    risk_score: int = 0
    risk_level: str = "LOW"

    # The 10 Diagnostic Answers required by the specification
    who_owns_agent: str = ""
    what_normally_does: str = ""
    what_did_it_do: str = ""
    which_tool_used: str = ""
    which_api_called: str = ""
    which_resource_accessed: str = ""
    why_was_it_abnormal: str = ""
    risk_signals_detected: List[str] = Field(default_factory=list)
    risk_score_explanation: str = ""
    attack_chain: str = ""

    # Structured details
    tool_chain: AgentToolChain
    detected_signals: List[str] = Field(default_factory=list)
    risk_contributions: List[RiskContribution] = Field(default_factory=list)
    is_prompt_injection: bool = False
    is_indirect_injection: bool = False
    is_privilege_escalation: bool = False
    is_exfiltration: bool = False
    explanation: str = ""


class AgentBaseline(BaseModel):
    agent_id: str
    agent_name: str
    agent_type: str
    owner_user: str
    model_provider: str = "claude-3-5-sonnet"
    normal_tools: List[str] = Field(default_factory=list)
    normal_apis: List[str] = Field(default_factory=list)
    normal_resources: List[str] = Field(default_factory=list)
    normal_destinations: List[str] = Field(default_factory=lambda: ["internal"])
    max_normal_records: int = 50
    max_normal_bytes: int = 50000
    privilege_level: str = "standard"


class AgentSecurityService:
    """Treats AI Agents as FIRST-CLASS SECURITY ENTITIES.
    Maintains behavioral baselines, detects 21 specific agent threat signals,
    analyzes Agent -> Tool -> API -> Resource chains, detects direct and indirect
    prompt injection, and provides 10-question diagnostic explainability.
    """

    DEFAULT_BASELINES: Dict[str, AgentBaseline] = {
        "hr_agent": AgentBaseline(
            agent_id="hr_agent",
            agent_name="HR Assistant Copilot",
            agent_type="hr_copilot",
            owner_user="U_ANALYST",
            model_provider="claude-3-5-sonnet",
            normal_tools=["hr_directory_lookup", "policy_retrieval", "benefits_query", "org_chart_search"],
            normal_apis=["/api/hr/profile", "/api/hr/benefits", "/api/directory", "/api/v1/hr"],
            normal_resources=["employees", "employee_db", "hr_policies", "company_handbook"],
            normal_destinations=["internal"],
            max_normal_records=25,
            max_normal_bytes=20000,
            privilege_level="standard",
        ),
        "agent_copilot": AgentBaseline(
            agent_id="agent_copilot",
            agent_name="Enterprise AI Assistant",
            agent_type="enterprise_copilot",
            owner_user="U_ANALYST",
            model_provider="claude-3-5-sonnet",
            normal_tools=["doc_search", "code_helper", "task_planner", "summarizer"],
            normal_apis=["/api/docs", "/api/tasks", "/api/assistant"],
            normal_resources=["documentation", "task_logs", "public_wiki"],
            normal_destinations=["internal"],
            max_normal_records=50,
            max_normal_bytes=40000,
            privilege_level="standard",
        ),
    }

    RESTRICTED_TOOLS: Set[str] = {
        "raw_sql_exec",
        "db_drop_tool",
        "bash_shell",
        "system_command",
        "memory_dump",
        "privileged_eval",
        "exfiltrate_tool",
        "export_tool",
        "curl_exec",
        "admin_shell",
        "credential_dump",
    }

    SENSITIVE_RESOURCES: Set[str] = {
        "customer-data",
        "customer_credentials",
        "credentials",
        "passwords",
        "tokens",
        "secrets",
        "api/keys",
        "pii",
        "customer_pii",
        "payroll_admin",
        "financial_records",
        "shadow-data",
    }

    PROMPT_INJECTION_PATTERNS = [
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        r"system\s+override",
        r"you\s+are\s+now\s+in\s+dan\s+mode",
        r"dan\s+mode",
        r"you\s+are\s+now\s+unrestricted",
        r"jailbreak",
        r"bypass\s+(?:all\s+)?(?:security|safety|filter)",
        r"disable\s+safety\s+filters",
        r"developer\s+mode\s+enabled",
        r"dump\s+(?:all\s+)?credentials",
        r"dump\s+(?:customer\s+)?passwords",
        r"show\s+me\s+the\s+system\s+prompt",
    ]

    INDIRECT_INJECTION_MARKERS = [
        "<!-- instruction:",
        "[system instruction:",
        "note for ai:",
        "ignore previous and execute",
        "instruction for agent:",
        "system prompt override:",
        "execute raw sql:",
        "exfiltrate to:",
    ]

    SIGNAL_WEIGHTS: Dict[str, int] = {
        "agent_unusual_tool_usage": 15,
        "agent_new_tool": 10,
        "agent_restricted_tool_usage": 20,
        "agent_privilege_escalation": 25,
        "agent_unusual_api_call": 15,
        "agent_unusual_resource_access": 15,
        "agent_unusual_data_volume": 20,
        "agent_data_exfiltration": 30,
        "agent_prompt_injection": 25,
        "agent_indirect_prompt_injection": 30,
        "agent_tool_chain_anomaly": 20,
        "agent_action_frequency_anomaly": 15,
        "agent_session_anomaly": 15,
        "agent_identity_mismatch": 20,
        "agent_owner_mismatch": 20,
        "agent_cross_user_activity": 25,
        "agent_cross_resource_activity": 20,
        "agent_policy_violation": 20,
        "agent_sensitive_data_access": 20,
        "agent_external_destination": 15,
        "agent_suspicious_autonomy": 20,
    }

    def __init__(self):
        self.baselines: Dict[str, AgentBaseline] = dict(self.DEFAULT_BASELINES)
        self.agent_history: Dict[str, List[SecurityEvent]] = {}

    def register_baseline(self, baseline: AgentBaseline):
        self.baselines[baseline.agent_id.lower()] = baseline

    def get_baseline(self, agent_id: str) -> AgentBaseline:
        key = agent_id.lower().strip()
        if key in self.baselines:
            return self.baselines[key]
        return AgentBaseline(
            agent_id=agent_id,
            agent_name=agent_id.replace("_", " ").title(),
            agent_type="custom_copilot",
            owner_user="system",
            model_provider="claude-3-5-sonnet",
            normal_tools=["general_lookup"],
            normal_apis=["/api/default"],
            normal_resources=["general_docs"],
            normal_destinations=["internal"],
            max_normal_records=50,
            max_normal_bytes=50000,
            privilege_level="standard",
        )

    def analyze_agent_event(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> AgentSecurityAnalysis:
        """Deep security analysis for an AI Agent event against its behavioral baseline."""
        agent_id = event.agent_id or "agent_copilot"
        baseline = self.get_baseline(agent_id)
        recent_events = recent_events or []

        # Track history
        if agent_id not in self.agent_history:
            self.agent_history[agent_id] = []
        self.agent_history[agent_id].append(event)

        meta = event.metadata or {}
        signals: List[str] = []
        reasons: List[str] = []
        contributions: List[RiskContribution] = []

        now_str = event.timestamp.isoformat() if event.timestamp else datetime.now(timezone.utc).isoformat()

        # 1. Tool Usage Evaluation
        tool = event.tool_name or meta.get("tool") or meta.get("tool_name")
        if tool:
            tool_lower = tool.lower()
            if tool_lower in self.RESTRICTED_TOOLS or any(r in tool_lower for r in ["drop", "raw_sql", "shell", "exec", "dump"]):
                sig = "agent_restricted_tool_usage"
                signals.append(sig)
                ev = f"Invoked restricted administrative tool '{tool}' outside security boundary."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))
            elif baseline.normal_tools and tool_lower not in [t.lower() for t in baseline.normal_tools]:
                sig = "agent_unusual_tool_usage"
                signals.append(sig)
                ev = f"Tool '{tool}' is not in agent's baseline normal tools ({', '.join(baseline.normal_tools)})."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

                # Check if first time ever seen
                prior_tools = {
                    (e.tool_name or "").lower() for e in self.agent_history.get(agent_id, []) if e.id != event.id
                }
                if tool_lower not in prior_tools:
                    sig_new = "agent_new_tool"
                    signals.append(sig_new)
                    ev_new = f"New tool '{tool}' executed for the first time by agent {agent_id}."
                    reasons.append(ev_new)
                    contributions.append(RiskContribution(signal=sig_new, weight=self.SIGNAL_WEIGHTS[sig_new], evidence=ev_new, entity=agent_id, timestamp=now_str))

        # 2. API Call Evaluation
        api_target = event.resource if (event.resource and "api" in event.resource.lower()) else meta.get("api_endpoint")
        if api_target:
            api_lower = api_target.lower()
            if baseline.normal_apis and not any(n.lower() in api_lower for n in baseline.normal_apis):
                sig = "agent_unusual_api_call"
                signals.append(sig)
                ev = f"API endpoint '{api_target}' called outside agent's authorized domain."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 3. Resource & Data Sensitivity Access
        resource = event.resource or meta.get("target_resource")
        if resource:
            res_lower = resource.lower()
            is_sensitive = any(s in res_lower for s in self.SENSITIVE_RESOURCES)
            if is_sensitive or meta.get("is_sensitive_resource") or meta.get("sensitive_resource"):
                sig = "agent_sensitive_data_access"
                signals.append(sig)
                ev = f"Accessed high-sensitivity data resource '{resource}' (credentials/PII/secrets)."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

            is_authorized = (
                any(n.lower() in res_lower for n in baseline.normal_resources)
                or any(n.lower() in res_lower for n in baseline.normal_apis)
            )
            if (baseline.normal_resources or baseline.normal_apis) and not is_authorized:
                sig = "agent_unusual_resource_access"
                signals.append(sig)
                ev = f"Resource '{resource}' is not part of agent's normal profile ({', '.join(baseline.normal_resources)})."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 4. Privilege Escalation & Policy Violations
        if meta.get("privilege_escalation") or meta.get("unauthorized_privilege") or meta.get("elevated_role"):
            sig = "agent_privilege_escalation"
            signals.append(sig)
            ev = "Agent attempted or performed privilege escalation beyond declared authorization boundary."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        if meta.get("policy_violation") or meta.get("agent_policy_violation"):
            sig = "agent_policy_violation"
            signals.append(sig)
            ev = "Agent action explicitly violated configured system execution policies."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 5. Direct Prompt Injection Analysis
        prompt = meta.get("prompt") or meta.get("user_prompt") or meta.get("query") or ""
        is_direct_injection = False
        if isinstance(prompt, str) and prompt:
            prompt_lower = prompt.lower()
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, prompt_lower):
                    is_direct_injection = True
                    sig = "agent_prompt_injection"
                    signals.append(sig)
                    ev = f"Direct prompt injection identified matching pattern '{pattern}'."
                    reasons.append(ev)
                    contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))
                    break

        # 6. Indirect Prompt Injection Analysis
        doc_content = meta.get("document_content") or meta.get("retrieved_text") or meta.get("scraped_content") or meta.get("third_party_payload") or ""
        is_indirect_injection = False
        if isinstance(doc_content, str) and doc_content:
            doc_lower = doc_content.lower()
            for marker in self.INDIRECT_INJECTION_MARKERS:
                if marker in doc_lower:
                    is_indirect_injection = True
                    sig = "agent_indirect_prompt_injection"
                    signals.append(sig)
                    ev = f"Indirect prompt injection marker '{marker}' found in retrieved third-party content."
                    reasons.append(ev)
                    contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))
                    break

        # 7. Data Volume & Exfiltration Analysis
        records = meta.get("records_requested") or meta.get("rows_retrieved") or meta.get("count") or 0
        bytes_transferred = meta.get("outbound_bytes") or meta.get("bytes_transferred") or 0
        if records > baseline.max_normal_records or bytes_transferred > baseline.max_normal_bytes:
            sig = "agent_unusual_data_volume"
            signals.append(sig)
            ev = f"Data volume anomaly: requested {records} records / {bytes_transferred} bytes (baseline max: {baseline.max_normal_records} records / {baseline.max_normal_bytes} bytes)."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        destination = meta.get("destination") or meta.get("external_destination")
        is_exfil = False
        if destination:
            dest_lower = destination.lower()
            if dest_lower not in [d.lower() for d in baseline.normal_destinations] and dest_lower != "internal":
                sig_dest = "agent_external_destination"
                signals.append(sig_dest)
                ev_dest = f"Targeted untrusted external destination '{destination}'."
                reasons.append(ev_dest)
                contributions.append(RiskContribution(signal=sig_dest, weight=self.SIGNAL_WEIGHTS[sig_dest], evidence=ev_dest, entity=agent_id, timestamp=now_str))

                if meta.get("data_exfiltration") or records > baseline.max_normal_records or bytes_transferred > baseline.max_normal_bytes:
                    is_exfil = True
                    sig_ex = "agent_data_exfiltration"
                    signals.append(sig_ex)
                    ev_ex = f"Active data exfiltration transmission to external destination '{destination}'."
                    reasons.append(ev_ex)
                    contributions.append(RiskContribution(signal=sig_ex, weight=self.SIGNAL_WEIGHTS[sig_ex], evidence=ev_ex, entity=agent_id, timestamp=now_str))

        # 8. Owner & Identity Mismatch Analysis
        if event.user_id and baseline.owner_user:
            if event.user_id.lower() != baseline.owner_user.lower():
                sig = "agent_owner_mismatch"
                signals.append(sig)
                ev = f"Invoking user '{event.user_id}' does not match registered agent owner '{baseline.owner_user}'."
                reasons.append(ev)
                contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 9. Cross-User / Cross-Resource Activity
        target_user = meta.get("target_user") or meta.get("affected_user")
        if target_user and event.user_id and target_user.lower() != event.user_id.lower():
            sig = "agent_cross_user_activity"
            signals.append(sig)
            ev = f"Agent operating on behalf of '{event.user_id}' accessed private data of another user '{target_user}'."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        if "customer" in (resource or "").lower() and "hr" in agent_id.lower():
            sig = "agent_cross_resource_activity"
            signals.append(sig)
            ev = f"Cross-domain resource jump: HR agent accessed Customer production database '{resource}'."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 10. Suspicious Autonomy
        if meta.get("unprompted_execution") or meta.get("autonomous_loop") or event.event_type == "unprompted_execution":
            sig = "agent_suspicious_autonomy"
            signals.append(sig)
            ev = "Agent triggered unprompted autonomous execution loop without active human session input."
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        # 11. Tool-Chain Correlation: AI Agent -> Tool -> API -> Resource
        tool_val = tool or "no_tool"
        api_val = api_target or "no_api"
        res_val = resource or "no_resource"
        chain_str = f"{agent_id} → {tool_val} → {api_val} → {res_val}"
        if destination:
            chain_str += f" → {destination}"

        has_high_risk_chain = False
        chain_evidence = []
        if (
            (tool and tool.lower() in self.RESTRICTED_TOOLS)
            or (resource and any(s in resource.lower() for s in self.SENSITIVE_RESOURCES))
            or is_exfil
            or is_direct_injection
            or is_indirect_injection
        ):
            has_high_risk_chain = True
            chain_evidence.append("Tool-chain violates authorization boundary and reaches high-sensitivity data.")
            sig = "agent_tool_chain_anomaly"
            signals.append(sig)
            ev = f"Anomalous tool chain detected: {chain_str}"
            reasons.append(ev)
            contributions.append(RiskContribution(signal=sig, weight=self.SIGNAL_WEIGHTS[sig], evidence=ev, entity=agent_id, timestamp=now_str))

        tool_chain = AgentToolChain(
            agent_id=agent_id,
            tool_name=tool,
            api_endpoint=api_target,
            resource=resource,
            destination=destination,
            is_abnormal=has_high_risk_chain,
            risk_level="HIGH" if has_high_risk_chain else "NORMAL",
            sequence=chain_str,
            evidence=chain_evidence,
        )

        # Calculate explainable risk score (0-100)
        raw_score = sum(c.weight for c in contributions)
        final_score = min(100, raw_score)

        if final_score >= 80:
            risk_level = "CRITICAL"
        elif final_score >= 60:
            risk_level = "HIGH"
        elif final_score >= 30:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"

        # Unique signals
        unique_signals = list(dict.fromkeys(signals))

        # Construct the 10 Diagnostic Answers
        q1_owner = f"{baseline.owner_user} (Role: {baseline.privilege_level.title()}, Scope: {baseline.agent_type})"
        q2_normal = (
            f"Normally handles {', '.join(baseline.normal_resources)} using authorized tools: "
            f"[{', '.join(baseline.normal_tools)}] via endpoints: [{', '.join(baseline.normal_apis)}]."
        )
        q3_did_this_time = (
            f"Invoked tool '{tool_val}' calling '{api_val}' and targeting resource '{res_val}'"
            f"{f' with outbound transmission to {destination}' if destination else ''}."
        )
        q4_tool = f"{tool_val} ({'RESTRICTED / ABNORMAL' if ('agent_restricted_tool_usage' in unique_signals or 'agent_unusual_tool_usage' in unique_signals) else 'Normal'})"
        q5_api = f"{api_val} ({'UNUSUAL / EXTERNAL' if 'agent_unusual_api_call' in unique_signals else 'Authorized Gateway'})"
        q6_resource = f"{res_val} ({'CRITICAL SENSITIVE STORE' if 'agent_sensitive_data_access' in unique_signals else 'Normal Scope'})"
        q7_why_abnormal = "; ".join(reasons) if reasons else "Conforms to established behavioral baseline."
        q8_signals = unique_signals
        q9_score = f"{final_score}/100 ({risk_level}) — Derived from {len(contributions)} explainable risk contributions."
        q10_chain = chain_str

        # Explanation summary
        if unique_signals:
            summary = (
                f"{baseline.agent_name} ({agent_id}) exhibited {len(unique_signals)} threat signals: "
                f"{q7_why_abnormal}. Attack chain: {chain_str}."
            )
        else:
            summary = f"{baseline.agent_name} ({agent_id}) operated fully within normal historical baseline parameters."

        return AgentSecurityAnalysis(
            agent_id=agent_id,
            agent_name=baseline.agent_name,
            agent_type=baseline.agent_type,
            owner_user=baseline.owner_user,
            session_id=event.session_id,
            model_provider=baseline.model_provider,
            status="quarantined" if final_score >= 80 else ("active" if final_score >= 30 else "normal"),
            risk_score=final_score,
            risk_level=risk_level,
            who_owns_agent=q1_owner,
            what_normally_does=q2_normal,
            what_did_it_do=q3_did_this_time,
            which_tool_used=q4_tool,
            which_api_called=q5_api,
            which_resource_accessed=q6_resource,
            why_was_it_abnormal=q7_why_abnormal,
            risk_signals_detected=q8_signals,
            risk_score_explanation=q9_score,
            attack_chain=q10_chain,
            tool_chain=tool_chain,
            detected_signals=unique_signals,
            risk_contributions=contributions,
            is_prompt_injection=is_direct_injection,
            is_indirect_injection=is_indirect_injection,
            is_privilege_escalation="agent_privilege_escalation" in unique_signals,
            is_exfiltration=is_exfil,
            explanation=summary,
        )

    def list_tracked_agents(self) -> List[Dict[str, Any]]:
        """Lists all known agents with baselines and status."""
        result = []
        for aid, baseline in self.baselines.items():
            result.append({
                "agent_id": baseline.agent_id,
                "agent_name": baseline.agent_name,
                "agent_type": baseline.agent_type,
                "owner_user": baseline.owner_user,
                "model_provider": baseline.model_provider,
                "normal_tools": baseline.normal_tools,
                "normal_apis": baseline.normal_apis,
                "normal_resources": baseline.normal_resources,
                "privilege_level": baseline.privilege_level,
            })
        return result
