from typing import Any, Dict, List, Optional
from app.models.risk import RiskAssessment, RiskLevel


class RiskService:
    """Transparent risk calculation and explanation engine.
    Combines detected signals, event correlation patterns, and historical Cognee context
    to produce bounded risk scores, categorized risk levels, confidence ratings,
    plain-English reasons, and recommended mitigation actions.
    Ensures single weak signals remain contextual (LOW/MODERATE) while multi-signal
    combinations escalate to HIGH/CRITICAL.
    """

    # Configurable prototype signal weights
    SIGNAL_WEIGHTS: Dict[str, int] = {
        # Internal threat signals (Step 2)
        "new_device": 15,
        "unknown_device": 15,
        "new_ip": 10,
        "impossible_travel": 30,
        "abnormal_login_time": 10,
        "device_anomaly": 15,
        "abnormal_resource_access": 15,
        "sensitive_resource": 20,
        "bulk_data_access": 20,
        "privilege_escalation": 25,
        "unusual_api_activity": 15,
        "unusual_api_access": 15,
        "suspicious_session_behavior": 20,
        "failed_login": 10,
        "repeated_failed_login": 20,
        "unexpected_agent_activity": 20,
        "unexpected_tool_usage": 20,
        "unusual_tool_usage": 10,
        "abnormal_event_sequence": 20,
        "contextual_baseline_deviation": 15,
        # External threat signals (Step 3)
        "brute_force_login": 25,
        "credential_stuffing": 30,
        "password_spraying": 30,
        "distributed_attack": 30,
        "suspicious_external_ip": 15,
        "api_abuse": 20,
        "prompt_injection": 25,
        "indirect_prompt_injection": 30,
        "ai_agent_abuse": 20,
        "agent_privilege_abuse": 25,
        "data_exfiltration": 30,
        "bot_automated_behavior": 20,
        "external_attack_chain": 25,
        # AI Agent deep security analysis signals (Area 2)
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

    # Signal alias groups to prevent double-counting synonymous detections
    ALIAS_GROUPS = [
        {"new_device", "unknown_device"},
        {"unusual_api_activity", "unusual_api_access"},
    ]

    # Human-readable explanations
    SIGNAL_EXPLANATIONS: Dict[str, str] = {
        "new_device": "Login/access originated from a device not previously associated with this user.",
        "unknown_device": "Login/access originated from an unknown or newly seen device.",
        "new_ip": "Network connection originated from an IP address not normally associated with the user.",
        "impossible_travel": "Impossible travel: User authenticated across geographically distant locations in an unrealistic time frame.",
        "abnormal_login_time": "Activity occurred outside the user's established historical baseline schedule.",
        "device_anomaly": "Device characteristics or fingerprint inconsistent with normal user profile.",
        "abnormal_resource_access": "Access to resources that deviate from the user's historical behavior or role profile.",
        "sensitive_resource": "Sensitive or restricted internal resource path was accessed.",
        "bulk_data_access": "Unusually large volume of records or bulk data exported/downloaded within a short period.",
        "privilege_escalation": "Privilege elevation transition or administrative role change detected.",
        "unusual_api_activity": "Unusual API call frequency, method, or endpoint accessed.",
        "unusual_api_access": "Unusual API access pattern or bulk data export requested.",
        "suspicious_session_behavior": "Session exhibits abnormal post-authentication behavior across entities.",
        "failed_login": "Authentication attempt failed.",
        "repeated_failed_login": "Repeated failed login attempts observed within correlation window.",
        "unexpected_agent_activity": "AI agent exhibited unprompted or unauthorized execution.",
        "unexpected_tool_usage": "AI agent invoked a restricted tool or an action outside its known baseline.",
        "unusual_tool_usage": "Tool usage deviates from agent baseline.",
        "abnormal_event_sequence": "Related suspicious activity occurred within the same session/entity chain.",
        "contextual_baseline_deviation": "Activity conflicts with historical entity profile graph.",
        # Step 3 Explanations
        "brute_force_login": "Rapid repeated authentication attempts targeting a specific user account.",
        "credential_stuffing": "Automated authentication attempts leveraging compromised credential lists.",
        "password_spraying": "Authentication attempts across multiple usernames using common passwords from an external IP.",
        "distributed_attack": "Coordinated authentication or request barrage distributed across multiple external IP addresses.",
        "suspicious_external_ip": "Connection originated from an external IP flagged for malicious reputation, TOR exit node, or proxy.",
        "api_abuse": "Anomalous API consumption, rate-limit threshold violations, or repeated forbidden requests.",
        "prompt_injection": "Direct prompt injection attempt identified designed to override AI agent system instructions.",
        "indirect_prompt_injection": "Indirect prompt injection detected in retrieved external document or third-party content.",
        "ai_agent_abuse": "AI agent manipulated or driven without authorization to execute policy-violating tasks.",
        "agent_privilege_abuse": "AI agent invoked restricted privileged tools or performed unauthorized high-privilege actions.",
        "data_exfiltration": "Active or anomalous outbound data transmission to untrusted external destination.",
        "bot_automated_behavior": "Automated web scanner or bot behavior detected from external client.",
        "external_attack_chain": "End-to-end coordinated attack progression: External Recon/Auth -> Agent/API Abuse -> Exfiltration.",
        # AI Agent Deep Analysis Explanations
        "agent_unusual_tool_usage": "AI agent invoked a tool outside its established behavioral baseline.",
        "agent_new_tool": "AI agent executed a newly observed tool for the first time.",
        "agent_restricted_tool_usage": "AI agent executed a restricted administrative/system tool.",
        "agent_privilege_escalation": "AI agent attempted or executed privilege escalation beyond authorized boundary.",
        "agent_unusual_api_call": "AI agent called an API endpoint outside its declared domain.",
        "agent_unusual_resource_access": "AI agent accessed an internal data resource outside its baseline profile.",
        "agent_unusual_data_volume": "AI agent requested or transmitted an abnormally high data volume.",
        "agent_data_exfiltration": "AI agent transmitted sensitive data to an untrusted external destination.",
        "agent_prompt_injection": "Direct malicious prompt injection vector detected in agent user instruction.",
        "agent_indirect_prompt_injection": "Indirect prompt injection vector discovered in external content retrieved by agent.",
        "agent_tool_chain_anomaly": "AI Agent -> Tool -> API -> Resource sequence exhibits high-risk authorization breach.",
        "agent_action_frequency_anomaly": "AI agent executed an abnormally rapid burst of automated actions.",
        "agent_session_anomaly": "AI agent execution detected in disconnected or anomalous session context.",
        "agent_identity_mismatch": "AI agent identity credentials conflict with registered metadata.",
        "agent_owner_mismatch": "Invoking user does not match the registered owner of this AI agent.",
        "agent_cross_user_activity": "AI agent accessed private data belonging to a different user identity.",
        "agent_cross_resource_activity": "AI agent crossed domain boundaries into restricted production stores.",
        "agent_policy_violation": "AI agent action violated configured security system prompt policy.",
        "agent_sensitive_data_access": "AI agent accessed sensitive credentials, tokens, or PII stores.",
        "agent_external_destination": "AI agent routed communication to an untrusted external host.",
        "agent_suspicious_autonomy": "AI agent executed autonomous action loop without active human prompt instruction.",
    }

    def assess_risk(
        self,
        signals: List[str],
        context: Optional[Dict[str, Any]] = None,
        correlated_event_count: int = 1,
    ) -> RiskAssessment:
        unique_signals = list(dict.fromkeys(signals))

        # Deduplicate synonymous signals for score weighting
        scored_signals = list(unique_signals)
        for group in self.ALIAS_GROUPS:
            present_in_group = [s for s in scored_signals if s in group]
            if len(present_in_group) > 1:
                # Keep only the first one for score weighting calculation
                for extra in present_in_group[1:]:
                    scored_signals.remove(extra)

        # Base score from signal weights
        raw_score = sum(self.SIGNAL_WEIGHTS.get(sig, 10) for sig in scored_signals)

        # Multi-signal synergistic correlation:
        # If 3 or more distinct behavioral signals corroborate, add synergy bonus
        known_threat_signals = set(self.SIGNAL_WEIGHTS.keys()) - {"failed_login"}
        distinct_threat_count = len(set(scored_signals).intersection(known_threat_signals))
        if distinct_threat_count >= 5:
            raw_score += 20
        elif distinct_threat_count >= 4:
            raw_score += 15
        elif distinct_threat_count >= 3:
            raw_score += 10

        # Additional risk if correlated multi-event chain has many events
        if correlated_event_count >= 4 and ("abnormal_event_sequence" in unique_signals or "external_attack_chain" in unique_signals):
            raw_score += 10

        risk_score = min(100, max(0, raw_score))

        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
            recommended_action = "Require human approval / suspend or isolate the affected action"
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
            recommended_action = "Require verification / restrict sensitive access"
        elif risk_score >= 30:
            risk_level = RiskLevel.MODERATE
            recommended_action = "Increase monitoring"
        else:
            risk_level = RiskLevel.LOW
            recommended_action = "Continue monitoring"

        # Construct clear, plain-English reasons
        reasons: List[str] = []
        for sig in unique_signals:
            if sig in self.SIGNAL_EXPLANATIONS:
                explanation = self.SIGNAL_EXPLANATIONS[sig]
                if explanation not in reasons:
                    reasons.append(explanation)
            else:
                reasons.append(f"Detected suspicious pattern: {sig}")

        # Incorporate specific context summary from Cognee if anomalous
        if context and context.get("is_anomaly") and context.get("summary"):
            if context["summary"] not in reasons:
                reasons.append(context["summary"])

        if not reasons:
            reasons.append("Standard activity conforming to security baseline.")

        # Confidence rating calculation (0.0 to 1.0)
        # Base 0.70, rising by 0.05 per corroborating signal, up to 0.96
        if len(unique_signals) == 0:
            confidence = 0.85
        else:
            confidence = min(0.96, round(0.70 + (len(unique_signals) * 0.055), 2))

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            reasons=reasons,
            recommended_action=recommended_action,
            correlated_signals=unique_signals,
        )

