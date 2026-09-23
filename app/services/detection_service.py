from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional
from app.models.event import SecurityEvent, EventType
from app.models.risk import DetectionResult


class DetectionService:
    """Lightweight, transparent, rule-based detection service for security events.
    Modular design provides plug-and-play evaluation of internal threat behavioral signals,
    session evolution, role-resource consistency, and AI agent actions.
    """

    SENSITIVE_RESOURCE_KEYWORDS = [
        "customer-data",
        "credential",
        "secret",
        "token",
        "admin",
        "finance",
        "payment",
        "database/dump",
        "api/keys",
        "shadow-data",
        "pii",
        "passwords",
        "payroll",
        "employees",
    ]

    UNUSUAL_API_INDICATORS = [
        "/export",
        "/dump",
        "/backup",
        "/bulk",
        "/scrape",
        "/batch-download",
    ]

    RESTRICTED_TOOLS = [
        "db_drop_tool",
        "raw_sql_exec",
        "bash_shell",
        "system_command",
        "memory_dump",
        "privileged_eval",
        "exfiltrate_tool",
    ]

    UNEXPECTED_AGENT_ACTIVITIES = [
        "unauthorized_agent_call",
        "unprompted_execution",
        "agent_policy_violation",
    ]

    KNOWN_LOCATIONS = {
        "delhi": (28.6139, 77.2090),
        "new delhi": (28.6139, 77.2090),
        "mumbai": (19.0760, 72.8777),
        "bangalore": (12.9716, 77.5946),
        "london": (51.5074, -0.1278),
        "new york": (40.7128, -74.0060),
        "singapore": (1.3521, 103.8198),
        "tokyo": (35.6762, 139.6503),
        "san francisco": (37.7749, -122.4194),
        "frankfurt": (50.1109, 8.6821),
    }

    PROMPT_INJECTION_KEYWORDS = [
        "ignore previous instructions",
        "ignore all prior instructions",
        "disregard previous instructions",
        "disregard all prior instructions",
        "system override",
        "you are now in dan mode",
        "you are now unrestricted",
        "jailbreak",
        "developer mode enabled",
        "bypass policy",
        "disable safety filters",
        "administrative override",
        "bypass restrictions",
        "reveal system prompt",
        "show system instructions",
        "output internal instructions",
        "print secret keys",
        "dump credentials",
    ]

    INDIRECT_INJECTION_MARKERS = [
        "<!-- ignore previous instructions",
        "[system]: override",
        "system override",
        "bypass policy",
        "execute raw sql",
        "drop table",
        "dump credentials",
        "exfiltrate",
    ]

    SCANNER_USER_AGENTS = [
        "sqlmap",
        "nikto",
        "masscan",
        "nmap",
        "gobuster",
        "dirbuster",
        "zgrab",
        "wpscan",
    ]

    def analyze_event(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> DetectionResult:
        signals: List[str] = []
        details: Dict[str, Any] = {}

        # 1. New / Unknown Device
        if self._is_new_or_unknown_device(event, historical_context):
            signals.append("new_device")
            signals.append("unknown_device")
            details["new_device"] = "Authentication or access originated from a new or unverified device."

        # 2. New / Unseen IP Address
        if self._is_new_ip(event, historical_context):
            signals.append("new_ip")
            ip_val = event.metadata.get("ip") or event.metadata.get("ip_address") or event.metadata.get("client_ip") or "unseen_ip"
            details["new_ip"] = f"Access originated from an IP not normally associated with user: {ip_val}"

        # 3. Impossible Travel (Timestamp + Geographic distance delta)
        impossible_travel_detail = self._check_impossible_travel(event, historical_context, recent_events)
        if impossible_travel_detail:
            signals.append("impossible_travel")
            details["impossible_travel"] = impossible_travel_detail

        # 4. Abnormal Login / Activity Time
        if self._is_abnormal_login_time(event, historical_context):
            signals.append("abnormal_login_time")
            details["abnormal_login_time"] = f"Activity at {event.timestamp.hour:02d}:00 UTC occurred outside normal baseline schedule."

        # 5. Device Anomaly (OS mismatch, tampering, or sudden change within session)
        device_anomaly_detail = self._check_device_anomaly(event, historical_context, recent_events)
        if device_anomaly_detail:
            signals.append("device_anomaly")
            details["device_anomaly"] = device_anomaly_detail

        # 6. Failed login / repeated failed login
        if event.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]:
            signals.append("failed_login")
            details["failed_login"] = "Authentication failed."
            if recent_events:
                failed_count = sum(
                    1 for e in recent_events
                    if e.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]
                )
                if failed_count >= 2:
                    signals.append("repeated_failed_login")
                    details["repeated_failed_login"] = f"Multiple ({failed_count + 1}) consecutive failed logins detected."

        # 7. Sensitive resource access (Contextual signal)
        if self._is_sensitive_resource(event):
            signals.append("sensitive_resource")
            details["sensitive_resource"] = f"Accessed high-sensitivity path: {event.resource}"

        # 8. Abnormal resource access (Role or historical deviation)
        if self._is_abnormal_resource_access(event, historical_context):
            signals.append("abnormal_resource_access")
            details["abnormal_resource_access"] = f"Resource '{event.resource}' is abnormal for user's assigned role or historical pattern."

        # 9. Bulk Data Access (Large volume download/export/query)
        bulk_detail = self._check_bulk_data_access(event)
        if bulk_detail:
            signals.append("bulk_data_access")
            details["bulk_data_access"] = bulk_detail

        # 10. Privilege escalation (Transition tracking)
        priv_detail = self._check_privilege_escalation(event, recent_events)
        if priv_detail:
            signals.append("privilege_escalation")
            details["privilege_escalation"] = priv_detail

        # 11. Unusual API activity (Endpoint, frequency, method, or parameters)
        if self._is_unusual_api_access(event):
            signals.append("unusual_api_activity")
            signals.append("unusual_api_access")
            details["unusual_api_activity"] = f"Unusual API access pattern or export endpoint: {event.resource}"

        # 12. Unexpected AI agent activity
        if self._is_unexpected_agent_activity(event, historical_context):
            signals.append("unexpected_agent_activity")
            details["unexpected_agent_activity"] = f"Agent '{event.agent_id}' invoked without authorization or outside baseline profile."

        # 13. Unexpected / restricted tool usage
        tool_signal = self._check_tool_usage(event, historical_context)
        if tool_signal:
            signals.append(tool_signal)
            signals.append("unusual_tool_usage")
            details["unexpected_tool_usage"] = f"Tool '{event.tool_name}' is restricted or atypical for agent '{event.agent_id}'."

        # 14. Session Behavior Correlation (Post-authentication behavioral chain evaluation)
        if self._is_suspicious_session_behavior(event, signals, recent_events):
            signals.append("suspicious_session_behavior")
            details["suspicious_session_behavior"] = "Session exhibits multi-step post-authentication behavioral divergence."

        # 15. Historical Context baseline deviation fallback
        if historical_context and historical_context.get("is_anomaly"):
            if "unexpected_tool_usage" not in signals and historical_context.get("tool_never_used_by_agent"):
                signals.append("unexpected_tool_usage")
            if "unknown_device" not in signals and historical_context.get("device_unseen_for_user"):
                signals.append("unknown_device")
                signals.append("new_device")
            if "new_ip" not in signals and historical_context.get("ip_unseen_for_user"):
                signals.append("new_ip")
            if "impossible_travel" not in signals and historical_context.get("impossible_travel_suspected"):
                signals.append("impossible_travel")
            if "abnormal_login_time" not in signals and historical_context.get("abnormal_login_time"):
                signals.append("abnormal_login_time")
            if "abnormal_resource_access" not in signals and historical_context.get("role_resource_mismatch"):
                signals.append("abnormal_resource_access")

        # =====================================================================
        # Step 3: EXTERNAL THREAT DETECTION RULES
        # =====================================================================

        # 16. External Login Attacks (Brute-Force, Credential Stuffing, Password Spraying, Distributed, Bursts)
        ext_login_signals = self._check_external_login_attacks(event, recent_events)
        for sig, msg in ext_login_signals.items():
            signals.append(sig)
            details[sig] = msg

        # 17. External IP & Bot / Automated Behavior
        ip_bot_signals = self._check_external_ip_and_bot(event, recent_events)
        for sig, msg in ip_bot_signals.items():
            signals.append(sig)
            details[sig] = msg

        # 18. API Abuse (Bursts, repeated 401/403, rate-limit thresholds)
        api_abuse_msg = self._check_api_abuse(event, recent_events)
        if api_abuse_msg:
            signals.append("api_abuse")
            details["api_abuse"] = api_abuse_msg

        # 19. Direct & Indirect Prompt Injection
        prompt_inj_msg = self._check_prompt_injection(event)
        if prompt_inj_msg:
            signals.append("prompt_injection")
            details["prompt_injection"] = prompt_inj_msg

        indirect_inj_msg = self._check_indirect_prompt_injection(event, recent_events)
        if indirect_inj_msg:
            signals.append("indirect_prompt_injection")
            details["indirect_prompt_injection"] = indirect_inj_msg

        # 20. AI Agent Abuse & Agent Privilege Abuse
        agent_abuse_signals = self._check_agent_abuse(event, historical_context, recent_events)
        for sig, msg in agent_abuse_signals.items():
            signals.append(sig)
            details[sig] = msg

        # 21. Data Exfiltration
        exfil_msg = self._check_data_exfiltration(event, recent_events)
        if exfil_msg:
            signals.append("data_exfiltration")
            details["data_exfiltration"] = exfil_msg

        # 22. External Attack Chain (End-to-end multi-step sequence)
        attack_chain_msg = self._check_external_attack_chain(event, signals, recent_events)
        if attack_chain_msg:
            signals.append("external_attack_chain")
            details["external_attack_chain"] = attack_chain_msg

        return DetectionResult(
            is_suspicious=len(signals) > 0,
            signals=list(dict.fromkeys(signals)),  # preserve order & unique
            details=details,
        )

    def _is_new_or_unknown_device(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if event.metadata.get("is_new_device") is True:
            return True
        if event.metadata.get("device_status") in ["unrecognized", "unknown", "new"]:
            return True
        if event.device_id and "unknown" in event.device_id.lower():
            return True
        if event.event_type in [EventType.DEVICE_CHANGE.value, "device_change"]:
            return True
        if historical_context and historical_context.get("device_unseen_for_user"):
            return True
        return False

    def _is_new_ip(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if event.metadata.get("is_new_ip") is True:
            return True
        if event.metadata.get("ip_status") in ["unrecognized", "unknown", "new"]:
            return True
        if historical_context and historical_context.get("ip_unseen_for_user"):
            return True
        return False

    def _calculate_haversine(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        r = 6371.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2.0) ** 2
        return r * 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    def _get_coords(self, loc_name: Optional[str], lat: Any, lon: Any) -> Optional[tuple]:
        if lat is not None and lon is not None:
            try:
                return float(lat), float(lon)
            except (ValueError, TypeError):
                pass
        if loc_name:
            k = str(loc_name).strip().lower()
            if k in self.KNOWN_LOCATIONS:
                return self.KNOWN_LOCATIONS[k]
        return None

    def _check_impossible_travel(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        if event.metadata.get("impossible_travel") is True:
            return "Geographically inconsistent login activity detected in unrealistic time window."

        if historical_context and historical_context.get("impossible_travel_suspected"):
            return "Impossible travel detected between user's current location and historical baseline."

        # Check against recent events for the same user
        curr_loc = event.metadata.get("location") or event.metadata.get("city")
        curr_lat = event.metadata.get("lat") or event.metadata.get("latitude")
        curr_lon = event.metadata.get("lon") or event.metadata.get("longitude")
        curr_coords = self._get_coords(curr_loc, curr_lat, curr_lon)

        if not curr_coords or not recent_events:
            return None

        curr_time = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)

        for prev in reversed(recent_events):
            if prev.id == event.id:
                continue
            prev_loc = prev.metadata.get("location") or prev.metadata.get("city")
            prev_lat = prev.metadata.get("lat") or prev.metadata.get("latitude")
            prev_lon = prev.metadata.get("lon") or prev.metadata.get("longitude")
            prev_coords = self._get_coords(prev_loc, prev_lat, prev_lon)

            if prev_coords:
                prev_time = prev.timestamp if prev.timestamp.tzinfo else prev.timestamp.replace(tzinfo=timezone.utc)
                delta_sec = abs((curr_time - prev_time).total_seconds())
                delta_hr = max(delta_sec / 3600.0, 0.001)

                dist_km = self._calculate_haversine(prev_coords[0], prev_coords[1], curr_coords[0], curr_coords[1])
                if dist_km > 250:
                    speed = dist_km / delta_hr
                    if speed > 850 or (dist_km > 1000 and delta_hr < 2.0):
                        return f"Impossible travel: {int(dist_km)} km traversed ({prev_loc or 'origin'} -> {curr_loc or 'dest'}) in {delta_hr:.2f}h (~{int(speed)} km/h)."

        return None

    def _is_abnormal_login_time(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if event.metadata.get("is_abnormal_time") is True or event.metadata.get("unusual_time") is True:
            return True
        if historical_context and historical_context.get("abnormal_login_time"):
            return True
        return False

    def _check_device_anomaly(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        if event.metadata.get("device_anomaly") is True or event.metadata.get("is_device_anomaly") is True:
            return "Device anomaly flagged in authentication metadata."

        client_os = str(event.metadata.get("client_os") or event.metadata.get("os") or "").lower()
        dev_id = str(event.device_id or "").lower()

        # Check for obvious OS / device name contradiction (e.g. device named Windows but client_os is Linux)
        if "windows" in dev_id and "linux" in client_os:
            return f"Device anomaly: Device fingerprint '{event.device_id}' inconsistent with client OS '{client_os}'."
        if "mac" in dev_id and "windows" in client_os:
            return f"Device anomaly: Device fingerprint '{event.device_id}' inconsistent with client OS '{client_os}'."

        if event.metadata.get("device_tampering") is True:
            return "Device integrity check failed: potential tampering detected."

        return None

    def _is_abnormal_resource_access(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if event.metadata.get("abnormal_resource") is True or event.metadata.get("role_violation") is True:
            return True
        if historical_context and historical_context.get("role_resource_mismatch"):
            return True
        return False

    def _check_bulk_data_access(self, event: SecurityEvent) -> Optional[str]:
        if event.metadata.get("bulk_data_access") is True or event.metadata.get("is_bulk") is True or event.metadata.get("bulk_export") is True:
            return "Bulk data export / download explicitly requested."

        records = (
            event.metadata.get("records_requested")
            or event.metadata.get("records_count")
            or event.metadata.get("batch_size")
            or event.metadata.get("download_count")
        )
        if records and isinstance(records, (int, float)) and records >= 1000:
            return f"Bulk data threshold exceeded: {int(records)} records requested."

        if event.resource:
            res_lower = event.resource.lower()
            if any(ind in res_lower for ind in ["/export", "/dump", "/bulk", "/batch-download"]):
                return f"Bulk export endpoint accessed: {event.resource}"

        return None

    def _check_privilege_escalation(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        if event.event_type in [EventType.PRIVILEGE_CHANGE.value, "privilege_change", "privilege_escalation"]:
            prev = event.metadata.get("previous_role") or event.metadata.get("previous_privilege") or "standard"
            new_r = event.metadata.get("new_role") or event.metadata.get("role") or "elevated"
            return f"Privilege change transition: {prev} -> {new_r}."

        if event.metadata.get("privilege_escalation") is True:
            prev = event.metadata.get("previous_role") or "standard"
            new_r = event.metadata.get("new_role") or event.metadata.get("role") or "admin"
            return f"Privilege escalation transition: {prev} -> {new_r}."

        if event.metadata.get("role") in ["admin", "root", "superuser"] and event.metadata.get("is_elevation"):
            return "Administrative role elevation detected."

        # Sequence check in recent events: recent privilege change followed by sensitive access
        if recent_events and self._is_sensitive_resource(event):
            for e in reversed(recent_events[-5:]):
                if e.event_type in [EventType.PRIVILEGE_CHANGE.value, "privilege_change", "privilege_escalation"] or e.metadata.get("privilege_escalation"):
                    return f"Post-privilege-escalation activity: High-privilege role used to access {event.resource}."

        return None

    def _is_sensitive_resource(self, event: SecurityEvent) -> bool:
        if event.metadata.get("is_sensitive") is True:
            return True
        if event.metadata.get("sensitivity") in ["high", "critical", "restricted"]:
            return True
        if not event.resource:
            return False
        resource_lower = event.resource.lower()
        return any(kw in resource_lower for kw in self.SENSITIVE_RESOURCE_KEYWORDS)

    def _is_unusual_api_access(self, event: SecurityEvent) -> bool:
        if event.metadata.get("unusual_api") is True or event.metadata.get("burst_api") is True:
            return True
        if event.event_type not in [
            EventType.API_ACCESS.value,
            "api_access",
            "data_access",
            "database_access",
        ]:
            return False
        if event.resource:
            res_lower = event.resource.lower()
            if any(ind in res_lower for ind in self.UNUSUAL_API_INDICATORS):
                return True
        # Bulk records threshold
        records = event.metadata.get("records_requested") or event.metadata.get("batch_size")
        if records and isinstance(records, (int, float)) and records >= 1000:
            return True
        return False

    def _is_unexpected_agent_activity(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not event.agent_id:
            return False
        if event.metadata.get("unexpected_agent") is True:
            return True
        if event.metadata.get("unauthorized") is True:
            return True
        if event.event_type in self.UNEXPECTED_AGENT_ACTIVITIES:
            return True
        if historical_context and historical_context.get("agent_unseen_for_user"):
            return True
        return False

    def _check_tool_usage(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        if not event.tool_name:
            return None
        tool_lower = event.tool_name.lower()
        if any(restricted in tool_lower for restricted in self.RESTRICTED_TOOLS):
            return "unexpected_tool_usage"
        if historical_context and historical_context.get("tool_never_used_by_agent"):
            return "unexpected_tool_usage"
        return None

    def _is_suspicious_session_behavior(
        self,
        event: SecurityEvent,
        signals: List[str],
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> bool:
        """Evaluates whether session has transitioned from normal authentication to abnormal
        behavioral chain across login -> device -> IP -> API -> resource.
        """
        if not recent_events or len(recent_events) < 2:
            return False

        # If session already contains auth/device anomalies and current event accesses sensitive or bulk data
        has_auth_anomalies = any(
            s in signals
            for s in ["new_device", "unknown_device", "new_ip", "impossible_travel", "abnormal_login_time"]
        )
        has_payload_signals = any(
            s in signals
            for s in ["sensitive_resource", "bulk_data_access", "privilege_escalation", "unusual_api_activity", "unusual_api_access"]
        )
        return has_auth_anomalies and has_payload_signals

    # =========================================================================
    # Step 3: EXTERNAL THREAT HELPER METHODS
    # =========================================================================

    def _check_external_login_attacks(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Dict[str, str]:
        signals: Dict[str, str] = {}
        meta = event.metadata or {}

        # Explicit metadata indicators from upstream sensors/WAF
        if meta.get("attack_type") == "brute_force" or meta.get("is_brute_force") is True:
            signals["brute_force_login"] = "Brute-force authentication attack detected against target account."
        if meta.get("attack_type") == "credential_stuffing" or meta.get("is_credential_stuffing") is True:
            signals["credential_stuffing"] = "Automated credential stuffing pattern detected from external source."
        if meta.get("attack_type") == "password_spraying" or meta.get("is_password_spraying") is True:
            signals["password_spraying"] = "Password spraying pattern detected across multiple user accounts."
        if meta.get("is_distributed") is True or meta.get("attack_type") == "distributed_attack":
            signals["distributed_attack"] = "Distributed attack pattern coordinated across multiple external IP addresses."

        # Stateful correlation over recent_events window
        if recent_events and event.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]:
            current_ip = meta.get("ip") or meta.get("ip_address") or meta.get("client_ip")
            target_user = event.user_id

            # 1. Brute-force: Repeated failed logins against same user
            same_user_failures = [
                e for e in recent_events
                if e.user_id == target_user and e.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]
            ]
            if len(same_user_failures) >= 2:  # current event makes >= 3
                signals["brute_force_login"] = (
                    f"Rapid consecutive failed logins ({len(same_user_failures) + 1}) targeting account '{target_user}'."
                )

            # 2. Password spraying: Same external IP attempting failed logins across multiple distinct users
            if current_ip:
                ip_failures = [
                    e for e in recent_events
                    if (e.metadata.get("ip") == current_ip or e.metadata.get("client_ip") == current_ip)
                    and e.event_type in [EventType.FAILED_LOGIN.value, "failed_login"]
                ]
                distinct_users = {e.user_id for e in ip_failures if e.user_id}
                if target_user:
                    distinct_users.add(target_user)
                if len(distinct_users) >= 3:
                    signals["password_spraying"] = (
                        f"External IP {current_ip} attempted failed logins across {len(distinct_users)} distinct user accounts."
                    )

            # 3. Distributed attack: Same target user attacked by multiple distinct external IPs
            if target_user:
                distinct_ips = set()
                if current_ip:
                    distinct_ips.add(current_ip)
                for e in same_user_failures:
                    e_ip = e.metadata.get("ip") or e.metadata.get("client_ip")
                    if e_ip:
                        distinct_ips.add(e_ip)
                if len(distinct_ips) >= 3:
                    signals["distributed_attack"] = (
                        f"Target user '{target_user}' subjected to authentication attempts from {len(distinct_ips)} distinct IPs."
                    )

        return signals

    def _check_external_ip_and_bot(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Dict[str, str]:
        signals: Dict[str, str] = {}
        meta = event.metadata or {}

        # 1. Suspicious / Threat-intel flagged external IP
        if (
            meta.get("is_suspicious_ip") is True
            or meta.get("ip_reputation") in ["malicious", "suspicious", "high_risk"]
            or meta.get("threat_intel_score", 0) > 60
            or meta.get("is_tor") is True
            or meta.get("is_proxy") is True
            or meta.get("is_vpn") is True
        ):
            ip_val = meta.get("ip") or meta.get("client_ip") or "external_source"
            signals["suspicious_external_ip"] = f"Origin IP {ip_val} flagged with high threat/proxy reputation."

        # 2. Automated scanner / Bot user-agent or behavior
        user_agent = (meta.get("user_agent") or meta.get("User-Agent") or "").lower()
        if (
            meta.get("is_bot") is True
            or meta.get("automated") is True
            or any(scanner in user_agent for scanner in self.SCANNER_USER_AGENTS)
        ):
            signals["bot_automated_behavior"] = (
                f"Automated bot or security scanner behavior detected (User-Agent: {user_agent or 'automated'})."
            )

        # 3. Rapid unhuman burst from same IP
        if recent_events and not signals.get("bot_automated_behavior"):
            current_ip = meta.get("ip") or meta.get("client_ip")
            if current_ip:
                recent_same_ip = [
                    e for e in recent_events
                    if (e.metadata.get("ip") == current_ip or e.metadata.get("client_ip") == current_ip)
                ]
                if len(recent_same_ip) >= 5:
                    signals["bot_automated_behavior"] = (
                        f"High-frequency request burst ({len(recent_same_ip) + 1} requests) originating from IP {current_ip}."
                    )

        return signals

    def _check_api_abuse(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        meta = event.metadata or {}

        # Direct explicit API abuse or rate-limit violations
        if meta.get("api_abuse") is True or meta.get("rate_limit_exceeded") is True:
            return "Excessive request rate or anomalous API consumption pattern detected."

        status_code = meta.get("status_code") or meta.get("http_status")
        if status_code in [401, 403, 429]:
            # Check if there are repeated auth/permission failures in API calls
            if recent_events:
                status_failures = sum(
                    1 for e in recent_events
                    if (e.metadata.get("status_code") in [401, 403, 429]
                        or e.metadata.get("http_status") in [401, 403, 429])
                )
                if status_failures >= 2:
                    return f"Repeated unauthorized/forbidden API responses ({status_failures + 1} requests with HTTP {status_code})."

        # High request rate in event metadata
        if meta.get("request_count", 0) > 40 or meta.get("burst_rate", 0) > 20:
            return f"Abnormal API burst volume ({meta.get('request_count') or meta.get('burst_rate')} calls) exceeding standard threshold."

        return None

    def _check_prompt_injection(self, event: SecurityEvent) -> Optional[str]:
        meta = event.metadata or {}
        text_corpus: List[str] = []

        # Check prompt, query, input_text, payload, message in event or metadata
        if event.resource:
            text_corpus.append(str(event.resource).lower())
        for key in ["prompt", "input", "query", "payload", "message", "text", "user_prompt"]:
            val = meta.get(key)
            if val and isinstance(val, str):
                text_corpus.append(val.lower())

        combined_text = " ".join(text_corpus)
        for keyword in self.PROMPT_INJECTION_KEYWORDS:
            if keyword in combined_text:
                return f"Prompt injection pattern detected: '{keyword}' identified in AI agent prompt."

        if meta.get("prompt_injection") is True or meta.get("is_jailbreak") is True:
            return "Prompt injection or jailbreak payload identified by upstream guardrail."

        return None

    def _check_indirect_prompt_injection(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        meta = event.metadata or {}

        # Check explicit indirect injection flag
        if meta.get("indirect_injection") is True or meta.get("tainted_document") is True:
            return "Untrusted external document/source contained instructions overriding AI agent safety policies."

        # Check document/external retrieved content
        source_type = meta.get("source_type") or meta.get("content_origin")
        external_content = meta.get("document_content") or meta.get("retrieved_text") or meta.get("scraped_content")

        if external_content and isinstance(external_content, str):
            content_lower = external_content.lower()
            for marker in self.INDIRECT_INJECTION_MARKERS:
                if marker in content_lower:
                    return f"Indirect prompt injection vector '{marker}' discovered inside retrieved external content ({source_type or 'external_doc'})."

        return None

    def _check_agent_abuse(
        self,
        event: SecurityEvent,
        historical_context: Optional[Dict[str, Any]] = None,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Dict[str, str]:
        signals: Dict[str, str] = {}
        meta = event.metadata or {}

        # 1. AI Agent Abuse: External caller directing agent to perform policy-violating tasks
        if meta.get("agent_abuse") is True or meta.get("ai_agent_abuse") is True:
            signals["ai_agent_abuse"] = "AI Agent abused to execute unapproved or policy-violating workflow."

        # External IP interacting directly with agent without active user session
        if event.agent_id and (meta.get("client_ip") or meta.get("ip")):
            if not event.session_id and not event.user_id:
                signals["ai_agent_abuse"] = f"Direct unauthenticated external invocation of AI agent '{event.agent_id}'."

        # 2. Agent Privilege Abuse: AI Agent invoking restricted tools or bypassing privilege constraints
        if event.agent_id and event.tool_name:
            tool_lower = event.tool_name.lower()
            is_restricted = any(r in tool_lower for r in self.RESTRICTED_TOOLS)
            is_sensitive_res = any(s in str(event.resource).lower() for s in self.SENSITIVE_RESOURCE_KEYWORDS)
            if is_restricted or meta.get("unauthorized_privilege") is True:
                signals["agent_privilege_abuse"] = (
                    f"Agent '{event.agent_id}' invoked restricted privileged tool '{event.tool_name}' without authorization."
                )
            elif is_sensitive_res and meta.get("unprompted") is True:
                signals["agent_privilege_abuse"] = (
                    f"Agent '{event.agent_id}' accessed sensitive resource '{event.resource}' autonomously."
                )

        return signals

    def _check_data_exfiltration(
        self,
        event: SecurityEvent,
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        meta = event.metadata or {}

        # Explicit exfiltration flag
        if meta.get("data_exfiltration") is True or meta.get("is_exfiltration") is True:
            return "Outbound data transmission flagged as active data exfiltration."

        # Outbound byte volume exceeding threshold
        outbound_bytes = meta.get("outbound_bytes") or meta.get("bytes_transferred") or meta.get("bytes_sent") or 0
        if isinstance(outbound_bytes, (int, float)) and outbound_bytes > 500_000:
            destination = meta.get("destination") or meta.get("external_destination") or "external host"
            return f"High-volume data transfer ({int(outbound_bytes):,} bytes) dispatched to external endpoint '{destination}'."

        # Sensitive resource coupled with untrusted destination
        destination = str(meta.get("destination") or meta.get("external_ip") or meta.get("external_url") or "").lower()
        if destination and ("untrusted" in destination or "attacker" in destination or "webhook.site" in destination or "pastebin" in destination):
            return f"Data routed to untrusted destination '{destination}'."

        return None

    def _check_external_attack_chain(
        self,
        event: SecurityEvent,
        signals: List[str],
        recent_events: Optional[List[SecurityEvent]] = None,
    ) -> Optional[str]:
        """Evaluates whether current event completes an end-to-end coordinated attack chain:
        External Source / Login Attack -> Valid Session / API Access -> Agent / Tool Abuse -> Exfiltration / Resource Access.
        """
        all_signals = set(signals)
        if recent_events:
            for e in recent_events:
                # Add signals from metadata or prior detections
                if e.metadata.get("detected_signals"):
                    all_signals.update(e.metadata["detected_signals"])
                if e.metadata.get("signals"):
                    all_signals.update(e.metadata["signals"])

        has_external_entry = any(
            s in all_signals
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

        has_execution_or_abuse = any(
            s in all_signals
            for s in [
                "api_abuse",
                "prompt_injection",
                "indirect_prompt_injection",
                "ai_agent_abuse",
                "agent_privilege_abuse",
                "unexpected_agent_activity",
                "unexpected_tool_usage",
                "privilege_escalation",
            ]
        )

        has_payload_or_exfil = any(
            s in all_signals
            for s in [
                "data_exfiltration",
                "sensitive_resource",
                "bulk_data_access",
            ]
        )

        if has_external_entry and has_execution_or_abuse and has_payload_or_exfil:
            return "Coordinated end-to-end attack chain confirmed: External Entry -> Execution/Agent Abuse -> Sensitive Access/Exfiltration."

        return None

