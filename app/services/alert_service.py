from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.models.alert import SecurityAlert
from app.models.risk import RiskAssessment, RiskLevel
from app.repositories.supabase_repository import SupabaseRepository

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {
    "LOW": 1,
    "MODERATE": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def sanitize_for_voice(text: str) -> str:
    """Sanitizes text for Web Speech API, removing sensitive tokens, passwords, and raw hashes."""
    if not text:
        return ""
    # Strip bearer tokens, passwords, raw hashes, or JWTs
    cleaned = re.sub(
        r'(bearer\s+[\w\.\-]+|password\s*=\s*\S+|token\s*=\s*\S+|jwt\s*=\s*\S+|eyJ[\w\.\-]+)',
        '[REDACTED]',
        text,
        flags=re.IGNORECASE,
    )
    return cleaned.strip()[:220]


def derive_threat_type(
    signals: Optional[List[str]] = None,
    event_type: Optional[str] = None,
    reasons: Optional[List[str]] = None,
) -> str:
    """Derives a concise, human-readable primary threat type from correlated signals and reasons."""
    sig_set = set(signals or [])
    if any(s in sig_set for s in ["external_attack_chain", "suspicious_external_ip"]):
        return "External attack chain"
    if any(s in sig_set for s in ["brute_force_login", "credential_stuffing", "password_spraying"]):
        return "Credential attack"
    if any(s in sig_set for s in ["prompt_injection", "agent_privilege_abuse"]):
        return "AI agent privilege abuse"
    if any(s in sig_set for s in ["data_exfiltration"]):
        return "Data exfiltration"
    if any(s in sig_set for s in ["sensitive_resource", "restricted_tool"]):
        return "Unusual resource access"
    if any(s in sig_set for s in ["impossible_travel", "unknown_device", "repeated_failed_login"]):
        return "Anomalous authentication"
    if event_type:
        return event_type.replace("_", " ").title()
    return "Suspicious security activity"


def format_voice_message(
    severity: str,
    risk_score: int,
    threat_type: str,
    affected_entity: Optional[str] = None,
    approval_required: bool = False,
) -> str:
    """Generates concise, sanitized voice announcement text for browser Web Speech API."""
    entity_str = ""
    if affected_entity and affected_entity not in ["U_UNKNOWN", "system"]:
        entity_str = f" for user {sanitize_for_voice(affected_entity)}"

    if severity == "CRITICAL":
        approval_part = " Human approval is required before containment." if approval_required else " Containment in progress."
        msg = f"CRITICAL security alert. Possible attack chain detected{entity_str}. Risk score {risk_score}.{approval_part}"
    elif severity == "HIGH":
        msg = f"HIGH security alert. {threat_type} detected{entity_str}. Risk score {risk_score}. Review recommended."
    elif severity == "MODERATE":
        msg = f"MODERATE security alert. {threat_type} detected{entity_str}. Risk score {risk_score}."
    else:
        msg = f"LOW security notice. Routine activity{entity_str}."

    return sanitize_for_voice(msg)


def format_alert_message(
    severity: str,
    risk_score: int,
    threat_type: str,
    affected_entity: Optional[str] = None,
    recommended_action: Optional[str] = None,
    approval_required: bool = False,
) -> str:
    """Generates detailed, deterministic alert display message."""
    entity_part = f" affecting '{affected_entity}'" if affected_entity and affected_entity != "system" else ""
    appr_part = " Containment requires human approval." if approval_required else ""
    rec_part = f" Recommended: {recommended_action}." if recommended_action else ""
    return f"{severity} security alert: {threat_type} detected{entity_part}. Risk score {risk_score}/100.{appr_part}{rec_part}"


class AlertService:
    """Alert Engine responsible for evaluating risk assessments,
    generating structured security alerts, mapping recommended actions,
    recording simulated containment actions, and persisting via Supabase.
    """

    SIMULATED_ACTIONS = {
        "LOW": "Simulated Action: Standard passive monitoring.",
        "MODERATE": "Simulated Action: Increased monitoring window and elevated telemetry logging.",
        "HIGH": "Simulated Action: Require verification and restrict sensitive endpoint access.",
        "CRITICAL": "Simulated Action: Human approval required / suspend and isolate affected action.",
    }

    def __init__(
        self,
        repo: Optional[SupabaseRepository] = None,
        response_svc: Optional[Any] = None,
        correlation_svc: Optional[Any] = None,
    ):
        self.repo = repo
        self.response_svc = response_svc
        self.correlation_svc = correlation_svc
        self._memory_alerts: Dict[str, SecurityAlert] = {}

    def _sync_alert_with_incident(self, alert: SecurityAlert) -> SecurityAlert:
        """Synchronizes alert status, risk level, risk score, and title with its authoritative incident."""
        if not alert.incident_id:
            return alert

        inc = None
        if self.correlation_svc:
            inc = self.correlation_svc.get_incident(alert.incident_id)

        if inc:
            inc_status = (inc.status or "active").lower()
            inc_score = None
            if inc.risk_assessment and inc.risk_assessment.risk_score is not None:
                inc_score = inc.risk_assessment.risk_score
            elif hasattr(inc, "risk_score") and inc.risk_score is not None:
                inc_score = inc.risk_score

            if inc_status in ["resolved", "recovered"] or inc_score == 0:
                alert.status = "resolved"
                alert.risk_score = 0
                alert.risk_level = "RESOLVED"
                alert.approval_state = "RESOLVED"
                alert.response_state = "RESTORED"
                alert.acknowledged = True
                alert.title = f"Security Alert: Resolved - {alert.primary_entity or 'Entity'}"
                alert.message = f"Resolved security incident: {alert.threat_type} affecting '{alert.primary_entity}'. Risk score 0/100 [RESOLVED]."
            elif inc_status == "contained" or (inc_score is not None and inc_score <= 25 and inc_status != "active"):
                alert.status = "contained"
                alert.risk_score = inc_score if inc_score is not None else 15
                alert.risk_level = "LOW"
                alert.approval_state = "APPROVED"
                alert.response_state = "CONTAINMENT_ACTIVE"
                alert.acknowledged = True
                alert.title = f"Security Alert: Contained - Low ({alert.primary_entity or 'Entity'})"
                alert.message = f"Contained security incident: {alert.threat_type} affecting '{alert.primary_entity}'. Risk score {alert.risk_score}/100 [CONTAINMENT ACTIVE]."
            elif inc_status == "acknowledged":
                alert.acknowledged = True
                alert.status = "acknowledged"

            self._memory_alerts[alert.alert_id] = alert
        return alert

    def should_generate_alert(self, risk_assessment: RiskAssessment) -> bool:
        """Determines if the assessed risk warrants creating a security alert."""
        return (
            risk_assessment.risk_level in [RiskLevel.MODERATE, RiskLevel.HIGH, RiskLevel.CRITICAL]
            or risk_assessment.risk_score >= 30
        )

    async def create_alert(
        self,
        incident_id: str,
        risk_assessment: RiskAssessment,
        event_id: Optional[str] = None,
        primary_entity: Optional[str] = None,
        threat_type: Optional[str] = None,
        approval_required: bool = False,
        approval_state: Optional[str] = None,
        response_state: Optional[str] = None,
        recommended_actions: Optional[List[str]] = None,
    ) -> SecurityAlert:
        """Creates or escalates a structured security alert, preventing duplicate audio spam
        while ensuring severity escalation triggers new voice alerts and audit events.
        """
        level_str = (
            risk_assessment.risk_level.value
            if hasattr(risk_assessment.risk_level, "value")
            else str(risk_assessment.risk_level)
        )
        simulated_action = self.SIMULATED_ACTIONS.get(
            level_str,
            "Simulated Action: Standard monitoring."
        )

        resolved_threat_type = threat_type or derive_threat_type(
            signals=risk_assessment.correlated_signals,
            reasons=risk_assessment.reasons,
        )

        is_voice_req = level_str in ["HIGH", "CRITICAL"]
        resolved_actions = recommended_actions or (
            [risk_assessment.recommended_action] if risk_assessment.recommended_action else []
        )

        voice_msg = format_voice_message(
            severity=level_str,
            risk_score=risk_assessment.risk_score,
            threat_type=resolved_threat_type,
            affected_entity=primary_entity,
            approval_required=approval_required,
        )

        display_msg = format_alert_message(
            severity=level_str,
            risk_score=risk_assessment.risk_score,
            threat_type=resolved_threat_type,
            affected_entity=primary_entity,
            recommended_action=risk_assessment.recommended_action,
            approval_required=approval_required,
        )

        # -------------------------------------------------------------
        # DUPLICATE ALERT PREVENTION & SEVERITY ESCALATION LOGIC
        # -------------------------------------------------------------
        existing_alert = next(
            (a for a in self._memory_alerts.values() if a.incident_id == incident_id and a.status != "resolved"),
            None
        )

        if existing_alert:
            old_rank = SEVERITY_RANKS.get(existing_alert.risk_level.upper(), 1)
            new_rank = SEVERITY_RANKS.get(level_str.upper(), 1)

            if new_rank > old_rank:
                # Severity Escalation: e.g. MODERATE -> HIGH or HIGH -> CRITICAL
                old_level = existing_alert.risk_level
                existing_alert.risk_level = level_str
                existing_alert.risk_score = risk_assessment.risk_score
                existing_alert.threat_type = resolved_threat_type
                existing_alert.title = f"Security Alert: {level_str} Risk Detected ({primary_entity or 'Entity'})"
                existing_alert.description = (
                    f"Incident '{incident_id}' escalated from {old_level} to {level_str} severity "
                    f"(score {risk_assessment.risk_score}/100)."
                )
                existing_alert.message = display_msg
                existing_alert.voice_message = voice_msg
                existing_alert.voice_alert_required = is_voice_req
                existing_alert.voice_played = False
                existing_alert.status = "escalated"
                existing_alert.reasons = risk_assessment.reasons
                existing_alert.recommended_action = risk_assessment.recommended_action
                existing_alert.approval_required = approval_required
                existing_alert.approval_state = approval_state or existing_alert.approval_state
                existing_alert.response_state = response_state or existing_alert.response_state
                existing_alert.simulated_action_taken = simulated_action
                existing_alert.timestamp = datetime.now(timezone.utc)

                if self.repo:
                    try:
                        await self.repo.save_alert(existing_alert)
                    except Exception as e:
                        logger.error(f"Failed to persist escalated alert: {e}")

                if self.response_svc:
                    self.response_svc._record_audit_entry(
                        incident_id=incident_id,
                        action="SEVERITY_ESCALATED",
                        target=existing_alert.alert_id,
                        target_type="alert",
                        risk_score=risk_assessment.risk_score,
                        severity=level_str,
                        reason=f"Alert escalated from {old_level} to {level_str} (score {risk_assessment.risk_score}/100).",
                        status="ESCALATED",
                        actor="AlertEngine",
                        details={
                            "old_severity": old_level,
                            "new_severity": level_str,
                            "alert_id": existing_alert.alert_id,
                            "voice_alert_required": is_voice_req,
                        },
                    )

                return existing_alert

            else:
                # Same or lower severity: update metrics without duplicate voice alert or resetting acknowledgement
                existing_alert.risk_score = max(existing_alert.risk_score, risk_assessment.risk_score)
                existing_alert.reasons = risk_assessment.reasons
                existing_alert.message = display_msg
                existing_alert.approval_required = approval_required
                if approval_state:
                    existing_alert.approval_state = approval_state
                if response_state:
                    existing_alert.response_state = response_state
                return existing_alert

        # -------------------------------------------------------------
        # NEW ALERT CREATION
        # -------------------------------------------------------------
        alert = SecurityAlert(
            incident_id=incident_id,
            event_id=event_id,
            title=f"Security Alert: {level_str} Risk Detected ({primary_entity or 'Entity'})",
            description=(
                f"Incident '{incident_id}' flagged with {level_str} severity "
                f"(score {risk_assessment.risk_score}/100)."
            ),
            risk_level=level_str,
            risk_score=risk_assessment.risk_score,
            reasons=risk_assessment.reasons,
            recommended_action=risk_assessment.recommended_action,
            timestamp=datetime.now(timezone.utc),
            status="escalated" if level_str in ["HIGH", "CRITICAL"] else "active",
            simulated_action_taken=simulated_action,
            threat_type=resolved_threat_type,
            message=display_msg,
            voice_message=voice_msg,
            voice_alert_required=is_voice_req,
            voice_played=False,
            acknowledged=False,
            approval_required=approval_required,
            approval_state=approval_state,
            response_state=response_state,
            recommended_actions=resolved_actions,
            affected_entity=primary_entity,
            metadata={
                "confidence": risk_assessment.confidence,
                "correlated_signals": risk_assessment.correlated_signals,
            },
        )

        # Store in local service memory
        self._memory_alerts[alert.alert_id] = alert

        # Persist through repository
        if self.repo:
            try:
                await self.repo.save_alert(alert)
            except Exception as e:
                logger.error(f"Failed to persist alert {alert.alert_id} to repository: {e}")

        # Record audit trail entry for alert creation
        if self.response_svc:
            self.response_svc._record_audit_entry(
                incident_id=incident_id,
                action="ALERT_CREATED",
                target=alert.alert_id,
                target_type="alert",
                risk_score=risk_assessment.risk_score,
                severity=level_str,
                reason=f"Security alert created: {level_str} risk detected ({resolved_threat_type}).",
                status="ACTIVE",
                actor="AlertEngine",
                details={
                    "alert_id": alert.alert_id,
                    "threat_type": resolved_threat_type,
                    "voice_alert_required": is_voice_req,
                    "approval_required": approval_required,
                },
            )

        return alert

    async def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Fetches an alert by ID."""
        if alert_id in self._memory_alerts:
            return self._memory_alerts[alert_id]
        if self.repo:
            alert = await self.repo.get_alert(alert_id)
            if alert:
                self._memory_alerts[alert.alert_id] = alert
                return alert
        return None

    async def list_alerts(
        self,
        limit: int = 50,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        acknowledged: Optional[bool] = None,
    ) -> List[SecurityAlert]:
        """Lists alerts with optional risk_level, status, and acknowledgement filtering."""
        # Synchronize memory alerts with current incident state
        for a in list(self._memory_alerts.values()):
            self._sync_alert_with_incident(a)

        results = list(self._memory_alerts.values())
        if self.repo:
            repo_alerts = await self.repo.list_alerts(limit=limit, risk_level=risk_level, status=status)
            if repo_alerts:
                # Merge into memory alerts prioritizing memory state
                for ra in repo_alerts:
                    if ra.alert_id not in self._memory_alerts:
                        self._sync_alert_with_incident(ra)
                        self._memory_alerts[ra.alert_id] = ra
                results = list(self._memory_alerts.values())

        if risk_level:
            results = [a for a in results if a.risk_level.upper() == risk_level.upper()]
        if status:
            results = [a for a in results if a.status.lower() == status.lower()]
        if acknowledged is not None:
            results = [a for a in results if a.acknowledged == acknowledged]

        # Sort by timestamp descending
        results.sort(key=lambda a: a.timestamp, reverse=True)
        return results[:limit]

    async def update_alert_status(self, alert_id: str, new_status: str) -> Optional[SecurityAlert]:
        """Updates the status of an alert (e.g. acknowledged, resolved)."""
        alert = await self.get_alert(alert_id)
        if alert:
            alert.status = new_status
            if new_status == "acknowledged":
                alert.acknowledged = True
                alert.acknowledged_at = datetime.now(timezone.utc)
            elif new_status == "resolved":
                alert.acknowledged = True
                alert.acknowledged_at = datetime.now(timezone.utc)
                alert.risk_score = 0
                alert.risk_level = "RESOLVED"
                alert.approval_state = "RESOLVED"
                alert.response_state = "RESTORED"
            self._memory_alerts[alert.alert_id] = alert
            if self.repo:
                await self.repo.save_alert(alert)
            return alert
        return None

    async def acknowledge_alert(
        self,
        alert_id: str,
        actor: str = "SOC_Analyst",
        notes: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        """Acknowledges an alert.
        IMPORTANT: Acknowledging an alert indicates operator review and stops voice alert loops,
        but does NOT resolve or suppress the underlying security incident.
        """
        alert = await self.get_alert(alert_id)
        if not alert:
            return None

        alert.acknowledged = True
        alert.status = "acknowledged"
        alert.acknowledged_by = actor
        alert.acknowledged_at = datetime.now(timezone.utc)
        self._memory_alerts[alert.alert_id] = alert

        if self.repo:
            try:
                await self.repo.save_alert(alert)
            except Exception as e:
                logger.error(f"Failed to persist acknowledged alert: {e}")

        # Record audit trail entry
        if self.response_svc:
            self.response_svc._record_audit_entry(
                incident_id=alert.incident_id,
                action="ALERT_ACKNOWLEDGED",
                target=alert.alert_id,
                target_type="alert",
                risk_score=alert.risk_score,
                severity=alert.risk_level,
                reason=f"Operator '{actor}' acknowledged {alert.risk_level} security alert.",
                status="ACKNOWLEDGED",
                actor=actor,
                details={
                    "alert_id": alert.alert_id,
                    "notes": notes,
                    "incident_id": alert.incident_id,
                    "preserves_incident": True,
                },
            )

        return alert

    async def replay_alert(
        self,
        alert_id: str,
        actor: str = "SOC_Analyst",
    ) -> Optional[SecurityAlert]:
        """Marks alert as replayed and records audit event for manual voice replay."""
        alert = await self.get_alert(alert_id)
        if not alert:
            return None

        alert.voice_played = True
        self._memory_alerts[alert.alert_id] = alert

        if self.response_svc:
            self.response_svc._record_audit_entry(
                incident_id=alert.incident_id,
                action="ALERT_REPLAYED",
                target=alert.alert_id,
                target_type="alert",
                risk_score=alert.risk_score,
                severity=alert.risk_level,
                reason=f"Operator '{actor}' requested voice alert replay for {alert.risk_level} incident.",
                status="REPLAYED",
                actor=actor,
                details={
                    "alert_id": alert.alert_id,
                    "voice_message": alert.voice_message,
                },
            )

        return alert

    async def get_active_critical_alert(self) -> Optional[SecurityAlert]:
        """Finds the most recent unacknowledged CRITICAL alert whose associated incident is currently active and requires critical operator attention.
        Must NOT return alerts for resolved, contained, mitigated, or recovered incidents, or alerts with risk score <= 25.
        """
        # Synchronize memory alerts with current incident state
        for a in list(self._memory_alerts.values()):
            self._sync_alert_with_incident(a)

        active_critical = []
        for a in self._memory_alerts.values():
            if a.status in ["resolved", "contained", "mitigated", "recovered"]:
                continue
            if a.approval_state in ["APPROVED", "RESOLVED"]:
                continue
            if a.acknowledged:
                continue
            if a.risk_score is not None and a.risk_score <= 25:
                continue
            if (a.risk_level or "").upper() != "CRITICAL" and (a.risk_score or 0) < 80:
                continue

            # Verify associated incident state if linked
            if a.incident_id and self.correlation_svc:
                inc = self.correlation_svc.get_incident(a.incident_id)
                if inc:
                    if inc.status in ["resolved", "contained", "mitigated", "recovered"]:
                        continue
                    if inc.risk_assessment and inc.risk_assessment.risk_score <= 25:
                        continue

            active_critical.append(a)

        if active_critical:
            active_critical.sort(key=lambda a: a.timestamp, reverse=True)
            return active_critical[0]
        return None

    async def resolve_alerts_for_incident(
        self,
        incident_id: str,
        new_status: str = "contained",
        risk_score: int = 15,
        risk_level: str = "LOW",
        approval_state: str = "APPROVED",
        response_state: str = "CONTAINMENT_ACTIVE",
    ) -> List[SecurityAlert]:
        """Resolves or contains all alerts strictly associated with an incident when containment or recovery is completed."""
        if not incident_id:
            return []
        updated = []
        for alert in list(self._memory_alerts.values()):
            if alert.incident_id and alert.incident_id == incident_id:
                alert.status = new_status
                alert.risk_score = risk_score
                alert.risk_level = risk_level
                alert.approval_state = approval_state
                alert.response_state = response_state
                if new_status in ["contained", "resolved"]:
                    alert.acknowledged = True
                    alert.acknowledged_at = datetime.now(timezone.utc)
                entity_name = getattr(alert, "affected_entity", None) or getattr(alert, "primary_entity", None) or "Entity"
                threat = alert.threat_type or "Threat"
                if new_status == "contained":
                    alert.title = f"Security Alert: Contained - Low ({entity_name})"
                    alert.message = f"Contained security incident: {threat} affecting '{entity_name}'. Risk score {risk_score}/100 [CONTAINMENT ACTIVE]."
                elif new_status == "resolved":
                    alert.title = f"Security Alert: Resolved - {entity_name}"
                    alert.message = f"Resolved security incident: {threat} affecting '{entity_name}'. Risk score 0/100 [RESOLVED]."
                self._memory_alerts[alert.alert_id] = alert
                if self.repo:
                    try:
                        await self.repo.save_alert(alert)
                    except Exception as e:
                        logger.error(f"Failed to persist alert status update: {e}")
                updated.append(alert)
        return updated

    async def resolve_single_alert(
        self,
        alert_id: str,
        reason: str = "Resolved by SOC Operator",
        actor: str = "SOC_Analyst",
    ) -> Optional[SecurityAlert]:
        """Resolves a single security alert without auto-resolving unrelated alerts."""
        alert = await self.get_alert(alert_id)
        if not alert:
            return None

        alert.status = "resolved"
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = actor
        alert.risk_score = 0
        alert.risk_level = "RESOLVED"
        alert.approval_state = "RESOLVED"
        alert.response_state = "RESTORED"
        self._memory_alerts[alert.alert_id] = alert

        if self.repo:
            try:
                await self.repo.save_alert(alert)
            except Exception as e:
                logger.error(f"Failed to persist resolved alert {alert_id}: {e}")

        # If this alert is linked to an incident, check if other active alerts exist for it
        if alert.incident_id and self.response_svc:
            other_active_alerts = [
                a for a in self._memory_alerts.values()
                if a.incident_id == alert.incident_id and a.alert_id != alert.alert_id and a.status != "resolved"
            ]
            if not other_active_alerts:
                try:
                    self.response_svc.recover_false_positive(
                        incident_id=alert.incident_id,
                        reason=reason,
                        actor=actor,
                    )
                except Exception as e:
                    logger.debug(f"Incident recovery notice: {e}")

            self.response_svc._record_audit_entry(
                incident_id=alert.incident_id,
                action="ALERT_RESOLVED",
                target=alert.alert_id,
                target_type="alert",
                risk_score=0,
                severity="RESOLVED",
                reason=f"Operator '{actor}' resolved alert {alert.alert_id}: {reason}.",
                status="RESOLVED",
                actor=actor,
                details={
                    "alert_id": alert.alert_id,
                    "resolution_reason": reason,
                    "incident_id": alert.incident_id,
                },
            )

        return alert

    async def resolve_alerts_for_user(
        self,
        user_id: str,
        new_status: str = "resolved",
        risk_score: int = 0,
        risk_level: str = "RESOLVED",
        approval_state: str = "APPROVED",
        response_state: str = "RESTORED",
        actor: str = "SOC_Analyst",
        reason: str = "User threats cleared and synchronized by analyst",
    ) -> List[SecurityAlert]:
        """Resolves or contains all security alerts across the system for a specific user upon approval/update."""
        if not user_id:
            return []
        uid_clean = str(user_id).strip().lower()
        updated = []
        for alert in list(self._memory_alerts.values()):
            matches = False
            for attr in ["primary_entity", "affected_entity", "user_id"]:
                val = getattr(alert, attr, None)
                if val and str(val).strip().lower() == uid_clean:
                    matches = True
                    break
            if not matches:
                # Check alert message or title for employee name or code
                msg = (alert.message or "") + " " + (alert.title or "")
                if uid_clean in msg.lower():
                    matches = True

            if matches:
                alert.status = new_status
                alert.acknowledged = True
                alert.acknowledged_at = datetime.now(timezone.utc)
                alert.acknowledged_by = actor
                alert.risk_score = risk_score
                alert.risk_level = risk_level
                alert.approval_state = approval_state
                alert.response_state = response_state
                entity_name = getattr(alert, "affected_entity", None) or getattr(alert, "primary_entity", None) or user_id
                threat = alert.threat_type or "Threat"
                if new_status == "contained":
                    alert.title = f"Security Alert: Contained - Low ({entity_name})"
                    alert.message = f"Contained security incident: {threat} affecting '{entity_name}'. Risk score {risk_score}/100 [CONTAINMENT ACTIVE]."
                elif new_status == "resolved":
                    alert.title = f"Security Alert: Resolved - {entity_name}"
                    alert.message = f"Resolved security incident: {threat} affecting '{entity_name}'. Risk score 0/100 [RESOLVED]."

                self._memory_alerts[alert.alert_id] = alert
                if self.repo:
                    try:
                        await self.repo.save_alert(alert)
                    except Exception as e:
                        logger.error(f"Failed to persist alert {alert.alert_id}: {e}")
                updated.append(alert)

        return updated


