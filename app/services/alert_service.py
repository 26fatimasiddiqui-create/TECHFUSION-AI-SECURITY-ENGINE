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

    def __init__(self, repo: Optional[SupabaseRepository] = None, response_svc: Optional[Any] = None):
        self.repo = repo
        self.response_svc = response_svc
        self._memory_alerts: Dict[str, SecurityAlert] = {}

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
        results = list(self._memory_alerts.values())
        if self.repo:
            repo_alerts = await self.repo.list_alerts(limit=limit, risk_level=risk_level, status=status)
            if repo_alerts:
                # Merge into memory alerts prioritizing memory state
                for ra in repo_alerts:
                    if ra.alert_id not in self._memory_alerts:
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
        """Finds the most recent unacknowledged CRITICAL alert for prominent banner display."""
        critical_alerts = [
            a for a in self._memory_alerts.values()
            if a.risk_level == "CRITICAL" and not a.acknowledged and a.status != "resolved"
        ]
        if not critical_alerts:
            # Fall back to any active critical alert
            critical_alerts = [
                a for a in self._memory_alerts.values()
                if a.risk_level == "CRITICAL" and a.status != "resolved"
            ]
        if critical_alerts:
            critical_alerts.sort(key=lambda a: a.timestamp, reverse=True)
            return critical_alerts[0]
        return None

