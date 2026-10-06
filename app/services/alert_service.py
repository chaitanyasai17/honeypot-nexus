"""
Honeypot Nexus - Alert Generation & Lifecycle Service
Creates actionable security alerts with intelligent cooldown and deduplication.
"""

from typing import List
from datetime import datetime, timezone, timedelta
from app.models.models import Alert, HoneypotEventModel, AttackerSession, utc_now, gen_uuid
from app.detection.base import Detection
from app.detection.scoring import score_to_band
from app.services.config_service import get_config_value
from app.extensions import db


def evaluate_and_create_alerts(
    event: HoneypotEventModel,
    session: AttackerSession,
    detections: List[Detection]
) -> List[Alert]:
    """Evaluates event and session state to create or coalesce security alerts."""
    raised_alerts = []
    cooldown_s = get_config_value("ALERT_COOLDOWN_S", 120)
    cooldown_cutoff = utc_now() - timedelta(seconds=cooldown_s)

    # 1. Check for HIGH / CRITICAL rule detections or Brute Force
    high_detections = [
        d for d in detections
        if (getattr(d.severity, "value", str(d.severity)) in ("HIGH", "CRITICAL")
            or d.rule_id == "R-BF-001")
    ]

    for det in high_detections:
        atype = det.attack_type.value if hasattr(det.attack_type, "value") else str(det.attack_type)
        sev = det.severity.value if hasattr(det.severity, "value") else str(det.severity)
        dedupe_key = f"{session.id}:{atype}:{sev}"

        # Cooldown check for existing open alert
        existing = Alert.query.filter(
            Alert.dedupe_key == dedupe_key,
            Alert.status.in_(["NEW", "ACKNOWLEDGED"]),
            Alert.last_occurrence_at >= cooldown_cutoff
        ).first()

        if existing:
            existing.occurrences += 1
            existing.last_occurrence_at = utc_now()
            existing.risk_score = max(existing.risk_score, event.risk_score)
            reasons = list(existing.reasons_json or [])
            if det.reason not in reasons:
                reasons.append(det.reason)
            existing.reasons_json = reasons
            raised_alerts.append(existing)
        else:
            title = f"{atype.replace('_', ' ').title()} Activity from {event.source_ip}"
            alert = Alert(
                alert_id=gen_uuid(),
                timestamp=utc_now(),
                severity=sev,
                title=title,
                description=f"Automated detection triggered by {det.rule_id}: {det.reason}",
                source_ip=event.source_ip,
                session_id=session.id,
                event_id=event.event_id,
                attack_type=atype,
                risk_score=event.risk_score,
                status="NEW",
                dedupe_key=dedupe_key,
                occurrences=1,
                reasons_json=[det.reason],
                last_occurrence_at=utc_now()
            )
            db.session.add(alert)
            raised_alerts.append(alert)

    # 2. Check for Session Severity Escalation
    session_band = score_to_band(session.risk_score)
    if session_band in ("HIGH", "CRITICAL") and detections:
        escalation_key = f"{session.id}:ESCALATION:{session_band}"
        existing_esc = Alert.query.filter(
            Alert.dedupe_key == escalation_key,
            Alert.status.in_(["NEW", "ACKNOWLEDGED"])
        ).first()

        if not existing_esc:
            esc_alert = Alert(
                alert_id=gen_uuid(),
                timestamp=utc_now(),
                severity=session_band,
                title=f"Attacker Session Escalated to {session_band}",
                description=f"Cumulative session risk reached {session.risk_score}/100 from {event.source_ip}",
                source_ip=event.source_ip,
                session_id=session.id,
                event_id=event.event_id,
                attack_type=event.attack_type,
                risk_score=session.risk_score,
                status="NEW",
                dedupe_key=escalation_key,
                occurrences=1,
                reasons_json=[f"Session escalated into {session_band} threat band"],
                last_occurrence_at=utc_now()
            )
            db.session.add(esc_alert)
            raised_alerts.append(esc_alert)

    return raised_alerts
