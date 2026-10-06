"""
Honeypot Nexus - Statistics & Aggregations Service
Computes real-time KPIs, Threat Pulse, distribution charts, and timeline telemetry.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
import sqlalchemy as sa
from app.models.models import (
    HoneypotEventModel,
    AttackerSession,
    AttackerProfile,
    Alert,
    utc_now
)
from app.detection.scoring import score_to_band
from app.extensions import db

START_TIME = utc_now()


def get_kpis() -> Dict[str, Any]:
    """Calculates the 6 main SOC KPIs."""
    now = utc_now()
    active_cutoff = now - timedelta(minutes=15)

    total_events = HoneypotEventModel.query.count()
    active_attackers = AttackerProfile.query.filter(AttackerProfile.last_seen >= active_cutoff).count()
    active_sessions = AttackerSession.query.filter(AttackerSession.status == "active").count()

    high_crit_alerts = Alert.query.filter(
        Alert.severity.in_(["HIGH", "CRITICAL"]),
        Alert.status.in_(["NEW", "ACKNOWLEDGED"])
    ).count()

    # Average risk of active sessions
    avg_risk_query = db.session.query(sa.func.avg(AttackerSession.risk_score)).filter(
        AttackerSession.status == "active"
    ).scalar()
    avg_risk = round(float(avg_risk_query or 0.0), 1)

    uptime_s = int((now - START_TIME).total_seconds())

    return {
        "total_events": total_events,
        "active_attackers": active_attackers,
        "active_sessions": active_sessions,
        "high_critical_alerts": high_crit_alerts,
        "avg_risk": avg_risk,
        "uptime_seconds": uptime_s
    }


def get_threat_pulse() -> Dict[str, Any]:
    """Calculates global Threat Pulse score (0-100) and severity band."""
    now = utc_now()
    window_cutoff = now - timedelta(minutes=15)

    # Highest session risk in window
    recent_sessions = AttackerSession.query.filter(AttackerSession.last_seen >= window_cutoff).all()

    if not recent_sessions:
        return {
            "score": 0,
            "level": "NORMAL",
            "reasons": ["No active threat sessions within rolling 15m window"]
        }

    max_session_risk = max((s.risk_score for s in recent_sessions), default=0)
    high_threat_sources = sum(1 for s in recent_sessions if s.risk_score >= 50)

    # Multi-attacker threat elevation bonus
    bonus = min(20, (high_threat_sources - 1) * 10) if high_threat_sources > 1 else 0
    pulse_score = min(100, max_session_risk + bonus)
    level = score_to_band(pulse_score)

    reasons = [f"Peak active session risk: {max_session_risk}/100"]
    if high_threat_sources > 1:
        reasons.append(f"{high_threat_sources} distinct sources exhibiting High/Critical risk")

    return {
        "score": pulse_score,
        "level": level,
        "reasons": reasons
    }


def get_attack_distribution() -> Dict[str, int]:
    """Returns count breakdown by attack type."""
    rows = db.session.query(
        HoneypotEventModel.attack_type,
        sa.func.count(HoneypotEventModel.event_id)
    ).filter(HoneypotEventModel.attack_type != "NONE").group_by(HoneypotEventModel.attack_type).all()

    return {row[0]: row[1] for row in rows}


def get_attack_timeline(minutes: int = 60) -> List[Dict[str, Any]]:
    """Aggregates telemetry into 1-minute buckets for timeline chart."""
    now = utc_now()
    cutoff = now - timedelta(minutes=minutes)

    events = HoneypotEventModel.query.filter(HoneypotEventModel.timestamp >= cutoff).order_by(HoneypotEventModel.timestamp.asc()).all()

    buckets: Dict[str, dict] = {}
    for ev in events:
        minute_str = ev.timestamp.strftime("%H:%M")
        if minute_str not in buckets:
            buckets[minute_str] = {
                "t": minute_str,
                "count": 0,
                "NORMAL": 0,
                "ELEVATED": 0,
                "HIGH": 0,
                "CRITICAL": 0
            }
        buckets[minute_str]["count"] += 1
        sev = ev.severity or "NORMAL"
        if sev in buckets[minute_str]:
            buckets[minute_str][sev] += 1

    return list(buckets.values())


def get_top_attackers(limit: int = 5) -> List[Dict[str, Any]]:
    """Returns top threat sources by maximum risk and event volume."""
    profiles = AttackerProfile.query.order_by(
        AttackerProfile.max_risk.desc(),
        AttackerProfile.total_events.desc()
    ).limit(limit).all()

    res = []
    for p in profiles:
        geo = p.geo_record
        res.append({
            "ip": p.source_ip,
            "max_risk": p.max_risk,
            "total_events": p.total_events,
            "top_attack": p.top_attack_type,
            "country": geo.country if geo else "Unknown",
            "city": geo.city if geo else "Unknown",
            "vpn": p.vpn_detected,
            "tor": p.tor_detected
        })
    return res
