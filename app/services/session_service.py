"""
Honeypot Nexus - Session Correlation Service
Correlates incoming honeypot events to attacker sessions and profiles.
"""

from typing import Tuple, Dict, Any
from app.models.models import AttackerSession, AttackerProfile, GeoIPRecord, utc_now
from app.extensions import db


def correlate_attacker_session(
    session_id: str,
    source_ip: str,
    endpoint: str,
    surface: str,
    geo_info: Dict[str, Any]
) -> Tuple[AttackerSession, AttackerProfile]:
    """Finds or creates attacker profile and attacker session."""
    # 1. Attacker Profile lookup or creation
    profile = AttackerProfile.query.filter_by(source_ip=source_ip).first()
    if not profile:
        geo_rec = GeoIPRecord.query.filter_by(ip=source_ip).first()
        profile = AttackerProfile(
            source_ip=source_ip,
            geo_id=geo_rec.id if geo_rec else None,
            first_seen=utc_now(),
            last_seen=utc_now(),
            total_sessions=1,
            total_events=0,
            avg_risk=0.0,
            max_risk=0,
            engagement_score=0,
            top_attack_type="NONE",
            vpn_detected=geo_info.get("vpn", False),
            tor_detected=geo_info.get("tor", False)
        )
        db.session.add(profile)
        db.session.flush()

    # 2. Attacker Session lookup or creation
    session = AttackerSession.query.filter_by(id=session_id).first()
    if not session:
        session = AttackerSession(
            id=session_id,
            profile_id=profile.id,
            source_ip=source_ip,
            first_seen=utc_now(),
            last_seen=utc_now(),
            event_count=0,
            risk_score=0,
            engagement_score=0,
            status="active",
            attack_types_json={},
            endpoints_json=[endpoint],
            surfaces_json=[surface],
            score_breakdown_json={}
        )
        db.session.add(session)
        db.session.flush()
        # Increment profile session count if existing profile got a new session
        if profile.total_events > 0:
            profile.total_sessions += 1
    else:
        # Update existing session endpoint and surface lists
        eps = list(session.endpoints_json or [])
        if endpoint not in eps and len(eps) < 200:
            eps.append(endpoint)
            session.endpoints_json = eps

        surfs = list(session.surfaces_json or [])
        if surface not in surfs:
            surfs.append(surface)
            session.surfaces_json = surfs

        if session.status != "active":
            session.status = "active"

    return session, profile
