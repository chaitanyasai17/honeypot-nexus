"""
Honeypot Nexus - Dashboard REST API Endpoints
Implements the complete REST specification with role authorization and JSON error envelopes.
"""

from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify, request, Response
from app.models.models import (
    HoneypotEventModel,
    AttackerSession,
    AttackerProfile,
    Alert,
    AuditLog,
    utc_now
)
from app.auth.security import login_required, role_required
from app.services.stats_service import (
    get_kpis,
    get_threat_pulse,
    get_attack_distribution,
    get_attack_timeline,
    get_top_attackers
)
from app.services.health_service import sample_system_health
from app.services.demo_service import run_scenario_async, purge_synthetic_data
from app.services.report_service import generate_events_csv, generate_attackers_csv, generate_pdf_report
from app.services.config_service import set_config_value, get_config_value
from app.services.audit_service import audit_log
from app.detection.engine import get_detection_engine
from app.extensions import db, limiter
from app.errors import ApiError

api_soc_bp = Blueprint("soc_api", __name__, url_prefix="/api")


# 1. Summary
@api_soc_bp.route("/dashboard/summary")
@login_required
def dashboard_summary():
    since = request.args.get("since", "24h")
    kpis = get_kpis()
    threat = get_threat_pulse()
    dist = get_attack_distribution()
    timeline = get_attack_timeline()
    top_attackers = get_top_attackers()
    health = sample_system_health()

    return jsonify({
        "kpis": kpis,
        "threat": threat,
        "distribution": dist,
        "timeline": timeline,
        "top_attackers": top_attackers,
        "health": health
    })


# 2. Events List & Details
@api_soc_bp.route("/events")
@login_required
def list_events():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(1, int(request.args.get("per_page", 50))))

    query = HoneypotEventModel.query

    # Filters
    if request.args.get("source_ip"):
        query = query.filter(HoneypotEventModel.source_ip.like(f"%{request.args.get('source_ip')}%"))
    if request.args.get("session_id"):
        query = query.filter_by(session_id=request.args.get("session_id"))
    if request.args.get("attack_type"):
        query = query.filter_by(attack_type=request.args.get("attack_type"))
    if request.args.get("severity"):
        query = query.filter_by(severity=request.args.get("severity"))
    if request.args.get("surface"):
        query = query.filter_by(surface=request.args.get("surface"))
    if request.args.get("min_risk"):
        query = query.filter(HoneypotEventModel.risk_score >= int(request.args.get("min_risk")))

    total = query.count()
    events = query.order_by(HoneypotEventModel.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    data = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "source_ip": e.source_ip,
            "endpoint": e.endpoint,
            "http_method": e.http_method,
            "surface": e.surface,
            "event_type": e.event_type,
            "attack_type": e.attack_type,
            "severity": e.severity,
            "risk_score": e.risk_score,
            "session_id": e.session_id,
            "geo_country": e.geo_country,
            "geo_city": e.geo_city,
            "vpn_detected": e.vpn_detected,
            "tor_detected": e.tor_detected,
            "payload_preview": (e.payload or "")[:80]
        }
        for e in events
    ]

    return jsonify({
        "data": data,
        "meta": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page
        }
    })


@api_soc_bp.route("/events/<event_id>")
@login_required
def get_event(event_id):
    ev = HoneypotEventModel.query.get(event_id)
    if not ev:
        raise ApiError("not_found", "Event not found", 404)

    detections = [
        {
            "rule_id": d.rule_id,
            "attack_type": d.attack_type,
            "severity": d.severity,
            "points": d.points,
            "reason": d.reason,
            "evidence": d.evidence_json
        }
        for d in ev.detections
    ]

    session_summary = {
        "session_id": ev.session.id,
        "event_count": ev.session.event_count,
        "risk_score": ev.session.risk_score,
        "engagement_score": ev.session.engagement_score,
        "status": ev.session.status
    } if ev.session else None

    return jsonify({
        "event_id": ev.event_id,
        "timestamp": ev.timestamp.isoformat(),
        "source_ip": ev.source_ip,
        "source_port": ev.source_port,
        "destination": ev.destination,
        "endpoint": ev.endpoint,
        "query_string": ev.query_string,
        "http_method": ev.http_method,
        "user_agent": ev.user_agent,
        "surface": ev.surface,
        "event_type": ev.event_type,
        "attack_type": ev.attack_type,
        "severity": ev.severity,
        "risk_score": ev.risk_score,
        "engagement_score": ev.engagement_score,
        "payload": ev.payload,
        "http_status": ev.http_status,
        "status": ev.status,
        "geo": {
            "country": ev.geo_country,
            "city": ev.geo_city,
            "asn": ev.asn,
            "isp": ev.isp,
            "vpn": ev.vpn_detected,
            "tor": ev.tor_detected,
            "source": ev.geo_source
        },
        "detections": detections,
        "session_summary": session_summary,
        "meta": ev.meta_json
    })


# 3. Alerts
@api_soc_bp.route("/alerts")
@login_required
def list_alerts():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 50))))

    query = Alert.query
    if request.args.get("status"):
        query = query.filter_by(status=request.args.get("status"))
    if request.args.get("severity"):
        query = query.filter_by(severity=request.args.get("severity"))

    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    counts = {
        "ALL": Alert.query.count(),
        "NEW": Alert.query.filter_by(status="NEW").count(),
        "ACKNOWLEDGED": Alert.query.filter_by(status="ACKNOWLEDGED").count(),
        "RESOLVED": Alert.query.filter_by(status="RESOLVED").count()
    }

    return jsonify({
        "data": [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "source_ip": a.source_ip,
                "session_id": a.session_id,
                "event_id": a.event_id,
                "attack_type": a.attack_type,
                "risk_score": a.risk_score,
                "status": a.status,
                "occurrences": a.occurrences,
                "reasons": a.reasons_json,
                "last_occurrence_at": a.last_occurrence_at.isoformat() if a.last_occurrence_at else None
            }
            for a in alerts
        ],
        "counts": counts,
        "meta": {"page": page, "per_page": per_page, "total": total}
    })


@api_soc_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
@login_required
@role_required("analyst")
def acknowledge_alert(alert_id):
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ApiError("not_found", "Alert not found", 404)

    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = utc_now()
    db.session.commit()
    audit_log("alert.acknowledge", alert_id, "success")
    return jsonify({"status": "success", "alert_id": alert_id})


@api_soc_bp.route("/alerts/<alert_id>/resolve", methods=["POST"])
@login_required
@role_required("analyst")
def resolve_alert(alert_id):
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ApiError("not_found", "Alert not found", 404)

    alert.status = "RESOLVED"
    alert.resolved_at = utc_now()
    db.session.commit()
    audit_log("alert.resolve", alert_id, "success")
    return jsonify({"status": "success", "alert_id": alert_id})


# 4. Attackers
@api_soc_bp.route("/attackers")
@login_required
def list_attackers():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 50))))

    query = AttackerProfile.query
    if request.args.get("q"):
        query = query.filter(AttackerProfile.source_ip.like(f"%{request.args.get('q')}%"))

    total = query.count()
    profiles = query.order_by(AttackerProfile.max_risk.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "data": [
            {
                "id": p.id,
                "source_ip": p.source_ip,
                "country": p.geo_record.country if p.geo_record else "Unknown",
                "city": p.geo_record.city if p.geo_record else "Unknown",
                "first_seen": p.first_seen.isoformat(),
                "last_seen": p.last_seen.isoformat(),
                "total_sessions": p.total_sessions,
                "total_events": p.total_events,
                "max_risk": p.max_risk,
                "avg_risk": p.avg_risk,
                "engagement_score": p.engagement_score,
                "top_attack_type": p.top_attack_type,
                "vpn_detected": p.vpn_detected,
                "tor_detected": p.tor_detected
            }
            for p in profiles
        ],
        "meta": {"page": page, "per_page": per_page, "total": total}
    })


@api_soc_bp.route("/attackers/<ip_or_id>")
@login_required
def get_attacker(ip_or_id):
    profile = AttackerProfile.query.filter(
        (AttackerProfile.source_ip == ip_or_id) | (AttackerProfile.id == (int(ip_or_id) if ip_or_id.isdigit() else -1))
    ).first()

    if not profile:
        raise ApiError("not_found", "Attacker profile not found", 404)

    geo = profile.geo_record
    events = HoneypotEventModel.query.filter_by(source_ip=profile.source_ip).order_by(HoneypotEventModel.timestamp.desc()).limit(100).all()

    return jsonify({
        "profile": {
            "id": profile.id,
            "source_ip": profile.source_ip,
            "country": geo.country if geo else "Unknown",
            "city": geo.city if geo else "Unknown",
            "isp": geo.isp if geo else "Unknown",
            "asn": geo.asn if geo else "Unknown",
            "first_seen": profile.first_seen.isoformat(),
            "last_seen": profile.last_seen.isoformat(),
            "total_sessions": profile.total_sessions,
            "total_events": profile.total_events,
            "max_risk": profile.max_risk,
            "avg_risk": profile.avg_risk,
            "engagement_score": profile.engagement_score,
            "top_attack_type": profile.top_attack_type,
            "vpn": profile.vpn_detected,
            "tor": profile.tor_detected
        },
        "recent_events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "endpoint": e.endpoint,
                "surface": e.surface,
                "attack_type": e.attack_type,
                "severity": e.severity,
                "risk_score": e.risk_score
            }
            for e in events
        ]
    })


# 5. Sessions
@api_soc_bp.route("/sessions")
@login_required
def list_sessions():
    sessions = AttackerSession.query.order_by(AttackerSession.last_seen.desc()).limit(100).all()
    return jsonify({
        "data": [
            {
                "id": s.id,
                "source_ip": s.source_ip,
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
                "duration_seconds": int((s.last_seen - s.first_seen).total_seconds()),
                "event_count": s.event_count,
                "risk_score": s.risk_score,
                "engagement_score": s.engagement_score,
                "status": s.status,
                "attack_types": s.attack_types_json,
                "surfaces": s.surfaces_json
            }
            for s in sessions
        ]
    })


@api_soc_bp.route("/sessions/<session_id>")
@login_required
def get_session(session_id):
    sess = AttackerSession.query.get(session_id)
    if not sess:
        raise ApiError("not_found", "Session not found", 404)

    events = HoneypotEventModel.query.filter_by(session_id=session_id).order_by(HoneypotEventModel.timestamp.asc()).all()

    return jsonify({
        "session": {
            "id": sess.id,
            "source_ip": sess.source_ip,
            "first_seen": sess.first_seen.isoformat(),
            "last_seen": sess.last_seen.isoformat(),
            "duration_seconds": int((sess.last_seen - sess.first_seen).total_seconds()),
            "event_count": sess.event_count,
            "risk_score": sess.risk_score,
            "engagement_score": sess.engagement_score,
            "status": sess.status,
            "score_breakdown": sess.score_breakdown_json,
            "endpoints": sess.endpoints_json,
            "surfaces": sess.surfaces_json
        },
        "timeline": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "endpoint": e.endpoint,
                "http_method": e.http_method,
                "surface": e.surface,
                "attack_type": e.attack_type,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "payload": e.payload
            }
            for e in events
        ]
    })


# 6. Detection Rules
@api_soc_bp.route("/detection/rules")
@login_required
def get_rules():
    engine = get_detection_engine()
    return jsonify({"rules": engine.get_rules_info()})


@api_soc_bp.route("/detection/rules/<rule_id>", methods=["PUT"])
@login_required
@role_required("admin")
def update_rule(rule_id):
    body = request.get_json(silent=True) or {}
    if "enabled" in body:
        set_config_value(f"rule.{rule_id}.enabled", bool(body["enabled"]))
        audit_log("rule.toggle", rule_id, "success", {"enabled": bool(body["enabled"])})

    return jsonify({"status": "success", "rule_id": rule_id})


# 7. Map Points
@api_soc_bp.route("/map/points")
@login_required
def get_map_points():
    profiles = AttackerProfile.query.all()
    points = []
    for p in profiles:
        geo = p.geo_record
        if geo and geo.latitude is not None and geo.longitude is not None:
            points.append({
                "ip": p.source_ip,
                "lat": geo.latitude,
                "lng": geo.longitude,
                "country": geo.country or "Unknown",
                "city": geo.city or "Unknown",
                "isp": geo.isp or "Unknown",
                "asn": geo.asn or "None",
                "attack_count": p.total_events,
                "max_risk": p.max_risk,
                "top_attack": p.top_attack_type,
                "vpn": p.vpn_detected,
                "tor": p.tor_detected,
                "approx": True
            })
    return jsonify({"points": points})


# 8. System Health & Honeypot Status
@api_soc_bp.route("/system/health")
@login_required
def system_health():
    return jsonify(sample_system_health())


@api_soc_bp.route("/honeypot/status")
@login_required
def honeypot_status():
    surfaces = ["login", "admin", "api", "files", "database", "shell"]
    cards = []
    for s in surfaces:
        count = HoneypotEventModel.query.filter_by(surface=s).count()
        attacks = HoneypotEventModel.query.filter(
            HoneypotEventModel.surface == s,
            HoneypotEventModel.attack_type != "NONE"
        ).count()
        last_ev = HoneypotEventModel.query.filter_by(surface=s).order_by(HoneypotEventModel.timestamp.desc()).first()

        cards.append({
            "name": f"Fake {s.title()}",
            "surface": s,
            "status": "Operational",
            "events": count,
            "attacks": attacks,
            "last_activity": last_ev.timestamp.isoformat() if last_ev else None
        })

    return jsonify({"surfaces": cards})


# 9. Audit Logs
@api_soc_bp.route("/audit")
@login_required
@role_required("admin")
def list_audit():
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    total = AuditLog.query.count()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "data": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "username": l.username,
                "action": l.action,
                "target": l.target,
                "ip": l.ip,
                "outcome": l.outcome,
                "detail": l.detail_json
            }
            for l in logs
        ],
        "meta": {"page": page, "per_page": per_page, "total": total}
    })


# 10. Reports
@api_soc_bp.route("/reports/events.csv")
@login_required
@role_required("analyst")
def export_events_csv():
    csv_data = generate_events_csv()
    filename = f"honeypot_nexus_events_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@api_soc_bp.route("/reports/attackers.csv")
@login_required
@role_required("analyst")
def export_attackers_csv():
    csv_data = generate_attackers_csv()
    filename = f"honeypot_nexus_attackers_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@api_soc_bp.route("/reports/threat-report.pdf")
@login_required
@role_required("analyst")
def export_pdf_report():
    pdf_bytes = generate_pdf_report()
    filename = f"honeypot_nexus_threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# 11. Demo Endpoints
@api_soc_bp.route("/demo/run", methods=["POST"])
@login_required
@role_required("admin")
def trigger_demo():
    body = request.get_json(silent=True) or {}
    scenario = body.get("scenario", "mixed")
    try:
        events_planned = run_scenario_async(scenario)
        return jsonify({"status": "success", "scenario": scenario, "events_planned": events_planned})
    except Exception as e:
        raise ApiError("conflict", str(e), 409)


@api_soc_bp.route("/demo/reset", methods=["POST"])
@login_required
@role_required("admin")
def reset_demo():
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "RESET":
        raise ApiError("validation_error", "Must pass confirm='RESET'", 422)

    purge_synthetic_data()
    return jsonify({"status": "success", "message": "Synthetic telemetry purged"})
