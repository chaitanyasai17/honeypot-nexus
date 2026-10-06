"""
Honeypot Nexus - WebSocket Communication Service (/soc namespace)
Broadcasts live telemetry, threat level updates, and security alerts to connected SOC analysts.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any
from flask import request
from flask_socketio import emit
from app.extensions import socketio
from app.logging_config import get_logger

logger = get_logger("app")
_seq_counter = 0


def _next_seq() -> int:
    global _seq_counter
    _seq_counter += 1
    return _seq_counter


def broadcast_pipeline_updates(event_model, session, detections, alerts: list):
    """
    Called by processor after DB transaction commit.
    Emits events in strict order: new_event -> new_attack -> risk_update -> session_update -> new_alert.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Compact Event DTO
    event_dto = {
        "event_id": event_model.event_id,
        "timestamp": event_model.timestamp.isoformat() if hasattr(event_model.timestamp, "isoformat") else str(event_model.timestamp),
        "source_ip": event_model.source_ip,
        "endpoint": event_model.endpoint,
        "http_method": event_model.http_method,
        "surface": event_model.surface,
        "event_type": event_model.event_type,
        "attack_type": event_model.attack_type,
        "severity": event_model.severity,
        "risk_score": event_model.risk_score,
        "engagement_score": event_model.engagement_score,
        "session_id": event_model.session_id,
        "geo_country": event_model.geo_country,
        "geo_city": event_model.geo_city,
        "latitude": event_model.latitude,
        "longitude": event_model.longitude,
        "asn": event_model.asn,
        "isp": event_model.isp,
        "vpn_detected": event_model.vpn_detected,
        "tor_detected": event_model.tor_detected,
        "payload_preview": (event_model.payload or "")[:120],
        "seq": _next_seq(),
        "ts": now_iso
    }

    # Emit new_event
    socketio.emit("new_event", event_dto, namespace="/soc")

    # 2. Emit new_attack if event has detections
    if detections:
        attack_payload = {
            "event": event_dto,
            "detections": [
                {
                    "rule_id": d.rule_id,
                    "attack_type": d.attack_type.value if hasattr(d.attack_type, "value") else str(d.attack_type),
                    "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
                    "points": d.points,
                    "reason": d.reason,
                }
                for d in detections
            ],
            "session": {
                "id": session.id,
                "risk_score": session.risk_score,
                "event_count": session.event_count
            },
            "seq": _next_seq(),
            "ts": now_iso
        }
        socketio.emit("new_attack", attack_payload, namespace="/soc")

    # 3. Emit risk_update
    risk_payload = {
        "session_id": session.id,
        "source_ip": session.source_ip,
        "risk_score": session.risk_score,
        "engagement_score": session.engagement_score,
        "seq": _next_seq(),
        "ts": now_iso
    }
    socketio.emit("risk_update", risk_payload, namespace="/soc")

    # 4. Emit session_update
    session_payload = {
        "id": session.id,
        "source_ip": session.source_ip,
        "status": session.status,
        "event_count": session.event_count,
        "risk_score": session.risk_score,
        "engagement_score": session.engagement_score,
        "surfaces": session.surfaces_json,
        "attack_types": session.attack_types_json,
        "seq": _next_seq(),
        "ts": now_iso
    }
    socketio.emit("session_update", session_payload, namespace="/soc")

    # 5. Emit new_alert for any raised alert
    for alert in alerts:
        alert_dto = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp),
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "source_ip": alert.source_ip,
            "session_id": alert.session_id,
            "attack_type": alert.attack_type,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "occurrences": alert.occurrences,
            "reasons": alert.reasons_json,
            "seq": _next_seq(),
            "ts": now_iso
        }
        socketio.emit("new_alert", alert_dto, namespace="/soc")


# Register SocketIO event handlers on /soc namespace
@socketio.on("connect", namespace="/soc")
def handle_soc_connect():
    logger.info("SOC Analyst connected to live telemetry stream (/soc)")
    emit("server_notice", {"level": "info", "text": "Connected to Honeypot Nexus Live Stream"})


@socketio.on("disconnect", namespace="/soc")
def handle_soc_disconnect():
    logger.info("SOC Analyst disconnected from live telemetry stream")


@socketio.on("ping_session", namespace="/soc")
def handle_ping():
    emit("pong", {"ts": datetime.now(timezone.utc).isoformat()})
