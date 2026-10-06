"""
Honeypot Nexus - Event Processor Pipeline
Executes the strict 9-stage sequence on each received BusEnvelope:
1 verify_signature -> 2 normalize -> 3 intelligence_enrich -> 4 session_correlate
-> 5 detect -> 6 score -> 7 persist -> 8 alert -> 9 broadcast
"""

import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List

from flask import Flask
from app.events.schemas import BusEnvelope, NormalizedEvent, AttackType, Severity
from app.models.models import (
    HoneypotEventModel,
    AttackerSession,
    AttackerProfile,
    DetectionModel,
    GeoIPRecord,
    Alert,
    utc_now,
    gen_uuid
)
from app.extensions import db, socketio
from app.logging_config import get_logger

logger = get_logger("app")
detection_logger = get_logger("detection")


class EventProcessor:
    """Thread-safe sequential pipeline executor for honeypot events."""

    def __init__(self, soc_app: Flask, event_bus):
        self.app = soc_app
        self.bus = event_bus
        self.pw_key = soc_app.config["PW_FINGERPRINT_KEY"].encode("utf-8")

    def _fingerprint_password(self, password: str) -> str:
        """Derives HMAC-SHA256 16-character hex fingerprint from password."""
        if not password:
            return ""
        return hmac.new(self.pw_key, password.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def process_envelope(self, envelope: BusEnvelope):
        """Processes a single BusEnvelope through the full pipeline under app context."""
        with self.app.app_context():
            try:
                # 1. Parse raw payload
                raw = json.loads(envelope.payload_json)

                # 2. Stage: Normalize & password redaction
                meta = raw.get("meta", {}).copy()
                transient = raw.get("transient", {})
                raw_pwd = transient.get("password")
                if raw_pwd:
                    meta["pw_fingerprint"] = self._fingerprint_password(raw_pwd)
                    meta["pw_length"] = len(raw_pwd)
                    meta["pw_class"] = self._classify_password(raw_pwd)

                ts = datetime.fromisoformat(raw["timestamp"]) if isinstance(raw["timestamp"], str) else raw["timestamp"]

                # 3. Stage: Intelligence Enrichment (GeoIP, ASN, VPN, Tor)
                geo_info = self._enrich_ip(raw["source_ip"])

                # 4. Stage: Session Correlation
                session, profile = self._correlate_session(
                    session_id=raw["session_id"],
                    source_ip=raw["source_ip"],
                    endpoint=raw["endpoint"],
                    surface=raw["surface"],
                    geo_info=geo_info
                )

                # 5. Stage: Detection Engine
                from app.detection.engine import get_detection_engine
                from app.detection.base import RuleContext
                from app.detection.windows import get_window_store

                window_store = get_window_store()
                # Record event in sliding windows
                window_store.record(
                    source_ip=raw["source_ip"],
                    session_id=raw["session_id"],
                    event_type=raw["event_type"],
                    status=raw["status"],
                    endpoint=raw["endpoint"],
                    username=meta.get("username", ""),
                    pw_fp=meta.get("pw_fingerprint", ""),
                    http_status=raw["http_status"]
                )

                rule_ctx = RuleContext(
                    raw_event=raw,
                    meta=meta,
                    transient=transient,
                    session=session,
                    windows=window_store
                )
                engine = get_detection_engine()
                detections = engine.run(rule_ctx)

                # 6. Stage: Risk & Engagement Scoring
                from app.detection.scoring import calculate_event_risk, calculate_session_risk, calculate_engagement

                primary_attack = self._pick_primary_attack(detections)
                event_risk = calculate_event_risk(detections, session)
                session_risk, risk_reasons = calculate_session_risk(session, detections)
                engagement_score, eng_reasons = calculate_engagement(session, raw, meta)
                severity = self._compute_severity(event_risk, detections, session_risk)

                # Update session counters and metadata
                session.event_count += 1
                session.last_seen = utc_now()
                session.risk_score = session_risk
                session.engagement_score = engagement_score
                if primary_attack != "NONE":
                    curr_attacks = dict(session.attack_types_json)
                    curr_attacks[primary_attack] = curr_attacks.get(primary_attack, 0) + 1
                    session.attack_types_json = curr_attacks
                session.score_breakdown_json = {
                    "risk_components": risk_reasons,
                    "engagement_components": eng_reasons
                }

                # Update profile
                profile.total_events += 1
                profile.last_seen = utc_now()
                if session_risk > profile.max_risk:
                    profile.max_risk = session_risk
                profile.engagement_score = max(profile.engagement_score, engagement_score)
                if primary_attack != "NONE":
                    profile.top_attack_type = primary_attack

                # 7. Stage: Database Persistence
                event_model = HoneypotEventModel(
                    event_id=raw.get("event_id", gen_uuid()),
                    session_id=session.id,
                    timestamp=ts,
                    received_at=utc_now(),
                    source_ip=raw["source_ip"],
                    source_port=raw.get("source_port", 0),
                    destination=raw.get("destination", "127.0.0.1:8080"),
                    endpoint=raw["endpoint"],
                    query_string=raw.get("query_string", ""),
                    http_method=raw["http_method"],
                    user_agent=raw.get("user_agent", ""),
                    surface=raw["surface"],
                    event_type=raw["event_type"],
                    attack_type=primary_attack,
                    payload=raw.get("payload", "")[:2048],
                    status=raw.get("status", "info"),
                    http_status=raw.get("http_status", 200),
                    risk_score=event_risk,
                    engagement_score=engagement_score,
                    severity=severity,
                    geo_country=geo_info.get("country"),
                    geo_country_code=geo_info.get("country_code"),
                    geo_region=geo_info.get("region"),
                    geo_city=geo_info.get("city"),
                    latitude=geo_info.get("latitude"),
                    longitude=geo_info.get("longitude"),
                    asn=geo_info.get("asn"),
                    isp=geo_info.get("isp"),
                    vpn_detected=geo_info.get("vpn", False),
                    tor_detected=geo_info.get("tor", False),
                    geo_source=geo_info.get("source", "mock"),
                    is_synthetic=raw.get("is_synthetic", False),
                    meta_json=meta
                )
                db.session.add(event_model)

                for det in detections:
                    d_model = DetectionModel(
                        event_id=event_model.event_id,
                        session_id=session.id,
                        rule_id=det.rule_id,
                        attack_type=det.attack_type.value if hasattr(det.attack_type, "value") else str(det.attack_type),
                        severity=det.severity.value if hasattr(det.severity, "value") else str(det.severity),
                        points=det.points,
                        reason=det.reason,
                        evidence_json=det.evidence,
                        detected_at=utc_now()
                    )
                    db.session.add(d_model)
                    detection_logger.info(f"Detection: rule={det.rule_id} type={det.attack_type} points={det.points} reason='{det.reason}'")

                # 8. Stage: Alert Generation
                from app.services.alert_service import evaluate_and_create_alerts
                alerts_raised = evaluate_and_create_alerts(event_model, session, detections)

                # Commit transaction before broadcasting
                db.session.commit()

                # 9. Stage: WebSocket Broadcast (AFTER COMMIT)
                from app.dashboard.websocket import broadcast_pipeline_updates
                broadcast_pipeline_updates(event_model, session, detections, alerts_raised)

            except Exception as e:
                db.session.rollback()
                logger.error(f"Pipeline error processing envelope {envelope.envelope_id}: {e}", exc_info=True)

    def _classify_password(self, pwd: str) -> str:
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_punct = any(not c.isalnum() for c in pwd)
        classes = []
        if has_lower: classes.append("lower")
        if has_upper: classes.append("upper")
        if has_digit: classes.append("digit")
        if has_punct: classes.append("punct")
        return "+".join(classes) if classes else "empty"

    def _enrich_ip(self, ip: str) -> dict:
        from app.intelligence.enrichment import get_enrichment_service
        return get_enrichment_service().enrich(ip)

    def _correlate_session(self, session_id: str, source_ip: str, endpoint: str, surface: str, geo_info: dict):
        from app.services.session_service import correlate_attacker_session
        return correlate_attacker_session(session_id, source_ip, endpoint, surface, geo_info)

    def _pick_primary_attack(self, detections) -> str:
        if not detections:
            return "NONE"
        priority = [
            "SQL_INJECTION", "DIRECTORY_TRAVERSAL", "SENSITIVE_FILE_ACCESS",
            "BRUTE_FORCE", "CREDENTIAL_ATTACK", "SHELL_RECON",
            "SUSPICIOUS_API", "AUTOMATED_ENUMERATION", "SCANNER", "RECONNAISSANCE"
        ]
        det_types = [
            d.attack_type.value if hasattr(d.attack_type, "value") else str(d.attack_type)
            for d in detections
        ]
        for p in priority:
            if p in det_types:
                return p
        return det_types[0]

    def _compute_severity(self, event_risk: int, detections, session_risk: int) -> str:
        if event_risk >= 75 or (detections and session_risk >= 75):
            return "CRITICAL"
        elif event_risk >= 50 or any(getattr(d.severity, "value", str(d.severity)) == "HIGH" for d in detections):
            return "HIGH"
        elif event_risk >= 25 or any(getattr(d.severity, "value", str(d.severity)) == "ELEVATED" for d in detections):
            return "ELEVATED"
        return "NORMAL"
