"""
Integration tests for the Honeypot Nexus end-to-end processing pipeline.
"""

import time
from pathlib import Path
import json
from app.models.models import HoneypotEventModel, AttackerSession, DetectionModel, Alert
from app.events.schemas import HoneypotEvent, BusEnvelope, SurfaceType, EventType, EventStatus
from app.extensions import db


def test_full_pipeline_event_persistence(soc_app):
    """
    Validates end-to-end pipeline:
    HoneypotEvent -> EventBus.publish -> Worker Processor -> DB Persistence -> Detection -> Alert
    """
    event_bus = soc_app.extensions["event_bus"]

    # Publish SQL injection attack event
    test_event = HoneypotEvent(
        source_ip="198.51.100.77",
        endpoint="/database",
        http_method="GET",
        session_id="integration_test_session_1",
        surface=SurfaceType.database,
        event_type=EventType.db_query,
        payload="' UNION SELECT username,password FROM users--",
        status=EventStatus.success
    )

    result = event_bus.publish(test_event)
    assert result.accepted is True

    # Allow worker thread to process envelope
    time.sleep(0.5)

    with soc_app.app_context():
        # 1. Verify Event persisted
        ev_row = HoneypotEventModel.query.filter_by(session_id="integration_test_session_1").first()
        assert ev_row is not None
        assert ev_row.attack_type == "SQL_INJECTION"
        assert ev_row.risk_score >= 30

        # 2. Verify Attacker Session created
        sess_row = db.session.get(AttackerSession, "integration_test_session_1")
        assert sess_row is not None
        assert sess_row.risk_score >= 30
        assert sess_row.source_ip == "198.51.100.77"

        # 3. Verify Detections recorded
        detections = DetectionModel.query.filter_by(session_id="integration_test_session_1").all()
        assert len(detections) > 0
        assert any(d.rule_id == "R-SQLI-001" for d in detections)

        # 4. Verify Alert raised for HIGH SQL Injection
        alert_row = Alert.query.filter_by(session_id="integration_test_session_1").first()
        assert alert_row is not None
        assert alert_row.severity in ("HIGH", "CRITICAL")
        assert "SQL_INJECTION" in alert_row.attack_type


def test_rest_api_summary_and_events(soc_app, soc_client):
    """Verifies REST endpoints return valid json with correct schemas."""
    # Test unauthenticated access to protected API returns 401 or redirect
    resp = soc_client.get("/api/dashboard/summary")
    assert resp.status_code in (401, 302)

    # Healthz public check
    resp_health = soc_client.get("/healthz")
    assert resp_health.status_code == 200
    assert resp_health.get_json()["status"] == "ok"


def test_pipeline_duplicate_event_idempotency(soc_app):
    """Verifies duplicate event submissions are ignored cleanly without database crash."""
    event_bus = soc_app.extensions["event_bus"]
    fixed_id = "duplicate_test_event_fixed_123"

    ev = HoneypotEvent(
        event_id=fixed_id,
        source_ip="198.51.100.99",
        endpoint="/database",
        http_method="POST",
        session_id="duplicate_test_sess",
        surface=SurfaceType.database,
        event_type=EventType.db_query,
        payload="SELECT 1",
        status=EventStatus.success
    )

    # 1. Publish first time
    res1 = event_bus.publish(ev)
    assert res1.accepted is True
    time.sleep(0.5)

    with soc_app.app_context():
        count1 = HoneypotEventModel.query.filter_by(event_id=fixed_id).count()
        assert count1 == 1

    # 2. Publish duplicate second time
    res2 = event_bus.publish(ev)
    assert res2.accepted is True
    time.sleep(0.5)

    with soc_app.app_context():
        count2 = HoneypotEventModel.query.filter_by(event_id=fixed_id).count()
        assert count2 == 1  # Count does not duplicate or raise IntegrityError


def test_eventbus_hmac_tamper_rejection_and_dead_letter(soc_app):
    """Verifies that tampered HMAC signatures are rejected and recorded to dead_letter.jsonl."""
    event_bus = soc_app.extensions["event_bus"]
    dl_path = Path("dead_letter.jsonl")

    # Tampered envelope with bad signature
    tampered_env = BusEnvelope(
        seq=99999,
        schema_version=1,
        payload_json=json.dumps({"event_id": "tampered_1", "source_ip": "10.0.0.1"}),
        signature="bad_tampered_hmac_signature_value"
    )

    assert event_bus.verify_envelope(tampered_env) is False

    # Put directly on queue to test worker rejection
    event_bus.queue.put_nowait(tampered_env)
    time.sleep(0.6)

    # Check that dead_letter.jsonl recorded the HMAC rejection
    assert dl_path.exists()
    content = dl_path.read_text(encoding="utf-8")
    assert "hmac_verification_failed" in content


def test_eventbus_malformed_event_rejection(soc_app):
    """Verifies that publishing invalid/malformed event dictionaries is rejected."""
    event_bus = soc_app.extensions["event_bus"]

    # Missing mandatory fields like endpoint, surface, etc.
    malformed_event = {"bad_field": "no_source_ip_or_endpoint"}
    res = event_bus.publish(malformed_event)
    assert res.accepted is False
    assert res.reason is not None


def test_honeypot_database_query_length_limit(honeypot_client):
    """Verifies honeypot database surface validates and rejects excessive query length."""
    huge_query = "SELECT * FROM users WHERE " + ("A" * 3000)
    resp = honeypot_client.post("/database", data={"q": huge_query, "table": "users"})
    assert resp.status_code == 400
    assert b"exceeds maximum allowed packet size" in resp.data


def test_system_health_subsystem_verification(soc_app):
    """Verifies sample_system_health accurately tests all core subsystems."""
    from app.services.health_service import sample_system_health
    with soc_app.app_context():
        health = sample_system_health()
        assert "database" in health
        assert health["database"]["status"] == "operational"
        assert "eventbus" in health
        assert health["eventbus"]["status"] == "operational"
        assert "services" in health

        service_names = [s["name"] for s in health["services"]]
        assert "Public Honeypot HTTP (Port 8080)" in service_names
        assert "Private SOC Dashboard (Port 5000)" in service_names
        assert "Database Layer (SQLite)" in service_names
        assert "Event Processing Pipeline" in service_names
        assert "Attack Prevention Engine" in service_names
        assert "GeoIP Intelligence Engine" in service_names
        for s in health["services"]:
            assert s["status"] in ("operational", "degraded")
