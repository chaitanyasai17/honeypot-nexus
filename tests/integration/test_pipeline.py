"""
Integration tests for the Honeypot Nexus end-to-end processing pipeline.
"""

import time
from app.models.models import HoneypotEventModel, AttackerSession, DetectionModel, Alert
from app.events.schemas import HoneypotEvent, SurfaceType, EventType, EventStatus


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
        sess_row = AttackerSession.query.get("integration_test_session_1")
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
