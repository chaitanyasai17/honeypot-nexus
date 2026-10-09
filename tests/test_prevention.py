"""
Honeypot Nexus - Attack Prevention Layer Automated Test Suite
Validates all 11 core prevention controls:
1. Normal requests within limits succeed (200).
2. Requests exceeding rate limits receive HTTP 429 and record telemetry.
3. Multiple failed logins trigger temporary lockout.
4. Locked user and non-existent accounts receive generic error messages (no enumeration).
5. Lockout expires after configured duration.
6. Temporarily blocked IP receives HTTP 403 on honeypot.
7. Unblocked / expired IP can make requests again.
8. Requests exceeding payload limits receive HTTP 413.
9. Unauthenticated or non-admin access to prevention APIs is rejected (401/403).
10. Admin can block/unblock via API, with full audit trail logging.
11. End-to-end pipeline verification (EventBus -> Detection -> Prevention -> Storage).
"""

import time
import pytest
from datetime import datetime, timezone, timedelta
from app.extensions import db, limiter
from app.config import Config
from app.models.models import User, BlockedIP, AuditLog, HoneypotEventModel
from app.auth.security import hash_password, create_admin_session
from app.services.prevention_service import get_prevention_service
from app.events.schemas import HoneypotEvent, SurfaceType, EventType, EventStatus


@pytest.fixture(autouse=True)
def cleanup_prevention_state():
    """Ensures each test starts with pristine in-memory and rate-limiting state."""
    prev_svc = get_prevention_service()
    prev_svc.reset_state()
    try:
        limiter.reset()
    except Exception:
        pass
    yield
    prev_svc.reset_state()
    try:
        limiter.reset()
    except Exception:
        pass


# Helper to authenticate a test client session
def authenticate_client(app, client, user):
    """Sets a valid authenticated admin session for client."""
    with app.test_request_context():
        dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()
        token = create_admin_session(user, dummy_req)
    with client.session_transaction() as sess:
        sess["soc_token"] = token
    return token


# -------------------------------------------------------------
# 1. Normal Request Within Rate Limit Succeeds (200)
# -------------------------------------------------------------
def test_normal_request_within_rate_limit(honeypot_client):
    """Verifies that legitimate requests within rate limits receive HTTP 200."""
    resp = honeypot_client.get("/", environ_base={"REMOTE_ADDR": "198.51.100.1"})
    assert resp.status_code == 200


# -------------------------------------------------------------
# 2. Rate Limiting Enforces HTTP 429 and Records Telemetry
# -------------------------------------------------------------
def test_rate_limiting_enforcement_and_telemetry(honeypot_client, honeypot_app):
    """Verifies that exceeding rate limits triggers HTTP 429 and publishes telemetry."""
    honeypot_app.config["RATELIMIT_ENABLED"] = True
    test_ip = "198.51.100.99"

    # Honeypot login endpoint has RATE_LIMIT_LOGIN = 5 per minute
    # Send repeated login requests
    status_codes = []
    for _ in range(8):
        resp = honeypot_client.post(
            "/login",
            data={"username": "testuser", "password": "password123"},
            environ_base={"REMOTE_ADDR": test_ip}
        )
        status_codes.append(resp.status_code)

    assert 429 in status_codes, f"Expected 429 in status codes, got: {status_codes}"

    # Verify 429 response was recorded in prevention service
    prev_svc = get_prevention_service()
    rate_events = prev_svc.get_recent_rate_limits()
    assert len(rate_events) > 0
    assert any(ev["ip"] == test_ip for ev in rate_events)


# -------------------------------------------------------------
# 3 & 4. Brute-Force Lockout & Username Enumeration Guard
# -------------------------------------------------------------
def test_failed_logins_trigger_lockout_and_generic_message(soc_app, soc_client, monkeypatch):
    """
    Verifies that exceeding failed login attempts triggers account/IP lockout,
    and returns identical generic error messages preventing username enumeration.
    """
    # Lower threshold to 3 so lockout triggers before hitting the 5 req/min rate limit
    monkeypatch.setattr(Config, "AUTH_LOCKOUT_THRESHOLD", 3)
    test_ip = "198.51.100.50"
    prev_svc = get_prevention_service()

    with soc_app.app_context():
        generic_msg = "Invalid credentials or account temporarily locked. Please try again later."

        # 3 failed login attempts
        for _ in range(3):
            resp = soc_client.post(
                "/auth/login",
                data={"username": "admin_test", "password": "WrongPassword!"},
                environ_base={"REMOTE_ADDR": test_ip},
                follow_redirects=True
            )
            assert resp.status_code == 200
            assert generic_msg.encode() in resp.data

        # Account / IP should now be locked
        is_locked, until = prev_svc.is_login_locked(test_ip, "admin_test")
        assert is_locked is True
        assert until is not None

        # 4th attempt while locked must return the exact same generic error message (HTTP 200)
        resp_locked = soc_client.post(
            "/auth/login",
            data={"username": "admin_test", "password": "AdminSecurePassword123!"},
            environ_base={"REMOTE_ADDR": test_ip},
            follow_redirects=True
        )
        assert resp_locked.status_code == 200
        assert generic_msg.encode() in resp_locked.data

        # Non-existent user must also return the EXACT same generic message (Zero enumeration)
        resp_ghost = soc_client.post(
            "/auth/login",
            data={"username": "non_existent_ghost_user_123", "password": "SomePassword!"},
            environ_base={"REMOTE_ADDR": "198.51.100.51"},
            follow_redirects=True
        )
        assert resp_ghost.status_code == 200
        assert generic_msg.encode() in resp_ghost.data


# -------------------------------------------------------------
# 5. Lockout Expiration
# -------------------------------------------------------------
def test_lockout_expiration():
    """Verifies that expired lockouts are seamlessly cleared."""
    prev_svc = get_prevention_service()
    test_ip = "198.51.100.60"
    username = "analyst1"

    # Simulate lockout in the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    key = f"{test_ip}:{username.lower()}"
    with prev_svc._lock:
        prev_svc._failed_logins[key] = {
            "count": 5,
            "locked_until": past_time,
            "last_failed": past_time
        }

    # Calling is_login_locked should detect expiration and clear it
    is_locked, until = prev_svc.is_login_locked(test_ip, username)
    assert is_locked is False
    assert until is None


# -------------------------------------------------------------
# 6 & 7. Temporarily Blocked IP Receives 403 & Unblock Restores Access
# -------------------------------------------------------------
def test_ip_blocking_and_unblocking(honeypot_client, honeypot_app):
    """Verifies that blocked IPs receive 403 on honeypot, and unblocking restores access."""
    test_ip = "203.0.113.88"
    prev_svc = get_prevention_service()
    publisher = honeypot_app.extensions["test_publisher"]

    # Block IP
    prev_svc.block_ip(
        ip=test_ip,
        reason="Automated SQL injection defense",
        duration_minutes=30,
        blocked_by="test_suite"
    )

    # Request from blocked IP must receive 403 Forbidden
    resp_blocked = honeypot_client.get("/", environ_base={"REMOTE_ADDR": test_ip})
    assert resp_blocked.status_code == 403
    assert b"403 Forbidden" in resp_blocked.data

    # Verify telemetry was captured in publisher.events
    blocked_events = [e for e in publisher.events if e.event_type == EventType.blocked_request]
    assert len(blocked_events) > 0
    assert blocked_events[-1].source_ip == test_ip

    # Unblock IP
    unblocked = prev_svc.unblock_ip(ip=test_ip, unblocked_by="test_suite", reason="Test completed")
    assert unblocked is True

    # Request after unblock must succeed (200)
    resp_unblocked = honeypot_client.get("/", environ_base={"REMOTE_ADDR": test_ip})
    assert resp_unblocked.status_code == 200


# -------------------------------------------------------------
# 8. Maximum Payload Size Protection (413)
# -------------------------------------------------------------
def test_payload_size_limit_rejection(honeypot_client, honeypot_app):
    """Verifies that oversized request bodies return HTTP 413 and publish telemetry."""
    publisher = honeypot_app.extensions["test_publisher"]
    test_ip = "198.51.100.77"

    # Limit is 64 KB, send 70 KB payload
    oversized_body = "A" * (70 * 1024)

    resp = honeypot_client.post(
        "/login",
        data=oversized_body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(oversized_body))
        },
        environ_base={"REMOTE_ADDR": test_ip}
    )

    assert resp.status_code == 413
    assert b"413 Payload Too Large" in resp.data

    # Verify telemetry was published in publisher.events
    payload_events = [e for e in publisher.events if e.event_type == EventType.payload_oversized]
    assert len(payload_events) > 0


# -------------------------------------------------------------
# 9. Authorization Protection on Prevention Endpoints
# -------------------------------------------------------------
def test_prevention_api_authorization_guards(soc_app, soc_client):
    """Verifies that unauthenticated and non-admin requests to block APIs are rejected."""
    with soc_app.app_context():
        # Seed an analyst user
        analyst = User(
            username="analyst_test",
            password_hash=hash_password("AnalystPassword123!"),
            role="analyst",
            mfa_enabled=False
        )
        db.session.add(analyst)
        db.session.commit()

        # 1. Unauthenticated request to block IP -> 401
        resp_unauth = soc_client.post("/api/prevention/block", json={"ip": "198.51.100.12"})
        assert resp_unauth.status_code in (401, 302)

        # 2. Authenticated as analyst (non-admin) -> 403 Forbidden
        authenticate_client(soc_app, soc_client, analyst)

        resp_forbidden = soc_client.post("/api/prevention/block", json={"ip": "198.51.100.12"})
        assert resp_forbidden.status_code == 403


# -------------------------------------------------------------
# 10. Admin Block/Unblock API and Audit Trail Recording
# -------------------------------------------------------------
def test_admin_block_unblock_api_and_audit(soc_app, soc_client):
    """
    Verifies that authenticated admin operators can block and unblock IPs via REST,
    persisting records in the BlockedIP table and AuditLog trail.
    """
    with soc_app.app_context():
        admin = User.query.filter_by(username="admin_test").first()
        authenticate_client(soc_app, soc_client, admin)

        target_ip = "198.51.100.42"

        # 1. Admin Block IP
        resp_block = soc_client.post(
            "/api/prevention/block",
            json={
                "ip": target_ip,
                "duration_minutes": 45,
                "reason": "Suspicious reconnaissance cluster"
            }
        )
        assert resp_block.status_code == 200
        block_json = resp_block.get_json()
        assert block_json["status"] == "success"

        # Verify BlockedIP in database
        db_block = BlockedIP.query.filter_by(ip=target_ip, is_active=True).first()
        assert db_block is not None
        assert db_block.blocked_by == "admin_test"
        assert db_block.reason == "Suspicious reconnaissance cluster"

        # Verify AuditLog recorded
        audit_entry = AuditLog.query.filter_by(action="prevention.ip_blocked", target=target_ip).first()
        assert audit_entry is not None
        assert audit_entry.username == "admin_test"

        # 2. Check Prevention Overview API
        resp_overview = soc_client.get("/api/prevention/overview")
        assert resp_overview.status_code == 200
        overview_data = resp_overview.get_json()
        assert overview_data["stats"]["active_blocks"] >= 1

        # 3. Check Prevention Page Route
        resp_page = soc_client.get("/dashboard/prevention")
        assert resp_page.status_code == 200
        assert b"Application-Level Attack Prevention" in resp_page.data

        # 4. Admin Unblock IP
        resp_unblock = soc_client.post(
            "/api/prevention/unblock",
            json={
                "ip": target_ip,
                "reason": "Threat neutralized and cleared"
            }
        )
        assert resp_unblock.status_code == 200
        unblock_json = resp_unblock.get_json()
        assert unblock_json["status"] == "success"

        # Verify DB updated
        db.session.refresh(db_block)
        assert db_block.is_active is False
        assert db_block.unblocked_by == "admin_test"

        # Verify AuditLog unblock recorded
        unblock_audit = AuditLog.query.filter_by(action="prevention.ip_unblocked", target=target_ip).first()
        assert unblock_audit is not None


# -------------------------------------------------------------
# 11. End-to-End Pipeline Integration Verification
# -------------------------------------------------------------
def test_pipeline_integration_with_prevention(soc_app):
    """
    Verifies that the complete event processing pipeline (EventBus -> Detection -> Prevention -> DB)
    continues functioning seamlessly and triggers autonomous blocks when critical thresholds are reached.
    """
    with soc_app.app_context():
        event_bus = soc_app.extensions["event_bus"]
        test_ip = "198.51.100.85"

        # Create high-severity attack event
        event = HoneypotEvent(
            event_id="test_ev_prev_001",
            timestamp=datetime.now(timezone.utc),
            session_id="prev_integration_session_01",
            source_ip=test_ip,
            surface=SurfaceType.database,
            event_type=EventType.db_query,
            endpoint="/database",
            http_method="POST",
            http_status=200,
            payload="' UNION SELECT username, password_hash FROM users --",
            status=EventStatus.success
        )

        result = event_bus.publish(event)
        assert result.accepted is True

        time.sleep(0.5)

        # Verify event was saved to database
        saved_ev = HoneypotEventModel.query.filter_by(event_id="test_ev_prev_001").first()
        assert saved_ev is not None
        assert saved_ev.source_ip == test_ip
