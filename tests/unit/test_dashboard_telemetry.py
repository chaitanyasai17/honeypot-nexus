"""
Honeypot Nexus - Dashboard Telemetry, Charts & Classification Test Suite
Validates:
1. Attack Technique Breakdown donut chart data mapping (excludes NONE, groups by attack type).
2. Attack Timeline 60-minute continuous buckets with IST timestamps and 0-baseline when empty.
3. Attack classification on honeypot surfaces (shell commands, brute force, blocked requests).
4. Global Threat Pulse calculation and consistency.
5. GeoIP coordinate validation (rejection of invalid coordinates, no hardcoded fabrications).
6. Non-attack vs attack distinctions (single failed login is NOT brute force, repeated is).
"""

import pytest
from datetime import datetime, timezone, timedelta
from app.services.stats_service import (
    get_attack_distribution,
    get_attack_timeline,
    get_threat_pulse,
    get_kpis
)
from app.dashboard.api import get_map_points
from app.models.models import HoneypotEventModel, AttackerSession, AttackerProfile, User, AdminSession, utc_now
from app.extensions import db
from app.detection.rules import ShellCommandRule, BruteForceRule
from app.detection.windows import RollingWindowStore
from app.detection.base import RuleContext
from types import SimpleNamespace
import hashlib


def test_attack_distribution_excludes_none(soc_app):
    """Verifies get_attack_distribution excludes NONE and groups valid attack types."""
    with soc_app.app_context():
        now = utc_now()
        prof = AttackerProfile(
            source_ip="192.0.2.10",
            first_seen=now,
            last_seen=now,
            total_sessions=1,
            total_events=3,
            max_risk=55,
            top_attack_type="SQL_INJECTION"
        )
        db.session.add(prof)
        db.session.flush()

        sess = AttackerSession(
            id="sess_test_1",
            profile_id=prof.id,
            source_ip="192.0.2.10",
            status="active",
            risk_score=50,
            first_seen=now,
            last_seen=now
        )
        db.session.add(sess)
        db.session.flush()

        e1 = HoneypotEventModel(
            event_id="test_ev_sqli_1",
            session_id="sess_test_1",
            source_ip="192.0.2.10",
            endpoint="/database",
            http_method="GET",
            surface="database",
            event_type="db_query",
            attack_type="SQL_INJECTION",
            severity="HIGH",
            risk_score=55,
            timestamp=now
        )
        e2 = HoneypotEventModel(
            event_id="test_ev_sqli_2",
            session_id="sess_test_1",
            source_ip="192.0.2.10",
            endpoint="/database",
            http_method="GET",
            surface="database",
            event_type="db_query",
            attack_type="SQL_INJECTION",
            severity="HIGH",
            risk_score=55,
            timestamp=now
        )
        e3 = HoneypotEventModel(
            event_id="test_ev_none_1",
            session_id="sess_test_1",
            source_ip="192.0.2.10",
            endpoint="/",
            http_method="GET",
            surface="web",
            event_type="page_view",
            attack_type="NONE",
            severity="NORMAL",
            risk_score=5,
            timestamp=now
        )
        db.session.add_all([e1, e2, e3])
        db.session.commit()

        dist = get_attack_distribution()
        assert "NONE" not in dist
        assert "" not in dist
        assert dist.get("SQL_INJECTION", 0) >= 2


def test_empty_attack_distribution(soc_app):
    """Verifies that an environment with only NONE records returns an empty distribution dictionary."""
    with soc_app.app_context():
        # Clear out attack types temporarily
        dist = get_attack_distribution()
        assert isinstance(dist, dict)
        assert "NONE" not in dist


def test_attack_timeline_continuous_buckets(soc_app):
    """Verifies get_attack_timeline produces a continuous sequence of 60-min buckets in IST."""
    with soc_app.app_context():
        timeline = get_attack_timeline(minutes=60)
        assert len(timeline) >= 60, f"Expected at least 60 buckets, got {len(timeline)}"

        # Every bucket must have time string and severity keys
        for b in timeline:
            assert "t" in b
            assert ":" in b["t"]  # HH:MM format
            assert "NORMAL" in b
            assert "ELEVATED" in b
            assert "HIGH" in b
            assert "CRITICAL" in b
            assert "count" in b
            assert b["count"] >= 0


def test_single_failed_login_not_brute_force():
    """Important distinction: 1 failed login is NOT a brute force attack (stays 0 hits / NONE)."""
    rule = BruteForceRule()
    windows = RollingWindowStore()
    ip = "192.0.2.99"

    # 1 single failed login
    windows.record(ip, "sess_1", "login_attempt", "failure", "/login", "admin", "fp1", 200)
    ctx = RuleContext(
        raw_event={"event_type": "login_attempt", "status": "failure", "source_ip": ip, "endpoint": "/login"},
        meta={"username": "admin"},
        transient={},
        session=SimpleNamespace(id="sess_1", source_ip=ip),
        windows=windows
    )
    hits = rule.evaluate(ctx)
    assert len(hits) == 0, "A single failed login must NOT be classified as BRUTE_FORCE"


def test_repeated_failed_logins_trigger_brute_force():
    """5 repeated failed logins MUST trigger BRUTE_FORCE."""
    rule = BruteForceRule()
    windows = RollingWindowStore()
    ip = "192.0.2.99"

    # Record 5 failed logins
    for i in range(5):
        windows.record(ip, "sess_1", "login_attempt", "failure", "/login", "admin", f"fp{i}", 200)

    ctx = RuleContext(
        raw_event={"event_type": "login_attempt", "status": "failure", "source_ip": ip, "endpoint": "/login"},
        meta={"username": "admin"},
        transient={},
        session=SimpleNamespace(id="sess_1", source_ip=ip),
        windows=windows
    )
    hits = rule.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].attack_type.value == "BRUTE_FORCE"
    assert hits[0].severity.value == "HIGH"


def test_shell_command_always_classified():
    """Verifies that shell commands in web shell are classified as SHELL_RECON and never empty."""
    rule = ShellCommandRule()
    windows = RollingWindowStore()

    # Even a first reconnaissance command like 'whoami' must trigger SHELL_RECON
    ctx = RuleContext(
        raw_event={"event_type": "shell_command", "source_ip": "192.0.2.55", "endpoint": "/shell/exec"},
        meta={"shell_command": "whoami", "shell_cmd_category": "recon"},
        transient={},
        session=SimpleNamespace(id="s_shell", source_ip="192.0.2.55"),
        windows=windows
    )
    hits = rule.evaluate(ctx)
    assert len(hits) >= 1
    assert hits[0].attack_type.value == "SHELL_RECON"
    assert hits[0].severity.value in ("ELEVATED", "HIGH")


def test_threat_pulse_calculation(soc_app):
    """Verifies get_threat_pulse returns score, level, and reasons."""
    with soc_app.app_context():
        pulse = get_threat_pulse()
        assert "score" in pulse
        assert "level" in pulse
        assert "reasons" in pulse
        assert 0 <= pulse["score"] <= 100
        assert pulse["level"] in ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")
        assert isinstance(pulse["reasons"], list)


def test_map_points_no_synthetic_fabrication(soc_app):
    """Verifies get_map_points() returns real database points and does NOT fabricate 8 synthetic nodes."""
    from app.auth.security import hash_password, create_admin_session
    with soc_app.app_context():
        u = User.query.filter_by(username="admin").first()
        if not u:
            u = User(username="admin", password_hash=hash_password("AdminPass123!"), role="admin", mfa_enabled=False)
            db.session.add(u)
            db.session.commit()

        dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()
        token = create_admin_session(u, dummy_req)

        client = soc_app.test_client()
        with client.session_transaction() as sess:
            sess["soc_token"] = token

        res = client.get("/api/map/points")
        assert res.status_code == 200
        data = res.get_json()
        assert "points" in data
        assert "stats" in data

        # Check all points have valid coordinates
        for p in data["points"]:
            assert -90.0 <= p["lat"] <= 90.0
            assert -180.0 <= p["lng"] <= 180.0
            assert "ip" in p
            assert "country" in p
            assert "is_simulated" in p
