"""
Unit tests for Detection Engine Rules, Signatures, and Scoring Models.
"""

from types import SimpleNamespace
from app.detection.base import RuleContext
from app.detection.rules import (
    BruteForceRule,
    CredentialAttackRule,
    SQLInjectionRule,
    DirectoryTraversalRule,
    ScannerRule,
    ReconRule,
    SuspiciousAPIRule,
    AutomatedEnumerationRule,
    ShellCommandRule,
    SensitiveFileRule,
)
from app.detection.windows import RollingWindowStore
from app.detection.scoring import calculate_event_risk, calculate_session_risk, calculate_engagement, RISK_WEIGHTS


def build_mock_ctx(raw_event, meta=None, transient=None, windows=None, session=None):
    return RuleContext(
        raw_event=raw_event,
        meta=meta or {},
        transient=transient or {},
        windows=windows or RollingWindowStore(),
        session=session or SimpleNamespace(
            id="test_sess",
            attack_types_json={},
            surfaces_json=[],
            endpoints_json=[],
            engagement_score=0,
            event_count=0
        )
    )


def test_sql_injection_positives():
    rule = SQLInjectionRule()
    payloads = [
        "' OR '1'='1' --",
        "admin' OR 1=1--",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--",
        "' AND SLEEP(5)--",
        "1' AND 1=2 UNION SELECT NULL,@@version--"
    ]
    for p in payloads:
        ctx = build_mock_ctx({"payload": p})
        hits = rule.evaluate(ctx)
        assert len(hits) > 0, f"Failed to detect SQLi payload: {p}"
        assert hits[0].rule_id == "R-SQLI-001"
        assert hits[0].points == 30


def test_sql_injection_negatives():
    rule = SQLInjectionRule()
    benign = [
        "Normal employee query",
        "O'Brien",
        "Select a team member",
        "Union of transport workers",
        "Search for 1=1 in math book"
    ]
    for b in benign:
        ctx = build_mock_ctx({"payload": b})
        hits = rule.evaluate(ctx)
        assert len(hits) == 0, f"False positive on benign input: {b}"


def test_directory_traversal():
    rule = DirectoryTraversalRule()
    traversals = [
        "../../etc/passwd",
        "..%2f..%2fetc%2fshadow",
        "%252e%252e%252fetc%252fpasswd",
        "....//....//etc/hosts",
        "/etc/passwd"
    ]
    for t in traversals:
        ctx = build_mock_ctx({"payload": t})
        hits = rule.evaluate(ctx)
        assert len(hits) > 0, f"Failed to detect traversal: {t}"
        assert hits[0].rule_id == "R-TRAV-001"
        assert hits[0].points == 25


def test_scanner_detection():
    rule = ScannerRule()
    ctx = build_mock_ctx({"user_agent": "sqlmap/1.7.8#stable"})
    hits = rule.evaluate(ctx)
    assert len(hits) > 0
    assert hits[0].rule_id == "R-SCAN-001"
    assert hits[0].points == 15


def test_reconnaissance():
    rule = ReconRule()
    for bait in ["/robots.txt", "/.env", "/.git/config", "/backup"]:
        ctx = build_mock_ctx({"endpoint": bait})
        hits = rule.evaluate(ctx)
        assert len(hits) > 0
        assert hits[0].rule_id == "R-RECON-001"
        assert hits[0].points == 10


def test_sensitive_file_access():
    rule = SensitiveFileRule()
    ctx = build_mock_ctx({"payload": "/backups/database_backup.sql"}, meta={"sensitive": True})
    hits = rule.evaluate(ctx)
    assert len(hits) > 0
    assert hits[0].rule_id == "R-FILE-001"
    assert hits[0].points == 20


def test_brute_force_rule():
    rule = BruteForceRule()
    windows = RollingWindowStore()
    ip = "203.0.113.45"

    # 4 failed attempts should not trigger yet
    for _ in range(4):
        windows.record(ip, "s1", "login_attempt", "failure", "/login", "admin", "fp1", 200)
    ctx4 = build_mock_ctx({"event_type": "login_attempt", "status": "failure", "source_ip": ip}, windows=windows)
    assert len(rule.evaluate(ctx4)) == 0

    # 5th failed attempt must trigger R-BF-001
    windows.record(ip, "s1", "login_attempt", "failure", "/login", "admin", "fp1", 200)
    ctx5 = build_mock_ctx({"event_type": "login_attempt", "status": "failure", "source_ip": ip}, windows=windows)
    hits = rule.evaluate(ctx5)
    assert len(hits) == 1
    assert hits[0].rule_id == "R-BF-001"
    assert hits[0].points == 20


def test_risk_scoring_worked_example():
    """Validates deterministic scoring worked example from §9.5 of blueprint."""
    session = SimpleNamespace(
        id="s_test",
        attack_types_json={},
        engagement_score=0
    )

    # 1. Normal interaction: GET / -> risk = 5
    score1, _ = calculate_session_risk(session, [])
    assert score1 == 5

    # 2. Recon: GET /robots.txt -> 5 + 10 = 15
    from app.detection.base import Detection
    from app.events.schemas import AttackType, Severity
    det_recon = Detection("R-RECON-001", AttackType.RECONNAISSANCE, Severity.ELEVATED, 10, "recon")
    session.attack_types_json["RECONNAISSANCE"] = 1
    score2, _ = calculate_session_risk(session, [det_recon])
    assert score2 == 15

    # 3. Brute Force + Credential Attack: 15 + 20 + 20 = 55 (HIGH)
    session.attack_types_json["BRUTE_FORCE"] = 1
    session.attack_types_json["CREDENTIAL_ATTACK"] = 1
    score3, _ = calculate_session_risk(session, [])
    assert score3 == 55

    # 4. SQL Injection (+30): 55 + 30 = 85 (CRITICAL)
    session.attack_types_json["SQL_INJECTION"] = 1
    score4, _ = calculate_session_risk(session, [])
    assert score4 == 85

    # 5. Directory Traversal (+25): 85 + 25 = 110 -> capped at 100
    session.attack_types_json["DIRECTORY_TRAVERSAL"] = 1
    score5, _ = calculate_session_risk(session, [])
    assert score5 == 100


def test_credential_attack_spraying():
    rule = CredentialAttackRule()
    windows = RollingWindowStore()
    ip = "198.51.100.23"

    for user in ["alice", "bob", "charlie"]:
        windows.record(ip, "s1", "login_attempt", "failure", "/login", user, "fp1", 200)

    ctx = build_mock_ctx({"event_type": "login_attempt", "source_ip": ip}, windows=windows)
    hits = rule.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].rule_id == "R-CRED-001"
    assert hits[0].points == 20


def test_suspicious_api_activity():
    rule = SuspiciousAPIRule()
    ctx = build_mock_ctx({"endpoint": "/api/v1/admin", "http_method": "GET"})
    hits = rule.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].rule_id == "R-API-001"

    # Test mutating method
    ctx_post = build_mock_ctx({"endpoint": "/api/v1/users/1", "http_method": "DELETE"})
    hits_post = rule.evaluate(ctx_post)
    assert len(hits_post) == 1


def test_automated_enumeration_burst():
    rule = AutomatedEnumerationRule()
    windows = RollingWindowStore()
    ip = "198.51.100.150"

    for i in range(20):
        windows.record(ip, "s1", "page_view", "info", f"/test_{i}", "", "", 200)

    ctx = build_mock_ctx({"source_ip": ip}, windows=windows)
    hits = rule.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].rule_id == "R-ENUM-001"


def test_shell_command_rule():
    rule = ShellCommandRule()
    ctx = build_mock_ctx(
        {"event_type": "shell_command"},
        meta={"shell_command": "sudo su -", "shell_cmd_category": "priv"}
    )
    hits = rule.evaluate(ctx)
    assert len(hits) == 1
    assert hits[0].rule_id == "R-SHELL-001"
    assert hits[0].severity.value == "HIGH"


def test_engagement_scoring():
    session = SimpleNamespace(
        surfaces_json=["login", "admin", "shell"],
        endpoints_json=["/login", "/admin", "/shell/exec"],
        event_count=12,
        attack_types_json={}
    )
    score, reasons = calculate_engagement(session, {"surface": "shell"}, {"sensitive": True})
    assert score >= 50
    assert len(reasons) >= 3
