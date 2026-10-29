# Honeypot Nexus — Project Architecture & Codebase Summary for AI Analysis

## 1. Project Overview
**Honeypot Nexus** is a dual-layer cybersecurity application combining:
1. **Untrusted Public Honeypot Deception Layer (SecureCorp)**: A realistic synthetic corporate IT website with deceptive interaction surfaces (login portal, fake admin console, file repository, database queries, web shell terminal, and synthetic REST API).
2. **Trusted Private SOC Dashboard (Honeypot Nexus)**: A Security Operations Center monitoring dashboard with real-time attack visualization, Leaflet geographic maps, multi-stage detection rules, 0-100 deterministic risk scoring, attacker dossiers, and an application-level Attack Prevention Layer.

## 2. Core Architecture & Layer Isolation
- **Isolation Invariant**: Layer 1 (Public Honeypot) is strictly isolated from the backend database/ORM and dangerous OS APIs. It communicates only by emitting HMAC-signed envelopes through an in-memory queue (`EventBus`) to the worker processor (`EventProcessor`).
- **Single Runtime, Dual Server**:
  - Public Honeypot binds to port `8080` (or unified via WSGI dispatcher on port `5000`).
  - Private SOC Dashboard binds to port `5000` (`/dashboard/`, `/auth/`, `/api/`, `/socket.io`).
- **Persistence & State**:
  - SQLite (`instance/honeypot_nexus.db`) stores durable audit logs, attacker profiles, correlated sessions, detections, user credentials, and prevention block history.
  - In-memory structures provide sub-millisecond IP blocking, sliding-window burst detection, and brute-force lockout tracking.

## 3. Directory Layout & Module Structure
```
├── app/
│   ├── auth/                # Operator authentication, PBKDF2 hashing, TOTP/MFA verification, RBAC
│   ├── config.py            # Centralized configuration, security validators, environment bindings
│   ├── dashboard/           # SOC web views, REST API endpoints (/api/*), Socket.IO live stream
│   ├── detection/           # Threat detection engine (10 MITRE-aligned rules), mathematical scoring
│   ├── events/              # EventBus, HMAC envelope validation, worker EventProcessor
│   ├── honeypot/            # Deceptive surfaces (/login, /admin, /files, /database, /shell, /api/v1)
│   ├── intelligence/        # GeoIP provider (MaxMind MMDB + RFC 5737 mock), Tor/VPN reputation
│   ├── models/              # SQLAlchemy models (BlockedIP, AuditLog, HoneypotEventModel, etc.)
│   ├── services/            # PreventionService, StatsService, HealthService, DemoService, ReportService
│   ├── static/              # Dark cybersecurity theme CSS, Leaflet.js, Chart.js, Socket.IO client
│   └── templates/           # Jinja2 templates (dashboard SOC UI and SecureCorp corporate website)
├── data/                    # RFC 5737 mock GeoIP database, static fixtures
├── docs/                    # Architecture diagrams, specifications, deployment logs
├── scripts/                 # Admin setup, isolation checker, live end-to-end verification suite
├── tests/                   # Pytest test suite (unit, integration, prevention, security invariants)
├── requirements.txt         # Dependencies (Flask, Flask-SocketIO, SQLAlchemy, pyotp, geoip2, etc.)
├── run.py                   # Production launcher running both Honeypot and SOC services
└── render.yaml              # Render deployment configuration
```

## 4. Detection Rules & Risk Scoring (0–100)
- **Rules (MITRE ATT&CK aligned)**:
  - `R-SQLI-001`: SQL Injection detection (UNION, Tautology, System functions).
  - `R-TRAV-001`: Directory Traversal (`../`, `/etc/passwd`, Windows system paths).
  - `R-BF-001`: High-frequency authentication brute-force.
  - `R-CRED-001`: Credential stuffing & password spraying across distinct accounts.
  - `R-SCAN-001`: Vulnerability scanner fingerprinting (Nikto, SQLmap, Nmap).
  - `R-RECON-001`: Sensitive endpoint probe & directory discovery.
  - `R-SHELL-001`: Controlled terminal command execution reconnaissance.
  - `R-API-001`: Excessive 404 burst / API parameter enumeration.
  - `R-FILE-001`: Honeytoken & canary file access detection.
- **Scoring Engine**:
  - Base interaction: 5 points.
  - Distinct technique weights: SQL Injection (+30), Directory Traversal (+25), Shell Recon (+20), Brute Force (+20), Scanners (+15), Recon (+10).
  - Repetition bonus: +10 points if any technique is repeated >= 3 times.
  - Engagement depth: +10 points if session explores multiple surfaces.
  - Bands: Normal (0-24), Elevated (25-49), High (50-74), Critical (75-100).

## 5. Attack Prevention Layer Controls
1. **Temporary IP Blocking**: Thread-safe in-memory cache synchronized with SQLite `BlockedIP` table. Intercepted in honeypot `before_request` hook returning `HTTP 403 Forbidden`.
2. **Account & IP Lockouts**: Brute-force tracking locking out attackers for 15 minutes after 5 consecutive failures without username enumeration.
3. **Automated Prevention Policy**: Triggers automatic blocking when critical risk (>= 85) with severe attack patterns is detected.
4. **Rate Limiting**: Flask-Limiter enforcing 60 req/min on public honeypot and 5 req/min on login, returning `HTTP 429 Too Many Requests`.
5. **Payload Size Guard**: Drops bodies > 64KB with `HTTP 413 Payload Too Large`.
6. **Whitelist & Loopback Immunity**: `127.0.0.1`, `::1`, and administrative IPs are immune from blocking.

## 6. Verification & Test Metrics
- **Automated Pytest Suite**: 46 / 46 passed (100%).
- **Live HTTP End-to-End Suite**: 35 / 35 passed (100%).
- **Isolation Check**: Zero ORM or DB imports in Layer 1 honeypot.
