# Honeypot Nexus

### Honeypot-Based Intrusion Detection & Live Attack Visualization Dashboard

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Security Tested](https://img.shields.io/badge/security-AST%20Isolated-success.svg)](#security-guarantees)
[![Test Suite](https://img.shields.io/badge/pytest-19%20passed-brightgreen.svg)](#automated-testing)
[![Architecture](https://img.shields.io/badge/architecture-3--Layer%20Deception-blueviolet.svg)](#system-architecture)

**Honeypot Nexus** is an enterprise-grade defensive deception platform and Security Operations Center (SOC) visualization system. It deploys a convincing, synthetic corporate web portal (**SecureCorp Inc.**) on port 8080 to attract adversarial probing, processes every interaction through an HMAC-signed in-process EventBus, executes deterministic rule-based attack detection and explainable risk scoring, and streams live telemetry over WebSockets to an authenticated, dark-themed SOC dashboard on port 5000.

---

## 🏛️ System Architecture

Honeypot Nexus is engineered with strict **three-layer architectural isolation**:

```
                      SIMULATED ATTACKER / EVALUATION CLIENT
                                         │
                                         ▼
 ┌────────────────────────────── LAYER 1 · PUBLIC WEB HONEYPOT  (untrusted) ───────────────────────────┐
 │  Port 8080 • Own Flask App • NO database • NO ORM import • NO subprocess • NO real filesystem        │
 │   Fake Login   Fake Admin   Fake API   Fake Files   Fake Database Viewer   Controlled Fake Shell    │
 │                         ▼  Request-capture middleware → HoneypotEvent (Pydantic)                    │
 │                         ▼  Publisher facade: publish(event) ← ONLY door out                         │
 └──────────────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                                ▼
                               ╔═══════════════ SECURE EVENTBUS ═══════════════╗
                               ║ HMAC-SHA256 Signed Envelope • Schema Enforced ║
                               ║ Bounded Queue • Real-time Backpressure        ║
                               ╚═══════════════════════╤═══════════════════════╝
                                                       ▼
 ┌────────────────────── LAYER 2 · TRUSTED EVENT & INTELLIGENCE PROCESSING ────────────────────────────┐
 │  Event Processor → Normalizer (Password HMAC Fingerprinting) → Session Engine                       │
 │  → GeoIP & Network Intelligence (ASN, ISP, VPN/Tor Heuristics)                                      │
 │  → Detection Engine (10 Modular Rules & Rolling Windows) → Deterministic Risk Scoring (0–100)       │
 │  → Engagement Depth Analysis → Alert Generation → SQLite Persistence → WebSocket Push               │
 └──────────────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                                ▼
 ┌──────────────────────── LAYER 3 · PRIVATE SOC DASHBOARD  (authenticated) ───────────────────────────┐
 │  Port 5000 • Argon2id Hashing • RFC 6238 TOTP MFA • Role-Based Access Control (RBAC)                │
 │  Live Attacks Stream • Geographic Threat Map • Attacker Dossiers • Explainable Risk Scoring         │
 │  Alert Incident Triage • Subsystem Health Diagnostics • DDE-Protected CSV & Branded PDF Reports    │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Key Features

- **Isolated Public Deception Surfaces (Port 8080):**
  - **Fake Login:** Captures credentials safely; detects brute force and password spraying.
  - **Fake Admin:** Realistic 8-section administration console (`/admin`).
  - **Fake REST API:** Decoy endpoints (`/api/v1/users`, `/config`, `/tokens`) detecting API enumeration.
  - **Fake File Manager:** In-memory virtual filesystem with simulated confidential and backup targets.
  - **Fake Database Viewer:** Safe in-memory list filtering — zero SQL queries executed.
  - **Controlled Fake Shell:** Pure dictionary-dispatch terminal simulator without any OS execution capabilities.
  - **Reconnaissance Bait:** `/robots.txt`, `/.git`, `/.env`, `/backup`, `/config` probes.

- **Deterministic & Explainable Attack Detection:**
  - `R-BF-001` — Brute Force Authentication (threshold in sliding window)
  - `R-CRED-001` — Credential Attack / Password Spraying (multiple usernames targeted)
  - `R-SQLI-001` — SQL Injection (Tautology, UNION, Boolean, Comment, Stacked, Time, Meta patterns)
  - `R-TRAV-001` — Directory Traversal (dot-dot-slash, URL double-encoding, absolute paths)
  - `R-SCAN-001` — Vulnerability Scanners (User-Agent signatures e.g. sqlmap, nikto, dirbuster)
  - `R-RECON-001` — Discovery Probes (sensitive bait endpoints)
  - `R-API-001` — Suspicious API Activity (unauthorized scopes, mutating methods)
  - `R-ENUM-001` — Automated Rate Anomaly & 404 Error Bursts
  - `R-SHELL-001` — Terminal Reconnaissance & Tool Execution Detection
  - `R-FILE-001` — Sensitive Credential / Key / Database Backup Access

- **Mathematical Risk & Engagement Scoring (0–100):**
  - **Risk Engine:** Transparent formula based on distinct attack techniques, repetition multipliers, and high engagement bonuses.
  - **Threat Pulse:** Real-time global severity metric calculated over a rolling 15-minute window.
  - **Engagement Score:** Reflects attacker exploration depth across multiple deception surfaces.

- **SOC Operator Security & Dashboard (Port 5000):**
  - Dark cybersecurity theme built on custom CSS tokens (`tokens.css`, `components.css`).
  - 100% offline vendored assets (`Chart.js`, `Leaflet.js`, `Socket.IO`).
  - Argon2id password hashing, account lockout, and sliding session timeouts.
  - Time-based One-Time Password (TOTP) Multi-Factor Authentication with replay protection.
  - DDE-protected CSV data exports and branded executive PDF threat reports.
  - Integrated 7-scenario attack simulation engine targeting local loopback.

---

## 🔒 Security Invariants (S-01 to S-10)

1. **Zero OS Command Execution:** No `os.system`, `subprocess`, `shell=True`, `eval`, or `exec` exist for handling attacker input.
2. **Layer 1 Database Isolation:** Public honeypot package (`app/honeypot/**`) has zero database or ORM imports.
3. **Password Non-Persistence:** Plaintext passwords submitted to honeypots are never written to disk, database, or logs. Only HMAC-derived fingerprints are stored.
4. **Virtual Filesystem Sandbox:** The fake shell and file repository operate entirely over static in-memory data structures.
5. **Safe In-Memory DB Filtering:** Database search queries are evaluated using Python string comparisons, never SQL engines.
6. **Strict Loopback Binding:** Default network bind is `127.0.0.1` preventing accidental public exposure.
7. **CSV Injection Defense:** Spreadsheet exports prepend apostrophes to cells starting with `=`, `+`, `-`, or `@`.
8. **Stored XSS Prevention:** All telemetry displayed on the SOC dashboard is escaped via strict DOM text assignment.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.11+
- Virtual environment recommended (`venv`)

### 2. Installation
```bash
# Clone and enter directory
cd "Honeypot-Based Intrusion Detection & Live Attack Visualization Dashboard"

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Setup
```bash
# Copy environment configuration
cp .env.example .env
```
*(The `.env` file already contains safe default secret keys for local evaluation).*

### 4. Provision Initial Administrator
```bash
python scripts/init_demo_admin.py
```
*Outputs evaluation credentials:*
- **Username:** `admin`
- **Password:** `AdminPassword123!`
- **Demo TOTP Secret Key:** `JBSWY3DPEHPK3PXP`

### 5. Launch the Application
```bash
python run.py
```

Access the interfaces in your browser:
- **Private SOC Dashboard:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Public Honeypot Portal:** [http://127.0.0.1:8080](http://127.0.0.1:8080)

---

## 🧪 Automated Testing

Run the full automated test suite (unit, security invariants, and integration):
```bash
python -m pytest -v
```

Run the AST-based honeypot isolation verification:
```bash
python scripts/check_isolation.py
```

---

## 📂 Project Structure

```
├── app/
│   ├── auth/                 # Operator authentication, Argon2id, and TOTP MFA
│   ├── config.py             # Configuration and environment validation
│   ├── dashboard/            # SOC REST API, Socket.IO broadcaster, and page routes
│   ├── detection/            # Detection Engine, 10 rule classes, patterns, and scoring
│   ├── errors.py             # Central JSON error envelopes and handlers
│   ├── events/               # EventBus, Pydantic schemas, publisher facade, and processor
│   ├── extensions.py         # SQLAlchemy, SocketIO, Limiter, CSRF registry
│   ├── honeypot/             # Deception layer (login, admin, files, db, shell simulator)
│   ├── intelligence/         # GeoIP providers (Mock/MaxMind), reputation lists, enrichment
│   ├── logging_config.py     # 4-stream JSON-lines structured logger
│   ├── models/               # 11 SQLAlchemy models and SQLite WAL listeners
│   ├── services/             # Session, alert, health, demo, and report services
│   ├── static/               # Design tokens, components CSS, JS modules, and vendored libraries
│   └── templates/            # SOC dashboard and honeypot HTML templates
├── data/                     # Offline mock GeoIP table, Tor exit nodes, and VPN ASNs
├── docs/                     # Architecture diagram SVG, build log, and decision records
├── scripts/                  # Isolation checker and admin provisioning CLI tools
├── tests/                    # Unit, security invariant, and pipeline integration tests
├── .env.example              # Configuration template
├── DEMO_GUIDE.md             # Complete step-by-step faculty presentation guide
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Python package dependencies
└── run.py                    # Dual-server application runner
```

---

## 🎓 Academic Demonstration

Refer to [DEMO_GUIDE.md](DEMO_GUIDE.md) for the complete 9-minute faculty evaluation script covering live brute-force detection, SQL injection simulation, directory traversal containment, safe shell execution, and PDF report generation.

---

## ⚖️ Limitations & Ethical Notice

- **Defensive Research Only:** Honeypot Nexus is designed for intrusion monitoring, telemetry capture, and educational demonstration. It contains no offensive "hack-back" mechanisms.
- **Approximate Attribution:** GeoIP coordinates and ISP/ASN data are derived telemetry and do not identify an attacker's true physical location. In demonstration mode, documentation ranges (RFC 5737) are mapped to world coordinates.
- **In-Process Bus:** The current EventBus is in-memory and bounded. For production multi-node scaling, an external broker (e.g. Redis/RabbitMQ) can be plugged in using the same `EventPublisher` protocol.
