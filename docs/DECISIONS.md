# Architecture & Implementation Decisions Log (Honeypot Nexus)

### 1. In-Process Two-Layer Isolation
- **Decision:** Run two separate Flask application objects (`create_soc_app` and `create_honeypot_app`) within a unified runtime on separate network ports (`5000` for Private SOC, `8080` for Public Honeypot).
- **Rationale:** Satisfies the blueprint requirement for strict isolation while supporting the in-memory HMAC-validated EventBus without requiring external message brokers (such as Redis or RabbitMQ) during lab presentations.
- **Verification:** Enforced by AST scan in `scripts/check_isolation.py` and `tests/security/test_security_invariants.py`.

### 2. Pure Virtual File & Shell Simulators
- **Decision:** The Honeypot shell terminal (`app/honeypot/shell_sim.py`) and file repository (`app/honeypot/files.py`) use dictionary dispatch and in-memory virtual directory hierarchies.
- **Rationale:** Zero real OS commands (`subprocess`, `os.system`, `eval`, `exec`) can ever be triggered by an attacker.

### 3. Password Non-Persistence via Ephemeral Transients
- **Decision:** Passwords submitted to the honeypot are placed into an ephemeral `transient` dictionary during request capture and immediately hashed into an HMAC fingerprint at the normalizer stage.
- **Rationale:** Prevents storing or logging plaintext credentials while enabling password reuse and spraying detection across multiple accounts.

### 4. Deterministic Scoring Model
- **Decision:** Replaced black-box or opaque scoring with a transparent mathematical formula (0–100) combining base interaction points, distinct attack category weights, repeat attack bonuses, and engagement metrics.
- **Rationale:** Complete explainability in the SOC UI and reproducible scoring in automated tests.
