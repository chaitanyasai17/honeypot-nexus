"""
Honeypot Nexus - Pure Controlled Shell Simulator
CRITICAL SECURITY MODULE:
This module contains zero operating system command execution capabilities.
It uses purely in-memory dictionary dispatch and virtual filesystem lookups.
Imports: ONLY shlex, posixpath, dataclasses, typing, and synthetic content.
"""

import shlex
import posixpath
from dataclasses import dataclass, field
from typing import List, Tuple
from app.honeypot.content.files_tree import VIRTUAL_FILES


@dataclass
class ShellState:
    cwd: str = "/home/admin"
    history: List[str] = field(default_factory=list)


@dataclass
class ShellResult:
    output: str
    cwd: str
    category: str
    recognized: bool


VIRTUAL_DIRS = {
    "/": ["bin", "etc", "home", "var", "opt", "root"],
    "/etc": ["passwd", "shadow", "hostname", "os-release"],
    "/home": ["admin"],
    "/home/admin": ["notes.txt", ".bash_history", ".ssh"],
    "/home/admin/.ssh": ["id_rsa.pub"],
    "/var": ["www", "log", "backups"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "config.php.bak"],
    "/opt": ["securecorp"],
    "/opt/securecorp": ["app.conf", "backup.sh"],
    "/root": ["todo.txt", ".bash_history"]
}

VIRTUAL_EXTRA_FILES = {
    "/etc/hostname": "sc-web-01",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian',
    "/home/admin/notes.txt": "Review firewall rules for port 8080. Migrate legacy tokens.",
    "/home/admin/.bash_history": "ls -la\ncat /etc/passwd\ncurl http://127.0.0.1:8080/api/v1/config\nsudo -l\nexit",
    "/home/admin/.ssh/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8syntheticKey admin@sc-web-01",
    "/var/www/html/index.html": "<html><body><h1>SecureCorp Portal</h1></body></html>",
    "/var/www/html/config.php.bak": "<?php\n$db_pass = 'HNX-FAKE-SQLpass2024';\n?>",
    "/opt/securecorp/app.conf": "PORT=8080\nENV=production\nLOG_LEVEL=DEBUG",
    "/opt/securecorp/backup.sh": "#!/bin/bash\ntar -czf /var/backups/daily.tar.gz /var/www",
    "/root/todo.txt": "1. Renew SSL certificates\n2. Patch openssl vulnerabilities\n3. Restrict shell access"
}


def _resolve_virtual_path(cwd: str, target: str) -> str:
    """Normalizes path within virtual POSIX tree."""
    if not target or target == ".":
        return cwd
    if target.startswith("/"):
        return posixpath.normpath(target)
    return posixpath.normpath(posixpath.join(cwd, target))


def run_command(command_line: str, state: ShellState) -> ShellResult:
    """
    Executes a simulated command against virtual state.
    Guaranteed to never execute any real OS process.
    """
    cmd_raw = command_line.strip()
    if not cmd_raw:
        return ShellResult(output="", cwd=state.cwd, category="empty", recognized=True)

    if len(cmd_raw) > 256:
        return ShellResult(output="bash: syntax error: line too long", cwd=state.cwd, category="syntax_error", recognized=False)

    state.history.append(cmd_raw)
    if len(state.history) > 100:
        state.history.pop(0)

    try:
        parts = shlex.split(cmd_raw, posix=True)
    except Exception:
        return ShellResult(output="bash: unexpected EOF while looking for matching quote", cwd=state.cwd, category="syntax_error", recognized=False)

    if not parts:
        return ShellResult(output="", cwd=state.cwd, category="empty", recognized=True)

    prog = parts[0].lower()
    args = parts[1:]

    # 1. Allowed Simulation Commands
    if prog == "help":
        output = (
            "SecureCorp Admin Terminal - Emulated Shell v2.4\n"
            "Supported builtins: help, whoami, id, pwd, ls, cd, cat, uname, history, clear"
        )
        return ShellResult(output=output, cwd=state.cwd, category="recon", recognized=True)

    elif prog == "whoami":
        return ShellResult(output="root", cwd=state.cwd, category="recon", recognized=True)

    elif prog == "id":
        return ShellResult(output="uid=0(root) gid=0(root) groups=0(root)", cwd=state.cwd, category="recon", recognized=True)

    elif prog == "pwd":
        return ShellResult(output=state.cwd, cwd=state.cwd, category="recon", recognized=True)

    elif prog == "uname":
        if "-a" in args:
            output = "Linux sc-web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        else:
            output = "Linux"
        return ShellResult(output=output, cwd=state.cwd, category="recon", recognized=True)

    elif prog == "history":
        lines = [f"  {idx + 1}  {cmd}" for idx, cmd in enumerate(state.history)]
        return ShellResult(output="\n".join(lines), cwd=state.cwd, category="recon", recognized=True)

    elif prog == "clear":
        return ShellResult(output="", cwd=state.cwd, category="recon", recognized=True)

    elif prog == "cd":
        target = args[0] if args else "/root"
        new_path = _resolve_virtual_path(state.cwd, target)
        if new_path in VIRTUAL_DIRS:
            state.cwd = new_path
            return ShellResult(output="", cwd=state.cwd, category="nav", recognized=True)
        else:
            return ShellResult(output=f"bash: cd: {target}: No such file or directory", cwd=state.cwd, category="nav", recognized=False)

    elif prog == "ls":
        target = args[-1] if (args and not args[-1].startswith("-")) else state.cwd
        path = _resolve_virtual_path(state.cwd, target)
        if path in VIRTUAL_DIRS:
            items = VIRTUAL_DIRS[path]
            if "-l" in args or "-la" in args or "-al" in args:
                lines = [f"total {len(items) * 4}"]
                for item in items:
                    lines.append(f"-rw-r--r-- 1 root root 4096 Mar 05 08:00 {item}")
                return ShellResult(output="\n".join(lines), cwd=state.cwd, category="recon", recognized=True)
            else:
                return ShellResult(output="  ".join(items), cwd=state.cwd, category="recon", recognized=True)
        else:
            return ShellResult(output=f"ls: cannot access '{target}': No such file or directory", cwd=state.cwd, category="recon", recognized=False)

    elif prog == "cat":
        if not args:
            return ShellResult(output="", cwd=state.cwd, category="file_read", recognized=True)
        target = args[0]
        path = _resolve_virtual_path(state.cwd, target)

        if path in VIRTUAL_FILES:
            content = VIRTUAL_FILES[path]["content"]
            return ShellResult(output=content, cwd=state.cwd, category="file_read", recognized=True)
        elif path in VIRTUAL_EXTRA_FILES:
            return ShellResult(output=VIRTUAL_EXTRA_FILES[path], cwd=state.cwd, category="file_read", recognized=True)
        else:
            return ShellResult(output=f"cat: {target}: No such file or directory", cwd=state.cwd, category="file_read", recognized=False)

    # 2. Controlled Decoy Responses for Common Attacker Tools / Priv Escalation
    if prog in ("wget", "curl", "nc", "ncat", "ping", "ssh", "ftp"):
        return ShellResult(output=f"{prog}: connect: Network is unreachable", cwd=state.cwd, category="tool", recognized=True)

    elif prog in ("sudo", "su"):
        output = "sudo: a password is required" if prog == "sudo" else "su: Authentication failure"
        return ShellResult(output=output, cwd=state.cwd, category="priv", recognized=True)

    elif prog in ("rm", "dd", "mkfs", "chmod", "chown", "shutdown", "reboot", "kill"):
        return ShellResult(output=f"{prog}: Operation not permitted", cwd=state.cwd, category="destructive", recognized=True)

    elif prog in ("python", "python3", "perl", "bash", "sh"):
        return ShellResult(output=f"bash: {prog}: Permission denied", cwd=state.cwd, category="tool", recognized=True)

    elif prog in ("crontab", "ssh-keygen"):
        return ShellResult(output=f"{prog}: Permission denied", cwd=state.cwd, category="persist", recognized=True)

    # 3. Default fallback for unknown commands
    return ShellResult(output=f"bash: {prog}: command not found", cwd=state.cwd, category="unknown", recognized=False)
