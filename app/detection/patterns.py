"""
Honeypot Nexus - Compiled Attack Signatures & Patterns
All regex patterns are pre-compiled and anchored to prevent ReDoS.
"""

import re
import urllib.parse
import unicodedata

# SQL Injection Signatures
SQLI_PATTERNS = {
    "TAUTOLOGY": re.compile(r"('\s*or\s*'?\d+'?\s*=\s*'?\d+|'\s*or\s*''='|\bor\s+1\s*=\s*1\b|\bor\s+'1'\s*=\s*'1')", re.IGNORECASE),
    "UNION": re.compile(r"\bunion(\s+all)?\s+select\b", re.IGNORECASE),
    "BOOLEAN": re.compile(r"(\band\s+\d+\s*=\s*\d+\b|\band\s+1\s*=\s*2\b|'\s*and\s*')", re.IGNORECASE),
    "COMMENT": re.compile(r"(--\s|#|/\*.*?\*/)", re.IGNORECASE),
    "STACKED": re.compile(r";\s*(drop|insert|update|delete|create|alter)\b", re.IGNORECASE),
    "TIME": re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()", re.IGNORECASE),
    "META": re.compile(r"(information_schema|sqlite_master|@@version|load_file\s*\()", re.IGNORECASE),
}

# Directory Traversal Signatures
TRAVERSAL_PATTERN = re.compile(
    r"(\.\.[/\\]|%2e%2e(%2f|%5c)|%252e%252e|....//|%00|/etc/passwd|/etc/shadow|/proc/self|c:\\windows|boot\.ini|win\.ini)",
    re.IGNORECASE
)

# Automated Scanners
SCANNER_UA_PATTERN = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wfuzz|ffuf|feroxbuster|nuclei|acunetix|nessus|openvas|burp|wpscan|whatweb|arachni)",
    re.IGNORECASE
)

# Reconnaissance Bait Paths
RECON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git", "/.env", "/.svn",
    "/server-status", "/phpinfo.php", "/wp-login.php", "/wp-admin",
    "/administrator", "/phpmyadmin", "/backup", "/config", "/old",
    "/dev", "/test", "/internal", "/uploads"
]

# Sensitive File Indicators
SENSITIVE_FILE_PATTERN = re.compile(
    r"(passw|secret|credential|\.pem|\.key|id_rsa|backup|dump|\.env)",
    re.IGNORECASE
)

# Shell Command Categories
SHELL_CMDS = {
    "recon": {"whoami", "id", "uname", "pwd", "ls"},
    "file_read": {"cat"},
    "tool": {"wget", "curl", "nc", "ncat", "python", "python3", "perl", "bash", "sh", "base64", "chmod", "chown"},
    "priv": {"sudo", "su"},
    "destructive": {"rm", "dd", "mkfs", "shutdown", "reboot", "kill"},
    "persist": {"crontab", "ssh-keygen"}
}


def normalize_input(val: str) -> str:
    """Normalizes string inputs to defeat basic encoding evasion techniques."""
    if not val:
        return ""
    # URL decode twice
    try:
        val = urllib.parse.unquote(urllib.parse.unquote(val))
    except Exception:
        pass
    # NFKC Unicode normalization
    val = unicodedata.normalize("NFKC", val)
    # Strip comments used as spaces: e.g. UN/**/ION
    val = re.sub(r"/\*.*?\*/", " ", val)
    # Collapse whitespace and cap length
    val = " ".join(val.split())[:4096]
    return val
