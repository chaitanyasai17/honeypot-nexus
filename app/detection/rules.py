"""
Honeypot Nexus - Detection Rules Catalogue
Implements all 10 modular detection rules following the system specification.
"""

from typing import List
from app.detection.base import BaseDetectionRule, Detection, RuleContext
from app.events.schemas import AttackType, Severity
from app.detection.patterns import (
    SQLI_PATTERNS,
    TRAVERSAL_PATTERN,
    SCANNER_UA_PATTERN,
    RECON_PATHS,
    SENSITIVE_FILE_PATTERN,
    SHELL_CMDS,
    normalize_input
)
from app.services.config_service import get_config_value


# 1. R-BF-001: Brute Force Rule
class BruteForceRule(BaseDetectionRule):
    rule_id = "R-BF-001"
    name = "Brute Force Authentication"
    attack_type = AttackType.BRUTE_FORCE
    severity = Severity.HIGH
    points = 20
    stateful = True
    description = "Detects rapid repeated login failures against authentication endpoints."
    mitre = ["T1110"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        if ctx.raw_event.get("event_type") != "login_attempt" or ctx.raw_event.get("status") != "failure":
            return []

        threshold = get_config_value("BF_THRESHOLD", 5)
        window_s = get_config_value("BF_WINDOW_S", 60)
        source_ip = ctx.raw_event.get("source_ip", "")

        fail_count = ctx.windows.count_ip(
            source_ip,
            lambda r: r.event_type == "login_attempt" and r.status == "failure",
            window_s
        )

        if fail_count >= threshold and (fail_count % threshold == 0 or fail_count == threshold):
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Detected {fail_count} failed login attempts from IP within {window_s}s window",
                evidence={"failed_count": fail_count, "window_seconds": window_s, "ip": source_ip}
            )]
        return []


# 2. R-CRED-001: Credential Attack Rule
class CredentialAttackRule(BaseDetectionRule):
    rule_id = "R-CRED-001"
    name = "Credential Attack / Password Spraying"
    attack_type = AttackType.CREDENTIAL_ATTACK
    severity = Severity.HIGH
    points = 20
    stateful = True
    description = "Detects password spraying across multiple usernames or credential stuffing."
    mitre = ["T1110.003"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        if ctx.raw_event.get("event_type") != "login_attempt":
            return []

        source_ip = ctx.raw_event.get("source_ip", "")
        window_s = get_config_value("CRED_WINDOW_S", 120)
        distinct_req = get_config_value("CRED_DISTINCT_USERS", 3)

        distinct_users = ctx.windows.distinct_ip_field(
            source_ip,
            "username",
            lambda r: r.event_type == "login_attempt",
            window_s
        )

        if len(distinct_users) >= distinct_req:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Password spraying pattern: {len(distinct_users)} distinct accounts targeted in {window_s}s",
                evidence={"targeted_users": list(distinct_users)[:10], "window_seconds": window_s}
            )]
        return []


# 3. R-SQLI-001: SQL Injection Rule
class SQLInjectionRule(BaseDetectionRule):
    rule_id = "R-SQLI-001"
    name = "SQL Injection Attempt"
    attack_type = AttackType.SQL_INJECTION
    severity = Severity.HIGH
    points = 30
    stateful = False
    description = "Detects SQL injection signatures across queries, form fields, and URIs."
    mitre = ["T1190"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        candidates = [
            ctx.raw_event.get("payload", ""),
            ctx.raw_event.get("query_string", ""),
            ctx.meta.get("username", ""),
            ctx.meta.get("db_query", ""),
            ctx.transient.get("password", "")
        ]

        matched_subtypes = set()
        matched_sample = ""

        for candidate in candidates:
            if not candidate:
                continue
            norm = normalize_input(candidate)
            for family, pattern in SQLI_PATTERNS.items():
                m = pattern.search(norm)
                if m:
                    matched_subtypes.add(family)
                    if not matched_sample:
                        matched_sample = m.group(0)[:80]

        if matched_subtypes:
            subtypes_str = ", ".join(sorted(matched_subtypes))
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"SQL injection detected matching pattern family: [{subtypes_str}]",
                evidence={"subtypes": list(matched_subtypes), "sample": matched_sample}
            )]
        return []


# 4. R-TRAV-001: Directory Traversal Rule
class DirectoryTraversalRule(BaseDetectionRule):
    rule_id = "R-TRAV-001"
    name = "Directory Traversal / Path Manipulation"
    attack_type = AttackType.DIRECTORY_TRAVERSAL
    severity = Severity.HIGH
    points = 25
    stateful = False
    description = "Detects directory escape sequences, dot-dot-slash patterns and absolute system file accesses."
    mitre = ["T1083"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        candidates = [
            ctx.raw_event.get("endpoint", ""),
            ctx.raw_event.get("payload", ""),
            ctx.raw_event.get("query_string", ""),
            ctx.meta.get("file_path", "")
        ]

        for cand in candidates:
            if not cand:
                continue
            norm = normalize_input(cand)
            m = TRAVERSAL_PATTERN.search(norm)
            if m:
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"Directory traversal sequence detected in request path or parameter: '{m.group(0)[:60]}'",
                    evidence={"match": m.group(0)[:80], "candidate": cand[:120]}
                )]
        return []


# 5. R-SCAN-001: Scanner Detection Rule
class ScannerRule(BaseDetectionRule):
    rule_id = "R-SCAN-001"
    name = "Automated Vulnerability Scanner"
    attack_type = AttackType.SCANNER
    severity = Severity.ELEVATED
    points = 15
    stateful = True
    description = "Identifies automated scanners via User-Agent signatures and rapid bait route probing."
    mitre = ["T1595"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        ua = ctx.raw_event.get("user_agent", "")
        if ua:
            m = SCANNER_UA_PATTERN.search(ua)
            if m:
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"Automated security scanner identified via User-Agent signature: '{m.group(0)}'",
                    evidence={"scanner_signature": m.group(0), "user_agent": ua[:120]}
                )]

        # Check path burst on recon bait
        source_ip = ctx.raw_event.get("source_ip", "")
        burst_threshold = get_config_value("SCAN_PATH_BURST", 6)
        window_s = get_config_value("SCAN_WINDOW_S", 30)

        bait_hits = ctx.windows.count_ip(
            source_ip,
            lambda r: any(r.endpoint.startswith(p) for p in RECON_PATHS),
            window_s
        )

        if bait_hits >= burst_threshold:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Scanner probe burst: {bait_hits} bait paths touched in {window_s}s",
                evidence={"bait_hits": bait_hits, "window_seconds": window_s}
            )]
        return []


# 6. R-RECON-001: Reconnaissance Rule
class ReconRule(BaseDetectionRule):
    rule_id = "R-RECON-001"
    name = "Reconnaissance & Bait Probing"
    attack_type = AttackType.RECONNAISSANCE
    severity = Severity.ELEVATED
    points = 10
    stateful = False
    description = "Detects enumeration of discovery endpoints such as robots.txt, /.git, /.env, and backup directories."
    mitre = ["T1595.003"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        ep = ctx.raw_event.get("endpoint", "").lower()
        for bait in RECON_PATHS:
            if ep == bait or ep.startswith(f"{bait}/"):
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"Reconnaissance probe targeted high-value bait path '{ep}'",
                    evidence={"bait_path": ep}
                )]
        return []


# 7. R-API-001: Suspicious API Rule
class SuspiciousAPIRule(BaseDetectionRule):
    rule_id = "R-API-001"
    name = "Suspicious API Activity & Enumeration"
    attack_type = AttackType.SUSPICIOUS_API
    severity = Severity.ELEVATED
    points = 15
    stateful = True
    description = "Detects unauthorized exploration of administrative API endpoints and mutating methods."
    mitre = ["T1083"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        ep = ctx.raw_event.get("endpoint", "").lower()
        method = ctx.raw_event.get("http_method", "GET").upper()

        if ep.startswith("/api/v1/"):
            sensitive_api_prefixes = ["/api/v1/admin", "/api/v1/config", "/api/v1/backup", "/api/v1/tokens", "/api/v1/system"]
            if any(ep.startswith(p) for p in sensitive_api_prefixes):
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"Sensitive synthetic API endpoint accessed: '{ep}'",
                    evidence={"endpoint": ep, "method": method}
                )]

            if method in ("PUT", "DELETE", "PATCH"):
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"Mutating {method} method attempted on synthetic API endpoint '{ep}'",
                    evidence={"endpoint": ep, "method": method}
                )]

        # Check API enumeration count in window
        source_ip = ctx.raw_event.get("source_ip", "")
        threshold = get_config_value("API_ENUM_DISTINCT", 8)
        window_s = get_config_value("API_ENUM_WINDOW_S", 60)

        distinct_api_eps = ctx.windows.distinct_ip_field(
            source_ip,
            "endpoint",
            lambda r: r.endpoint.startswith("/api"),
            window_s
        )

        if len(distinct_api_eps) >= threshold:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"API Enumeration: {len(distinct_api_eps)} distinct API paths mapped in {window_s}s",
                evidence={"paths_count": len(distinct_api_eps), "window_seconds": window_s}
            )]
        return []


# 8. R-ENUM-001: Automated Enumeration Rule
class AutomatedEnumerationRule(BaseDetectionRule):
    rule_id = "R-ENUM-001"
    name = "Automated Endpoint Enumeration"
    attack_type = AttackType.AUTOMATED_ENUMERATION
    severity = Severity.ELEVATED
    points = 15
    stateful = True
    description = "Detects rapid-fire sequential URL fuzzing and 404 error bursts."
    mitre = ["T1595"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        source_ip = ctx.raw_event.get("source_ip", "")
        req_burst_threshold = get_config_value("ENUM_REQ_BURST", 20)
        req_window_s = get_config_value("ENUM_REQ_WINDOW_S", 10)

        recent_reqs = ctx.windows.count_ip(source_ip, lambda r: True, req_window_s)
        if recent_reqs >= req_burst_threshold:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Automated request rate anomaly: {recent_reqs} requests in {req_window_s}s",
                evidence={"request_rate": recent_reqs, "window_seconds": req_window_s}
            )]

        # 404 burst
        err_threshold = get_config_value("ENUM_404_COUNT", 10)
        err_window_s = get_config_value("ENUM_404_WINDOW_S", 30)
        errors_404 = ctx.windows.count_ip(source_ip, lambda r: r.http_status == 404, err_window_s)
        if errors_404 >= err_threshold:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Automated path fuzzing: {errors_404} 404 Not Found responses generated in {err_window_s}s",
                evidence={"not_found_count": errors_404, "window_seconds": err_window_s}
            )]
        return []


# 9. R-SHELL-001: Shell Reconnaissance Rule
class ShellCommandRule(BaseDetectionRule):
    rule_id = "R-SHELL-001"
    name = "Terminal Shell Reconnaissance"
    attack_type = AttackType.SHELL_RECON
    severity = Severity.ELEVATED
    points = 20
    stateful = True
    description = "Identifies enumeration, tool execution, privilege escalation, or destructive commands in synthetic terminal."
    mitre = ["T1059", "T1087"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        if ctx.raw_event.get("event_type") != "shell_command":
            return []

        cmd = ctx.meta.get("shell_command", "").strip()
        cmd_cat = ctx.meta.get("shell_cmd_category", "unknown")

        if cmd_cat in ("tool", "priv", "destructive", "persist"):
            sev = Severity.HIGH if cmd_cat in ("priv", "destructive") else Severity.ELEVATED
            pts = 25 if cmd_cat in ("priv", "destructive") else 20
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=sev,
                points=pts,
                reason=f"Suspicious synthetic shell command category '{cmd_cat}': '{cmd[:60]}'",
                evidence={"command": cmd, "category": cmd_cat}
            )]

        # Check sequence of recon commands
        source_ip = ctx.raw_event.get("source_ip", "")
        recon_cmds = ctx.windows.count_ip(
            source_ip,
            lambda r: r.event_type == "shell_command",
            60
        )
        if recon_cmds >= 3:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Interactive terminal reconnaissance sequence: {recon_cmds} commands executed",
                evidence={"commands_count": recon_cmds, "last_command": cmd}
            )]

        return []


# 10. R-FILE-001: Sensitive File Rule
class SensitiveFileRule(BaseDetectionRule):
    rule_id = "R-FILE-001"
    name = "Sensitive File Access"
    attack_type = AttackType.SENSITIVE_FILE_ACCESS
    severity = Severity.HIGH
    points = 20
    stateful = False
    description = "Detects access or exfiltration attempts against credential, backup, or key files."
    mitre = ["T1552"]

    def evaluate(self, ctx: RuleContext) -> List[Detection]:
        file_path = ctx.meta.get("file_path", "")
        file_name = ctx.meta.get("file_name", "")
        payload = ctx.raw_event.get("payload", "")

        for target in (file_path, file_name, payload):
            if target and SENSITIVE_FILE_PATTERN.search(target):
                return [Detection(
                    rule_id=self.rule_id,
                    attack_type=self.attack_type,
                    severity=self.severity,
                    points=self.points,
                    reason=f"High-risk synthetic sensitive file target: '{target[:60]}'",
                    evidence={"target": target[:100]}
                )]

        if ctx.meta.get("sensitive") is True:
            return [Detection(
                rule_id=self.rule_id,
                attack_type=self.attack_type,
                severity=self.severity,
                points=self.points,
                reason=f"Protected synthetic resource access flagged sensitive: '{file_name or file_path}'",
                evidence={"file": file_name or file_path}
            )]
        return []
