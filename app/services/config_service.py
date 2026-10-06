"""
Honeypot Nexus - Configuration Service
Manages honeypot_config dynamic parameters, rule toggles, and seeding.
"""

from app.models.models import HoneypotConfig
from app.extensions import db

DEFAULT_CONFIGS = {
    "BF_THRESHOLD": ("5", "int", "Failed logins in window to trigger Brute Force rule"),
    "BF_WINDOW_S": ("60", "int", "Window in seconds for Brute Force detection"),
    "CRED_DISTINCT_USERS": ("3", "int", "Distinct usernames targeted before Credential Attack triggers"),
    "CRED_WINDOW_S": ("120", "int", "Window in seconds for Credential Attack detection"),
    "SCAN_PATH_BURST": ("6", "int", "Distinct bait paths accessed in burst to trigger Scanner rule"),
    "SCAN_WINDOW_S": ("30", "int", "Window in seconds for Scanner path burst"),
    "API_ENUM_DISTINCT": ("8", "int", "Distinct API endpoints accessed before API enum triggers"),
    "API_ENUM_WINDOW_S": ("60", "int", "Window in seconds for API enumeration detection"),
    "ENUM_REQ_BURST": ("20", "int", "Rapid request count in window for automated enum"),
    "ENUM_REQ_WINDOW_S": ("10", "int", "Window in seconds for automated enum request burst"),
    "ENUM_404_COUNT": ("10", "int", "Distinct 404 count in window"),
    "ENUM_404_WINDOW_S": ("30", "int", "Window in seconds for 404 burst"),
    "REPEAT_THRESHOLD": ("3", "int", "Attack repetition threshold for risk bonus points"),
    "ENGAGEMENT_BONUS_AT": ("60", "int", "Session engagement score threshold for risk bonus"),
    "ALERT_COOLDOWN_S": ("120", "int", "Cooldown window in seconds to coalesce duplicate alerts"),
    "THREAT_WINDOW_MIN": ("15", "int", "Rolling window in minutes for Threat Pulse score"),
    "SESSION_IDLE_S": ("300", "int", "Inactivity seconds before marking attacker session idle"),
    "SESSION_CLOSE_S": ("1800", "int", "Inactivity seconds before closing attacker session"),
    # Default rule toggles
    "rule.R-BF-001.enabled": ("true", "bool", "Brute Force Rule active status"),
    "rule.R-CRED-001.enabled": ("true", "bool", "Credential Attack Rule active status"),
    "rule.R-SQLI-001.enabled": ("true", "bool", "SQL Injection Rule active status"),
    "rule.R-TRAV-001.enabled": ("true", "bool", "Directory Traversal Rule active status"),
    "rule.R-SCAN-001.enabled": ("true", "bool", "Scanner Detection Rule active status"),
    "rule.R-RECON-001.enabled": ("true", "bool", "Reconnaissance Rule active status"),
    "rule.R-API-001.enabled": ("true", "bool", "Suspicious API Rule active status"),
    "rule.R-ENUM-001.enabled": ("true", "bool", "Automated Enumeration Rule active status"),
    "rule.R-SHELL-001.enabled": ("true", "bool", "Shell Reconnaissance Rule active status"),
    "rule.R-FILE-001.enabled": ("true", "bool", "Sensitive File Rule active status"),
}


def seed_default_configs():
    """Seeds default configurations idempotently."""
    changed = False
    for key, (val, vtype, desc) in DEFAULT_CONFIGS.items():
        existing = HoneypotConfig.query.filter_by(key=key).first()
        if not existing:
            cfg = HoneypotConfig(
                key=key,
                value=val,
                value_type=vtype,
                description=desc
            )
            db.session.add(cfg)
            changed = True
    if changed:
        db.session.commit()


def get_config_value(key: str, default=None):
    """Retrieves a configuration value cast to its type, with fallback outside app context."""
    from flask import has_app_context
    if not has_app_context():
        if key in DEFAULT_CONFIGS:
            val, vtype, _ = DEFAULT_CONFIGS[key]
            if vtype == "int": return int(val)
            elif vtype == "float": return float(val)
            elif vtype == "bool": return val.lower() in ("true", "1", "yes")
            return val
        return default

    cfg = HoneypotConfig.query.filter_by(key=key).first()
    if not cfg:
        if key in DEFAULT_CONFIGS:
            val, vtype, _ = DEFAULT_CONFIGS[key]
        else:
            return default
    else:
        val, vtype = cfg.value, cfg.value_type

    if vtype == "int":
        return int(val)
    elif vtype == "float":
        return float(val)
    elif vtype == "bool":
        return val.lower() in ("true", "1", "yes")
    return val


def set_config_value(key: str, value, user_id=None):
    """Sets a configuration value."""
    cfg = HoneypotConfig.query.filter_by(key=key).first()
    if not cfg:
        vtype = "string"
        if isinstance(value, bool):
            vtype = "bool"
        elif isinstance(value, int):
            vtype = "int"
        elif isinstance(value, float):
            vtype = "float"
        cfg = HoneypotConfig(key=key, value=str(value), value_type=vtype, updated_by=user_id)
        db.session.add(cfg)
    else:
        cfg.value = str(value).lower() if cfg.value_type == "bool" else str(value)
        cfg.updated_by = user_id
    db.session.commit()
