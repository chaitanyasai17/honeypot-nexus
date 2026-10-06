"""
Honeypot Nexus - Deterministic Risk & Engagement Scoring Models
Implements transparent 0-100 mathematical scoring with full component explainability.
"""

from typing import List, Dict, Any, Tuple
from app.detection.base import Detection
from app.services.config_service import get_config_value

# Canonical Attack Weights
RISK_WEIGHTS: Dict[str, int] = {
    "RECONNAISSANCE": 10,
    "SCANNER": 15,
    "AUTOMATED_ENUMERATION": 15,
    "SUSPICIOUS_API": 15,
    "BRUTE_FORCE": 20,
    "CREDENTIAL_ATTACK": 20,
    "SHELL_RECON": 20,
    "SENSITIVE_FILE_ACCESS": 20,
    "DIRECTORY_TRAVERSAL": 25,
    "SQL_INJECTION": 30,
}

SEVERITY_BANDS = [
    (0, 24, "NORMAL"),
    (25, 49, "ELEVATED"),
    (50, 74, "HIGH"),
    (75, 100, "CRITICAL"),
]


def score_to_band(score: int) -> str:
    for low, high, band in SEVERITY_BANDS:
        if low <= score <= high:
            return band
    return "CRITICAL" if score > 100 else "NORMAL"


def calculate_event_risk(detections: List[Detection], session) -> int:
    """Calculates risk score for an individual event (0-100)."""
    score = 5 # Base event interaction
    for d in detections:
        score += d.points

    # Bonus if attack repetition detected
    repeat_threshold = get_config_value("REPEAT_THRESHOLD", 3)
    curr_attacks = session.attack_types_json or {}
    for count in curr_attacks.values():
        if count == repeat_threshold:
            score += 10
            break

    return min(100, score)


def calculate_session_risk(session, current_detections: List[Detection]) -> Tuple[int, List[dict]]:
    """
    Calculates cumulative session risk (0-100).
    Uses distinct attack type weighting to avoid inflation from spam.
    Returns (score, list_of_reasons).
    """
    reasons = []
    score = 5
    reasons.append({"component": "Base Session Interaction", "points": 5, "reason": "Baseline visitor activity"})

    # Combine historical and current attack types
    attack_counts = dict(session.attack_types_json or {})
    for d in current_detections:
        atype = d.attack_type.value if hasattr(d.attack_type, "value") else str(d.attack_type)
        attack_counts[atype] = attack_counts.get(atype, 0) + 1

    # Distinct-type weighting
    for atype in attack_counts.keys():
        if atype in RISK_WEIGHTS:
            pts = RISK_WEIGHTS[atype]
            score += pts
            reasons.append({"component": f"Attack Technique: {atype}", "points": pts, "reason": f"Observed {atype} interaction"})

    # Repetition bonus
    repeat_threshold = get_config_value("REPEAT_THRESHOLD", 3)
    has_repeat = any(count >= repeat_threshold for count in attack_counts.values())
    if has_repeat:
        score += 10
        reasons.append({"component": "Repeated Attack Bonus", "points": 10, "reason": f"Attack type repeated >= {repeat_threshold} times"})

    # High engagement bonus
    bonus_at = get_config_value("ENGAGEMENT_BONUS_AT", 60)
    if (session.engagement_score or 0) >= bonus_at:
        score += 10
        reasons.append({"component": "High Engagement Bonus", "points": 10, "reason": f"Session engagement reached >= {bonus_at}"})

    final_score = min(100, score)
    return final_score, reasons


def calculate_engagement(session, raw_event: dict, meta: dict) -> Tuple[int, List[dict]]:
    """
    Calculates engagement score (0-100) reflecting attacker depth and persistence.
    Returns (score, list_of_reasons).
    """
    score = 0
    reasons = []

    surfaces = set(session.surfaces_json or [])
    endpoints = list(session.endpoints_json or [])
    ev_count = (session.event_count or 0) + 1

    # 1. Login attempt
    if "login" in surfaces or raw_event.get("surface") == "login":
        score += 10
        reasons.append({"component": "Login Attempt", "points": 10, "reason": "Attacker engaged authentication surface"})

    # 2. Admin interaction
    if "admin" in surfaces or raw_event.get("surface") == "admin":
        score += 15
        admin_actions = sum(1 for ep in endpoints if ep.startswith("/admin"))
        action_bonus = min(10, admin_actions * 2)
        score += action_bonus
        reasons.append({"component": "Admin Console Access", "points": 15 + action_bonus, "reason": "Explored administrative surfaces"})

    # 3. API enumeration
    api_paths = sum(1 for ep in endpoints if ep.startswith("/api"))
    if api_paths >= 8:
        score += 15
        reasons.append({"component": "Deep API Enumeration", "points": 15, "reason": "Mapped >= 8 distinct API paths"})
    elif api_paths >= 3:
        score += 10
        reasons.append({"component": "API Enumeration", "points": 10, "reason": "Mapped >= 3 API endpoints"})

    # 4. File browsing & sensitive files
    if "files" in surfaces or raw_event.get("surface") == "files":
        score += 10
        reasons.append({"component": "File System Exploration", "points": 10, "reason": "Navigated synthetic file hierarchy"})

    if meta.get("sensitive") is True or "SENSITIVE_FILE_ACCESS" in (session.attack_types_json or {}):
        score += 15
        reasons.append({"component": "Sensitive File Target", "points": 15, "reason": "Targeted confidential files or backups"})

    # 5. Database interaction
    if "database" in surfaces or raw_event.get("surface") == "database":
        db_queries = sum(1 for ep in endpoints if ep.startswith("/database"))
        bonus = min(10, db_queries * 2)
        score += (10 + bonus)
        reasons.append({"component": "Database Telemetry Query", "points": 10 + bonus, "reason": "Queried database viewer interface"})

    # 6. Shell interaction
    if "shell" in surfaces or raw_event.get("surface") == "shell":
        score += 15
        reasons.append({"component": "Interactive Shell Access", "points": 15, "reason": "Interacted with controlled terminal"})

    # 7. Multiple surfaces touched
    if len(surfaces) > 1:
        surf_bonus = min(15, (len(surfaces) - 1) * 5)
        score += surf_bonus
        reasons.append({"component": "Multi-Surface Exploration", "points": surf_bonus, "reason": f"Visited {len(surfaces)} deception surfaces"})

    # 8. Request count & duration tiers
    if ev_count >= 30:
        score += 10
        reasons.append({"component": "High Volume Persistence", "points": 10, "reason": "Generated >= 30 events in session"})
    elif ev_count >= 10:
        score += 5
        reasons.append({"component": "Activity Volume", "points": 5, "reason": "Generated >= 10 events in session"})

    final_score = min(100, score)
    return final_score, reasons
