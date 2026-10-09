"""
Honeypot Nexus - Application-Level Attack Prevention Service
Implements:
1. Thread-safe in-memory temporary IP block store with DB persistence.
2. Account and IP-based brute-force tracking and temporary lockout.
3. Automated prevention policy evaluation integrating with detection engine.
4. Whitelist protection for administrative loopback access.
"""

from datetime import datetime, timezone, timedelta
import ipaddress
import threading
from typing import Dict, List, Optional, Tuple, Any

from flask import current_app, has_app_context
from app.models.models import BlockedIP, utc_now
from app.extensions import db
from app.config import Config
from app.services.audit_service import audit_log
from app.logging_config import get_logger

logger = get_logger("app")


def _normalize_dt(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is naive UTC for consistent comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _has_db_context() -> bool:
    """Checks if current context has active database access."""
    if not has_app_context():
        return False
    try:
        return "sqlalchemy" in current_app.extensions
    except Exception:
        return False


class PreventionService:
    """Thread-safe centralized prevention manager."""

    def __init__(self):
        self._lock = threading.RLock()
        # In-memory active blocks: ip -> dict
        self._active_blocks: Dict[str, dict] = {}
        # In-memory brute force tracker: key -> dict
        self._failed_logins: Dict[str, dict] = {}
        # In-memory rate limit violations tracker (for dashboard reporting)
        self._rate_limit_events: List[dict] = []

    def reset_state(self):
        """Resets all in-memory tracking structures (for testing)."""
        with self._lock:
            self._active_blocks.clear()
            self._failed_logins.clear()
            self._rate_limit_events.clear()


    def is_whitelisted(self, ip: str) -> bool:
        """Determines if IP is whitelisted and immune from blocking."""
        if not ip:
            return False
        clean_ip = ip.strip()
        # Always whitelist loopback and localhost
        if clean_ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            return True
        whitelist = getattr(Config, "IP_WHITELIST", ["127.0.0.1", "::1", "localhost"])
        if clean_ip in whitelist:
            return True
        try:
            addr = ipaddress.ip_address(clean_ip)
            if addr.is_loopback:
                return True
        except ValueError:
            pass
        return False

    # -------------------------------------------------------------
    # 1. Temporary Application-Level IP Blocking
    # -------------------------------------------------------------
    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Fast thread-safe check if an IP is currently blocked.
        Auto-expires expired blocks seamlessly.
        """
        if not ip or self.is_whitelisted(ip):
            return False, None

        clean_ip = ip.strip()
        with self._lock:
            block = self._active_blocks.get(clean_ip)
            if not block:
                return False, None

            now = utc_now()
            expires_at = _normalize_dt(block.get("expires_at"))
            if expires_at and now > expires_at:
                # Expired: remove from in-memory cache
                del self._active_blocks[clean_ip]
                # Sync expiration in DB if app context available
                if _has_db_context():
                    try:
                        db_block = BlockedIP.query.filter_by(ip=clean_ip, is_active=True).first()
                        if db_block:
                            db_block.is_active = False
                            db.session.commit()
                    except Exception:
                        pass
                return False, None

            return True, block.get("reason", "Malicious activity detected")

    def block_ip(
        self,
        ip: str,
        reason: str,
        duration_minutes: Optional[int] = None,
        blocked_by: str = "system",
        event_id: Optional[str] = None
    ) -> Optional[dict]:
        """
        Applies a temporary application-level block to an IP.
        Persists to database and updates in-memory cache.
        """
        if not ip:
            return None

        clean_ip = ip.strip()
        if self.is_whitelisted(clean_ip):
            logger.warning(f"Prevented blocking whitelisted/loopback IP: {clean_ip}")
            return None

        # Validate IP format
        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            logger.error(f"Invalid IP address format for block: {clean_ip}")
            raise ValueError(f"Invalid IP address format: {clean_ip}")

        if duration_minutes is None:
            duration_minutes = getattr(Config, "DEFAULT_BLOCK_DURATION_MINUTES", 30)

        now = utc_now()
        expires_at = now + timedelta(minutes=duration_minutes)

        block_data = {
            "ip": clean_ip,
            "reason": reason[:256],
            "created_at": now,
            "expires_at": expires_at,
            "blocked_by": blocked_by[:64],
            "event_id": event_id,
            "duration_minutes": duration_minutes
        }

        with self._lock:
            self._active_blocks[clean_ip] = block_data

        # Persist to database if in application context
        if _has_db_context():
            try:
                existing = BlockedIP.query.filter_by(ip=clean_ip, is_active=True).first()
                if existing:
                    existing.reason = reason[:256]
                    existing.expires_at = expires_at
                    existing.blocked_by = blocked_by[:64]
                    existing.event_id = event_id
                else:
                    new_block = BlockedIP(
                        ip=clean_ip,
                        reason=reason[:256],
                        created_at=now,
                        expires_at=expires_at,
                        blocked_by=blocked_by[:64],
                        event_id=event_id,
                        is_active=True
                    )
                    db.session.add(new_block)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Could not persist BlockedIP to database: {e}")

            try:
                audit_log(
                    action="prevention.ip_blocked",
                    target=clean_ip,
                    outcome="success",
                    detail={
                        "reason": reason,
                        "duration_minutes": duration_minutes,
                        "blocked_by": blocked_by,
                        "expires_at": expires_at.isoformat()
                    }
                )
            except Exception:
                pass
        logger.info(f"[PREVENTION] IP blocked: {clean_ip} for {duration_minutes}m (reason: {reason})")
        return block_data

    def unblock_ip(
        self,
        ip: str,
        unblocked_by: str = "admin",
        reason: str = "manual_unblock"
    ) -> bool:
        """Removes temporary block from an IP and records audit record."""
        if not ip:
            return False

        clean_ip = ip.strip()
        was_in_cache = False

        with self._lock:
            if clean_ip in self._active_blocks:
                del self._active_blocks[clean_ip]
                was_in_cache = True

        db_updated = False
        if _has_db_context():
            try:
                records = BlockedIP.query.filter_by(ip=clean_ip, is_active=True).all()
                for r in records:
                    r.is_active = False
                    r.unblocked_at = utc_now()
                    r.unblock_reason = reason[:256]
                    r.unblocked_by = unblocked_by[:64]
                    db_updated = True
                db.session.commit()
            except Exception as e:
                logger.warning(f"Could not update BlockedIP unblock in database: {e}")

            try:
                audit_log(
                    action="prevention.ip_unblocked",
                    target=clean_ip,
                    outcome="success",
                    detail={"unblocked_by": unblocked_by, "reason": reason}
                )
            except Exception:
                pass
        logger.info(f"[PREVENTION] IP unblocked: {clean_ip} by {unblocked_by} (reason: {reason})")
        return was_in_cache or db_updated

    def load_active_blocks_from_db(self):
        """Loads non-expired active blocks into in-memory cache on app startup."""
        try:
            now = utc_now()
            records = BlockedIP.query.filter_by(is_active=True).all()
            loaded = 0
            with self._lock:
                for r in records:
                    exp = r.expires_at
                    if exp and exp.tzinfo is not None:
                        exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
                    if exp and exp > now:
                        self._active_blocks[r.ip] = {
                            "ip": r.ip,
                            "reason": r.reason,
                            "created_at": r.created_at,
                            "expires_at": exp,
                            "blocked_by": r.blocked_by,
                            "event_id": r.event_id
                        }
                        loaded += 1
                    else:
                        r.is_active = False
                db.session.commit()
            logger.info(f"[PREVENTION] Loaded {loaded} active IP blocks from database into cache.")
        except Exception as e:
            logger.warning(f"[PREVENTION] Error loading blocks from DB: {e}")

    def get_active_blocks(self) -> List[dict]:
        """Returns list of currently active blocks with time remaining."""
        now = utc_now()
        active = []
        with self._lock:
            # Clean expired on read
            to_remove = []
            for ip, data in self._active_blocks.items():
                exp = data.get("expires_at")
                if exp and now > exp:
                    to_remove.append(ip)
                else:
                    rem_sec = int((exp - now).total_seconds()) if exp else 0
                    active.append({
                        "ip": ip,
                        "reason": data.get("reason"),
                        "created_at": data.get("created_at").isoformat() if data.get("created_at") else "",
                        "expires_at": exp.isoformat() if exp else "",
                        "blocked_by": data.get("blocked_by"),
                        "remaining_seconds": max(0, rem_sec),
                        "remaining_minutes": max(0, rem_sec // 60)
                    })
            for ip in to_remove:
                del self._active_blocks[ip]

        # Sort newest first
        active.sort(key=lambda x: x["created_at"], reverse=True)
        return active

    def get_all_blocks(self, page: int = 1, per_page: int = 20) -> dict:
        """Returns paginated history of all blocks from database."""
        now = utc_now()
        try:
            pagination = BlockedIP.query.order_by(BlockedIP.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )
            items = []
            for r in pagination.items:
                exp = r.expires_at
                is_active = r.is_active and (exp > now if exp else False)
                rem_sec = int((exp - now).total_seconds()) if (exp and is_active) else 0
                items.append({
                    "id": r.id,
                    "ip": r.ip,
                    "reason": r.reason,
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                    "expires_at": exp.isoformat() if exp else "",
                    "blocked_by": r.blocked_by,
                    "is_active": is_active,
                    "remaining_seconds": max(0, rem_sec),
                    "unblocked_at": r.unblocked_at.isoformat() if r.unblocked_at else None,
                    "unblocked_by": r.unblocked_by,
                    "unblock_reason": r.unblock_reason
                })
            return {
                "items": items,
                "total": pagination.total,
                "pages": pagination.pages,
                "current_page": pagination.page
            }
        except Exception as e:
            logger.warning(f"Error fetching paginated blocks: {e}")
            return {"items": [], "total": 0, "pages": 1, "current_page": 1}

    # -------------------------------------------------------------
    # 2. Brute-Force Protection & Account Lockout
    # -------------------------------------------------------------
    def is_login_locked(self, ip: str, username: str) -> Tuple[bool, Optional[datetime]]:
        """
        Checks if login attempts are currently locked for (ip + username) OR ip.
        Auto-expires expired lockouts.
        """
        now = utc_now()
        user_key = f"{ip}:{username.lower()}"
        ip_key = f"ip:{ip}"

        with self._lock:
            for key in (user_key, ip_key):
                entry = self._failed_logins.get(key)
                if entry and entry.get("locked_until"):
                    lock_time = _normalize_dt(entry["locked_until"])
                    if now < lock_time:
                        return True, lock_time
                    else:
                        # Lockout has expired: reset entry
                        entry["count"] = 0
                        entry["locked_until"] = None

        return False, None

    def record_login_failure(
        self,
        ip: str,
        username: str
    ) -> Tuple[bool, int, Optional[datetime]]:
        """
        Tracks a failed login attempt for (ip + username) and (ip).
        Triggers temporary lockout if threshold is exceeded.
        """
        now = utc_now()
        user_key = f"{ip}:{username.lower()}"
        ip_key = f"ip:{ip}"

        user_threshold = getattr(Config, "AUTH_LOCKOUT_THRESHOLD", 5)
        ip_threshold = getattr(Config, "AUTH_IP_FAIL_THRESHOLD", 10)
        lockout_duration = getattr(Config, "AUTH_LOCKOUT_DURATION_MINUTES", 15)

        is_locked = False
        locked_until = None
        count_val = 0

        with self._lock:
            for key, thresh in ((user_key, user_threshold), (ip_key, ip_threshold)):
                entry = self._failed_logins.setdefault(key, {"count": 0, "last_attempt": now, "locked_until": None})
                entry["count"] += 1
                entry["last_attempt"] = now
                count_val = max(count_val, entry["count"])

                if entry["count"] >= thresh and not entry.get("locked_until"):
                    locked_until = now + timedelta(minutes=lockout_duration)
                    entry["locked_until"] = locked_until
                    is_locked = True

        if is_locked and locked_until:
            audit_log(
                action="auth.lockout",
                target=username or ip,
                outcome="locked",
                detail={
                    "ip": ip,
                    "username": username,
                    "failed_count": count_val,
                    "lockout_until": locked_until.isoformat(),
                    "duration_minutes": lockout_duration
                }
            )
            logger.warning(f"[PREVENTION] Login lockout applied for {ip} / {username} until {locked_until.isoformat()}")

        return is_locked, count_val, locked_until

    def record_login_success(self, ip: str, username: str):
        """Resets failed login counters upon successful authentication."""
        user_key = f"{ip}:{username.lower()}"
        ip_key = f"ip:{ip}"
        with self._lock:
            if user_key in self._failed_logins:
                del self._failed_logins[user_key]
            if ip_key in self._failed_logins:
                del self._failed_logins[ip_key]

    def get_active_lockouts(self) -> List[dict]:
        """Returns currently active lockouts with remaining time."""
        now = utc_now()
        lockouts = []
        with self._lock:
            for key, entry in list(self._failed_logins.items()):
                locked_until = _normalize_dt(entry.get("locked_until"))
                if locked_until:
                    if now < locked_until:
                        rem_sec = int((locked_until - now).total_seconds())
                        lockouts.append({
                            "key": key,
                            "failed_attempts": entry.get("count", 0),
                            "locked_until": locked_until.isoformat(),
                            "remaining_seconds": rem_sec,
                            "remaining_minutes": max(1, rem_sec // 60)
                        })
                    else:
                        del self._failed_logins[key]
        return lockouts

    # -------------------------------------------------------------
    # 3. Rate-Limit Telemetry Recording
    # -------------------------------------------------------------
    def record_rate_limit(self, ip: str, endpoint: str, limit_desc: str = ""):
        """Records a rate limit breach for security reporting."""
        entry = {
            "timestamp": utc_now().isoformat(),
            "ip": ip,
            "endpoint": endpoint,
            "limit": limit_desc
        }
        with self._lock:
            self._rate_limit_events.append(entry)
            if len(self._rate_limit_events) > 200:
                self._rate_limit_events.pop(0)

    def get_recent_rate_limits(self, limit: int = 50) -> List[dict]:
        """Returns recent rate limit breaches."""
        with self._lock:
            return list(reversed(self._rate_limit_events[-limit:]))

    # -------------------------------------------------------------
    # 4. Automated Prevention Policy Evaluation
    # -------------------------------------------------------------
    def evaluate_event_for_prevention(
        self,
        event_model,
        session,
        detections: List[Any]
    ) -> Optional[dict]:
        """
        Evaluates detection results against explicit prevention policies:
        - Never blocks purely on benign reconnaissance.
        - Avoids blocking trusted/loopback administrative IPs.
        - Triggers block for repeated high-severity attacks or critical risk.
        """
        if not getattr(Config, "AUTO_BLOCK_ENABLED", True):
            return None

        source_ip = event_model.source_ip
        if self.is_whitelisted(source_ip):
            return None

        # Already blocked? Skip
        is_already_blocked, _ = self.is_blocked(source_ip)
        if is_already_blocked:
            return None

        risk_threshold = getattr(Config, "AUTO_BLOCK_RISK_THRESHOLD", 85)
        attack_count_threshold = getattr(Config, "AUTO_BLOCK_ATTACK_COUNT", 6)
        block_duration = getattr(Config, "DEFAULT_BLOCK_DURATION_MINUTES", 30)

        severe_attack_types = {
            "SQL_INJECTION",
            "DIRECTORY_TRAVERSAL",
            "SHELL_RECON",
            "BRUTE_FORCE",
            "CREDENTIAL_ATTACK",
            "SENSITIVE_FILE_ACCESS"
        }

        # Rule 1: High-confidence severe attack exceeding risk threshold
        if session.risk_score >= risk_threshold:
            has_severe = any(
                (d.attack_type.value if hasattr(d.attack_type, "value") else str(d.attack_type)) in severe_attack_types
                for d in detections
            )
            if has_severe:
                reason = f"Automated Policy: Critical threat risk ({session.risk_score}/100) with severe attack patterns"
                return self.block_ip(
                    ip=source_ip,
                    reason=reason,
                    duration_minutes=block_duration,
                    blocked_by="auto_prevention",
                    event_id=event_model.event_id
                )

        # Rule 2: Repeated aggressive attack volume exceeding threshold
        if session.event_count >= attack_count_threshold and session.risk_score >= 60:
            attack_types_present = set(session.attack_types_json.keys()) if hasattr(session, "attack_types_json") else set()
            if attack_types_present.intersection(severe_attack_types):
                reason = f"Automated Policy: Sustained attack volume ({session.event_count} events) with malicious payload intent"
                return self.block_ip(
                    ip=source_ip,
                    reason=reason,
                    duration_minutes=block_duration,
                    blocked_by="auto_prevention",
                    event_id=event_model.event_id
                )

        # Rule 3: Repeated Brute Force Rule Trigger
        for d in detections:
            rule_id = getattr(d, "rule_id", "")
            if rule_id == "R-BF-001":
                fail_count = d.evidence.get("failed_count", 0) if hasattr(d, "evidence") and isinstance(d.evidence, dict) else 0
                if fail_count >= getattr(Config, "AUTH_LOCKOUT_THRESHOLD", 5) * 2:
                    reason = f"Automated Policy: High-intensity brute-force authentication attack ({fail_count} failed attempts)"
                    return self.block_ip(
                        ip=source_ip,
                        reason=reason,
                        duration_minutes=block_duration,
                        blocked_by="auto_prevention",
                        event_id=event_model.event_id
                    )

        return None


# Global singleton instance
_prevention_instance: Optional[PreventionService] = None

def get_prevention_service() -> PreventionService:
    """Returns singleton instance of PreventionService."""
    global _prevention_instance
    if _prevention_instance is None:
        _prevention_instance = PreventionService()
    return _prevention_instance
