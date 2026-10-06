"""
Honeypot Nexus - Audit Logging Service
Records immutable audit trail of administrator and security actions.
"""

from typing import Dict, Any, Optional
from flask import request, g
from app.models.models import AuditLog, utc_now
from app.extensions import db
from app.logging_config import get_logger

audit_file_logger = get_logger("audit")


def audit_log(
    action: str,
    target: str,
    outcome: str = "success",
    detail: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip: Optional[str] = None
):
    """Logs security audit entry to database and audit log file."""
    try:
        user = getattr(g, "current_user", None)
        uid = user_id or (user.id if user else None)
        uname = username or (user.username if user else "anonymous")
        client_ip = ip or (request.remote_addr if request else "127.0.0.1")

        sanitized_detail = {k: v for k, v in (detail or {}).items() if "password" not in k.lower() and "secret" not in k.lower()}

        log_entry = AuditLog(
            timestamp=utc_now(),
            user_id=uid,
            username=uname,
            action=action,
            target=target,
            ip=client_ip,
            detail_json=sanitized_detail,
            outcome=outcome
        )
        db.session.add(log_entry)
        db.session.commit()

        audit_file_logger.info(
            f"AUDIT: action={action} target={target} outcome={outcome} user={uname} ip={client_ip}",
            extra={"extra_data": sanitized_detail}
        )
    except Exception as e:
        db.session.rollback()
