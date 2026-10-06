"""
Honeypot Nexus - Authentication & Security Primitives
Implements Argon2id hashing, lockout logic, admin session tracking, and RBAC decorators.
"""

from functools import wraps
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import request, session, redirect, url_for, g, current_app

from app.models.models import User, AdminSession, utc_now
from app.extensions import db
from app.errors import ApiError
from app.services.audit_service import audit_log

hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

ROLE_HIERARCHY = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3
}


def hash_password(password: str) -> str:
    """Hashes password with Argon2id."""
    return hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifies password using Argon2id with constant-time characteristics."""
    try:
        return hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def create_admin_session(user: User, request_obj) -> str:
    """Generates random 256-bit token, stores its SHA-256 in DB, and returns token."""
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    timeout_min = current_app.config.get("SESSION_TIMEOUT", 30)
    expires = utc_now() + timedelta(minutes=timeout_min)

    admin_sess = AdminSession(
        id=token_hash,
        user_id=user.id,
        ip=request_obj.remote_addr or "127.0.0.1",
        user_agent=request_obj.headers.get("User-Agent", "")[:256],
        created_at=utc_now(),
        last_seen=utc_now(),
        expires_at=expires
    )
    db.session.add(admin_sess)
    db.session.commit()
    return raw_token


def get_authenticated_user() -> User | None:
    """Validates session token cookie against admin_sessions table."""
    token = session.get("soc_token")
    if not token:
        return None

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    admin_sess = AdminSession.query.filter_by(id=token_hash).first()

    if not admin_sess or admin_sess.revoked_at is not None:
        return None

    # Check expiration
    expires = admin_sess.expires_at
    if expires.tzinfo is not None:
        expires = expires.astimezone(timezone.utc).replace(tzinfo=None)
    if expires < utc_now():
        return None

    # Update sliding window expiration
    timeout_min = current_app.config.get("SESSION_TIMEOUT", 30)
    admin_sess.last_seen = utc_now()
    admin_sess.expires_at = utc_now() + timedelta(minutes=timeout_min)
    db.session.commit()

    return admin_sess.user


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_authenticated_user()
        if not user:
            if request.path.startswith("/api/") or request.is_json:
                raise ApiError("unauthenticated", "Authentication required for SOC access", 401)
            return redirect(url_for("auth.login_view", next=request.path))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function


def role_required(min_role: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None) or get_authenticated_user()
            if not user:
                if request.path.startswith("/api/") or request.is_json:
                    raise ApiError("unauthenticated", "Authentication required", 401)
                return redirect(url_for("auth.login_view", next=request.path))

            user_level = ROLE_HIERARCHY.get(user.role, 0)
            required_level = ROLE_HIERARCHY.get(min_role, 0)

            if user_level < required_level:
                if request.path.startswith("/api/") or request.is_json:
                    raise ApiError("forbidden", f"Role '{min_role}' required", 403)
                raise ApiError("forbidden", f"Insufficient role privileges. Role '{min_role}' required.", 403)

            g.current_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator
