"""
Honeypot Nexus - Honeypot Request Capture & Event Pipeline Middleware
Captures all visitor interactions on Layer 1 without any DB/ORM dependencies.
"""

import hmac
import hashlib
import ipaddress
import secrets
import time
from typing import Dict, Any, Optional
from flask import request, current_app, make_response
from app.events.schemas import HoneypotEvent, SurfaceType, EventType, EventStatus
from app.events.publisher import EventPublisher


ALLOWED_HEADERS = {
    "host", "referer", "accept", "accept-language",
    "content-type", "content-length", "origin", "x-forwarded-for", "authorization"
}


def resolve_client_ip() -> str:
    """
    Resolves client IP address with local demo header override in DEMO_MODE.
    """
    remote = request.remote_addr or "127.0.0.1"
    is_demo = current_app.config.get("DEMO_MODE", False)

    # Allow X-Demo-Source-IP override ONLY if caller is loopback and DEMO_MODE is true
    if is_demo and remote in ("127.0.0.1", "localhost", "::1"):
        demo_ip = request.headers.get("X-Demo-Source-IP")
        if demo_ip:
            try:
                addr = ipaddress.ip_address(demo_ip)
                # Ensure it is documentation or private range
                doc_ranges = [
                    ipaddress.ip_network("192.0.2.0/24"),
                    ipaddress.ip_network("198.51.100.0/24"),
                    ipaddress.ip_network("203.0.113.0/24"),
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("127.0.0.0/8")
                ]
                if any(addr in net for net in doc_ranges):
                    return demo_ip
            except ValueError:
                pass

    return remote


def get_or_create_session_id() -> str:
    """
    Retrieves or generates attacker session ID.
    Falls back to deterministic hash of IP + User-Agent if cookies are rejected.
    """
    sid = request.cookies.get("hnx_sid")
    if sid and len(sid) >= 16:
        return sid

    # Fallback deterministic fingerprint session
    ip = resolve_client_ip()
    ua = request.headers.get("User-Agent", "none")
    key = current_app.config.get("SECRET_KEY", "fallback_key").encode("utf-8")
    raw_sig = f"{ip}|{ua}".encode("utf-8")
    fp = hmac.new(key, raw_sig, hashlib.sha256).hexdigest()[:20]
    return f"f_{fp}"


def capture_interaction(
    surface: SurfaceType,
    event_type: EventType,
    status: EventStatus = EventStatus.info,
    payload: str = "",
    meta: Optional[Dict[str, Any]] = None,
    transient: Optional[Dict[str, Any]] = None,
    http_status: int = 200
):
    """
    Constructs a HoneypotEvent and publishes it to the EventBus facade.
    Wrapped in try/except to never crash honeypot route responses.
    """
    try:
        publisher: EventPublisher = current_app.extensions.get("event_publisher")
        if not publisher:
            return

        source_ip = resolve_client_ip()
        session_id = get_or_create_session_id()

        # Sanitize allowlisted headers
        headers = {}
        for h_key, h_val in request.headers.items():
            k_lower = h_key.lower()
            if k_lower in ALLOWED_HEADERS:
                if k_lower == "authorization":
                    # Mask authorization header: scheme + first 6 chars
                    parts = h_val.split()
                    scheme = parts[0] if parts else "Bearer"
                    secret_preview = parts[1][:6] if len(parts) > 1 else ""
                    headers[h_key] = f"{scheme} {secret_preview}..."
                else:
                    headers[h_key] = h_val[:256]

        event = HoneypotEvent(
            source_ip=source_ip,
            source_port=request.environ.get("REMOTE_PORT", 0) or 0,
            destination=f"{request.host}",
            endpoint=request.path[:512],
            query_string=request.query_string.decode("utf-8", errors="replace")[:1024],
            http_method=request.method[:16],
            user_agent=request.headers.get("User-Agent", "")[:256],
            session_id=session_id,
            surface=surface,
            event_type=event_type,
            payload=payload[:2048],
            http_status=http_status,
            status=status,
            headers=headers,
            meta=meta or {},
            transient=transient or {},
            is_synthetic=current_app.config.get("DEMO_MODE", False)
        )

        publisher.publish(event)

    except Exception:
        # Never break visitor flow in honeypot
        pass


def attach_session_cookie(response):
    """Attaches signed session cookie if not present."""
    if "hnx_sid" not in request.cookies:
        new_sid = secrets.token_urlsafe(16)
        response.set_cookie(
            "hnx_sid",
            new_sid,
            max_age=1800,
            httponly=True,
            samesite="Lax",
            path="/"
        )
    return response
