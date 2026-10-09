"""
Honeypot Nexus - Application Factories
Implements strict two-layer isolation:
- create_soc_app: Trusted Private SOC Dashboard, REST API, DB, SocketIO, EventBus
- create_honeypot_app: Untrusted Public Honeypot, NO DB, NO models, publishes via facade only
"""

import os
from pathlib import Path
from flask import Flask, jsonify, request, g
from app.config import Config, BASE_DIR, INSTANCE_DIR
from app.logging_config import configure_logging, get_logger
from app.errors import register_error_handlers
from app.extensions import db, socketio, limiter, csrf, migrate

logger = get_logger("app")


def create_soc_app(config_class=Config):
    """Creates the trusted Private SOC Dashboard application."""
    config_class.validate()
    configure_logging(INSTANCE_DIR / "logs", config_class.LOG_LEVEL)

    app = Flask(
        __name__,
        instance_path=str(INSTANCE_DIR),
        template_folder=str(BASE_DIR / "app" / "templates"),
        static_folder=str(BASE_DIR / "app" / "static")
    )
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    # Register error handlers
    register_error_handlers(app)

    # Register Jinja Timezone Filters (Asia/Kolkata / IST)
    from app.utils.timezone import format_ist, format_ist_time, format_ist_full, to_utc_iso
    app.jinja_env.filters["ist"] = format_ist_full
    app.jinja_env.filters["ist_time"] = format_ist_time
    app.jinja_env.filters["to_iso"] = to_utc_iso

    # Security Headers Hook
    @app.after_request
    def set_soc_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://server.arcgisonline.com https://services.arcgisonline.com https://*.arcgisonline.com https://*.basemaps.cartocdn.com https://basemaps.cartocdn.com https://api.maptiler.com https://*.maptiler.com; "
            "font-src 'self'; "
            "connect-src 'self' wss: https: ws://127.0.0.1:5000 ws://localhost:5000 http://127.0.0.1:5000 https://api.maptiler.com https://*.maptiler.com; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

    # Reverse proxy handling on Render
    if getattr(config_class, "TRUST_PROXY_HOPS", 0) > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config_class.TRUST_PROXY_HOPS, x_proto=1, x_host=1)

    # Attach prevention service
    from app.services.prevention_service import get_prevention_service
    app.extensions["prevention_service"] = get_prevention_service()

    # SOC Rate Limit (429) Handler
    @app.errorhandler(429)
    def soc_rate_limit_handler(e):
        client_ip = request.remote_addr or "127.0.0.1"
        from app.services.audit_service import audit_log
        audit_log("auth.rate_limited", client_ip, "denied", {
            "path": request.path,
            "limit": str(getattr(e, "description", "Rate limit exceeded"))
        })
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"error": "rate_limited", "message": "Too many requests. Please retry later."}), 429
        return jsonify({"error": "rate_limited", "message": "Rate limit exceeded. Please wait before retrying."}), 429

    # Health check route
    @app.route("/healthz")
    @limiter.exempt
    def healthz():
        return jsonify({"status": "ok", "app": "Honeypot Nexus SOC"}), 200

    # Auto-redirect root on port 5000 to /dashboard/
    @app.route("/")
    def index_redirect():
        from flask import redirect
        return redirect("/dashboard/")

    # Register SOC blueprints
    from app.auth.routes import auth_bp
    from app.dashboard.api import api_soc_bp
    from app.dashboard.routes import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_soc_bp)
    app.register_blueprint(dashboard_bp)

    return app


def create_honeypot_app(config_class=Config, publisher=None, prevention_service=None):
    """Creates the untrusted Public Web Honeypot application."""
    from flask import Response
    # Honeypot app must NOT have DB uri or DB configs
    app = Flask(
        "honeypot_nexus_honeypot",
        template_folder=str(BASE_DIR / "app" / "honeypot" / "templates"),
        static_folder=str(BASE_DIR / "app" / "honeypot" / "static" / "honeypot")
    )

    # Set honeypot-specific minimal configuration
    app.config["SECRET_KEY"] = config_class.SECRET_KEY
    app.config["TESTING"] = config_class.TESTING
    app.config["DEMO_MODE"] = config_class.DEMO_MODE
    app.config["MAX_CONTENT_LENGTH"] = getattr(config_class, "MAX_CONTENT_LENGTH", 64 * 1024)
    app.config["HONEYPOT_RESPONSE_JITTER_MS"] = config_class.HONEYPOT_RESPONSE_JITTER_MS
    app.config["RATELIMIT_ENABLED"] = getattr(config_class, "RATELIMIT_ENABLED", True)

    # Inject publisher facade into app extension dict
    from app.events.publisher import NullPublisher
    app.extensions["event_publisher"] = publisher or NullPublisher()

    # Inject prevention service into app extension dict
    from app.services.prevention_service import get_prevention_service
    app.extensions["prevention_service"] = prevention_service or get_prevention_service()

    # Reverse proxy handling on Render
    if getattr(config_class, "TRUST_PROXY_HOPS", 0) > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config_class.TRUST_PROXY_HOPS, x_proto=1, x_host=1)

    # Attach limiter to honeypot app
    limiter.init_app(app)

    # Honeypot Request Prevention Interceptor Hook
    @app.before_request
    def honeypot_prevention_filter():
        # 1. Payload size protection
        max_bytes = app.config.get("MAX_CONTENT_LENGTH", 64 * 1024)
        if request.content_length and request.content_length > max_bytes:
            from app.honeypot.capture import capture_interaction
            from app.events.schemas import SurfaceType, EventType, EventStatus
            capture_interaction(
                surface=SurfaceType.web,
                event_type=EventType.payload_oversized,
                status=EventStatus.denied,
                payload=f"Payload size {request.content_length} bytes exceeds maximum limit {max_bytes} bytes",
                http_status=413
            )
            return Response("413 Payload Too Large - Request entity exceeds maximum permitted size.", status=413, mimetype="text/plain")

        # 2. Temporary Application-Level IP Block Check
        from app.honeypot.capture import resolve_client_ip
        client_ip = resolve_client_ip()
        prev_svc = app.extensions.get("prevention_service")
        if prev_svc:
            is_blocked, reason = prev_svc.is_blocked(client_ip)
            if is_blocked:
                from app.honeypot.capture import capture_interaction
                from app.events.schemas import SurfaceType, EventType, EventStatus
                capture_interaction(
                    surface=SurfaceType.web,
                    event_type=EventType.blocked_request,
                    status=EventStatus.denied,
                    payload=f"Denied by application block: {reason}",
                    http_status=403
                )
                if request.path.startswith("/api/") or request.is_json:
                    return jsonify({"error": "forbidden", "message": "Access blocked by Security Operations Center prevention policy."}), 403
                return Response(f"403 Forbidden - Access blocked by security prevention policy: {reason}", status=403, mimetype="text/plain")

    # Honeypot 429 Rate Limit Handler
    @app.errorhandler(429)
    def honeypot_rate_limit_handler(e):
        from app.honeypot.capture import resolve_client_ip, capture_interaction
        from app.events.schemas import SurfaceType, EventType, EventStatus
        client_ip = resolve_client_ip()
        desc = getattr(e, "description", "Rate limit exceeded")
        prev_svc = app.extensions.get("prevention_service")
        if prev_svc:
            prev_svc.record_rate_limit(client_ip, request.path, desc)
        capture_interaction(
            surface=SurfaceType.web,
            event_type=EventType.rate_limited,
            status=EventStatus.denied,
            payload=f"Rate limit exceeded on {request.path}: {desc}",
            http_status=429
        )
        resp = Response("429 Too Many Requests - Excessive interaction rate detected. Access throttled.", status=429, mimetype="text/plain")
        resp.headers["Retry-After"] = "60"
        return resp

    # Honeypot 413 Payload Too Large Handler
    @app.errorhandler(413)
    def honeypot_oversized_handler(e):
        from app.honeypot.capture import capture_interaction
        from app.events.schemas import SurfaceType, EventType, EventStatus
        capture_interaction(
            surface=SurfaceType.web,
            event_type=EventType.payload_oversized,
            status=EventStatus.denied,
            payload="HTTP 413 Request entity too large",
            http_status=413
        )
        return Response("413 Payload Too Large - Request entity exceeds maximum permitted size.", status=413, mimetype="text/plain")

    # Honeypot security headers hook
    @app.after_request
    def set_honeypot_headers(response):
        response.headers["Server"] = "nginx/1.24.0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Register honeypot deception blueprints
    from app.honeypot import register_honeypot_blueprints
    register_honeypot_blueprints(app)

    return app
