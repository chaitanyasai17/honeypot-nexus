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
            "connect-src 'self' ws://127.0.0.1:5000 ws://localhost:5000 http://127.0.0.1:5000 https://api.maptiler.com https://*.maptiler.com; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

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


def create_honeypot_app(config_class=Config, publisher=None):
    """Creates the untrusted Public Web Honeypot application."""
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
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 # 16 KB max request size
    app.config["HONEYPOT_RESPONSE_JITTER_MS"] = config_class.HONEYPOT_RESPONSE_JITTER_MS

    # Inject publisher facade into app extension dict
    from app.events.publisher import NullPublisher
    app.extensions["event_publisher"] = publisher or NullPublisher()

    # Honeypot security headers hook
    @app.after_request
    def set_honeypot_headers(response):
        response.headers["Server"] = "nginx/1.24.0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # Register honeypot deception blueprints
    from app.honeypot import register_honeypot_blueprints
    register_honeypot_blueprints(app)

    return app
