#!/usr/bin/env python3
"""
Honeypot Nexus - Primary Application Runner
Launches both isolated applications within a single Python runtime:
- Trusted SOC Dashboard & Event Processing Pipeline on port 5000
- Untrusted Public Honeypot Deception Layer on port 8080
"""

import threading
import sys
from werkzeug.serving import make_server
from app import create_soc_app, create_honeypot_app
from app.config import Config
from app.extensions import socketio, db
from app.services.config_service import seed_default_configs
from app.events.event_bus import EventBus
from app.events.processor import EventProcessor
from app.logging_config import get_logger

logger = get_logger("app")


def start_honeypot_server(app, host: str, port: int):
    """Runs the untrusted honeypot server in a background thread."""
    server = make_server(host, port, app, threaded=True)
    logger.info(f"Public Honeypot server listening on http://{host}:{port}")
    server.serve_forever()


def main():
    print("=" * 70)
    print("  HONEYPOT NEXUS - INTRUSION DETECTION & SOC DASHBOARD")
    print("=" * 70)

    # 1. Initialize EventBus & Processor
    event_bus = EventBus(
        hmac_key=Config.EVENTBUS_HMAC_KEY,
        maxsize=Config.EVENTBUS_MAX_QUEUE,
        num_workers=Config.EVENTBUS_WORKERS
    )

    # 2. Build Trusted SOC Application
    soc_app = create_soc_app(Config)

    # Attach event bus to soc_app
    soc_app.extensions["event_bus"] = event_bus

    from app.services.prevention_service import get_prevention_service
    prevention_service = get_prevention_service()
    soc_app.extensions["prevention_service"] = prevention_service

    with soc_app.app_context():
        # Ensure database tables exist
        db.create_all()
        # Load persistent active IP blocks into in-memory prevention store
        prevention_service.load_active_blocks_from_db()
        # Seed default configurations
        seed_default_configs()
        # Seed evaluation administrator idempotently
        try:
            from scripts.init_demo_admin import init_demo_admin
            init_demo_admin()
        except Exception as e:
            logger.warning(f"Admin provisioning notice: {e}")

    # 3. Create Event Processor and subscribe pipeline to EventBus
    processor = EventProcessor(soc_app, event_bus)
    event_bus.subscribe(processor.process_envelope, name="master_pipeline")
    event_bus.start()

    # 4. Build Untrusted Honeypot Application with isolated publisher facade
    publisher = event_bus.publisher()
    honeypot_app = create_honeypot_app(Config, publisher=publisher, prevention_service=prevention_service)

    # 5. Start dedicated Honeypot server if running on distinct port
    if Config.HONEYPOT_PORT != Config.DASHBOARD_PORT:
        hp_thread = threading.Thread(
            target=start_honeypot_server,
            args=(honeypot_app, Config.HONEYPOT_BIND_HOST, Config.HONEYPOT_PORT),
            daemon=True,
            name="HoneypotServerThread"
        )
        hp_thread.start()
        print(f"[*] Public Honeypot online:  http://{Config.HONEYPOT_BIND_HOST}:{Config.HONEYPOT_PORT}")
    else:
        print(f"[*] Single-port unified cloud mode: Honeypot & SOC active on port {Config.DASHBOARD_PORT}")

    # 6. Apply Unified WSGI Dispatcher to allow seamless single-port & cloud access
    original_wsgi_app = soc_app.wsgi_app

    def unified_dispatcher(environ, start_response):
        path = environ.get("PATH_INFO", "")
        # Route to SOC application
        if (
            path.startswith(("/dashboard", "/auth", "/socket.io", "/healthz"))
            or (path.startswith("/api/") and not path.startswith("/api/v1/"))
            or (path.startswith("/static/") and not path.startswith("/static/honeypot/"))
        ):
            return original_wsgi_app(environ, start_response)
        # All other paths route to untrusted honeypot deception layer
        return honeypot_app(environ, start_response)

    soc_app.wsgi_app = unified_dispatcher

    print(f"[*] Private SOC Dashboard:  http://{Config.DASHBOARD_BIND_HOST}:{Config.DASHBOARD_PORT}/dashboard/")
    print(f"[*] System Mode: DEMO_MODE={'ENABLED' if Config.DEMO_MODE else 'DISABLED'}")
    print("=" * 70)

    try:
        # 6. Run SOC application via SocketIO
        socketio.run(
            soc_app,
            host=Config.DASHBOARD_BIND_HOST,
            port=Config.DASHBOARD_PORT,
            use_reloader=False,
            log_output=False,
            allow_unsafe_werkzeug=True
        )
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Shutting down Honeypot Nexus cleanly...")
    finally:
        event_bus.stop(drain=True)


if __name__ == "__main__":
    main()
