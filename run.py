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

    with soc_app.app_context():
        # Ensure database tables exist
        db.create_all()
        # Seed default configurations
        seed_default_configs()

    # 3. Create Event Processor and subscribe pipeline to EventBus
    processor = EventProcessor(soc_app, event_bus)
    event_bus.subscribe(processor.process_envelope, name="master_pipeline")
    event_bus.start()

    # 4. Build Untrusted Honeypot Application with isolated publisher facade
    publisher = event_bus.publisher()
    honeypot_app = create_honeypot_app(Config, publisher=publisher)

    # 5. Start Honeypot server in daemon thread
    hp_thread = threading.Thread(
        target=start_honeypot_server,
        args=(honeypot_app, Config.HONEYPOT_BIND_HOST, Config.HONEYPOT_PORT),
        daemon=True,
        name="HoneypotServerThread"
    )
    hp_thread.start()

    print(f"[*] Public Honeypot online:  http://{Config.HONEYPOT_BIND_HOST}:{Config.HONEYPOT_PORT}")
    print(f"[*] Private SOC Dashboard:  http://{Config.DASHBOARD_BIND_HOST}:{Config.DASHBOARD_PORT}")
    print(f"[*] System Mode: DEMO_MODE={'ENABLED' if Config.DEMO_MODE else 'DISABLED'}")
    print("=" * 70)

    try:
        # 6. Run SOC application via SocketIO
        socketio.run(
            soc_app,
            host=Config.DASHBOARD_BIND_HOST,
            port=Config.DASHBOARD_PORT,
            use_reloader=False,
            log_output=False
        )
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Shutting down Honeypot Nexus cleanly...")
    finally:
        event_bus.stop(drain=True)


if __name__ == "__main__":
    main()
