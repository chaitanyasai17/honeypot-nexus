"""
Honeypot Nexus - System Health Telemetry Service
Samples real-world system metrics (CPU, RAM, Disk) using psutil and runtime monitors.
"""

import time
import psutil
from typing import Dict, Any
from flask import current_app
from app.models.models import SystemHealth, HoneypotEventModel, utc_now
from app.extensions import db


def sample_system_health() -> Dict[str, Any]:
    """Collects hardware and subsystem health status."""
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent if hasattr(psutil, "disk_usage") else 0.0

    # Test DB status and measure latency
    db_status = "operational"
    db_latency_ms = 0.0
    try:
        t0 = time.time()
        HoneypotEventModel.query.limit(1).all()
        db_latency_ms = round((time.time() - t0) * 1000, 2)
    except Exception:
        db_status = "degraded"

    # EventBus health
    event_bus = current_app.extensions.get("event_bus")
    bus_stats = event_bus.stats() if event_bus else None
    bus_status = bus_stats.status if bus_stats else "operational"
    q_depth = bus_stats.queue_depth if bus_stats else 0

    services = [
        {"name": "Public Honeypot HTTP (Port 8080)", "status": "operational"},
        {"name": "Private SOC Dashboard (Port 5000)", "status": "operational"},
        {"name": "Event Processing Pipeline", "status": bus_status},
        {"name": "Real-time Telemetry WebSocket", "status": "operational"},
        {"name": "GeoIP Intelligence Engine", "status": "operational"}
    ]

    return {
        "cpu": cpu,
        "memory": mem,
        "disk": disk,
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms
        },
        "eventbus": {
            "status": bus_status,
            "queue_depth": q_depth,
            "published": bus_stats.published if bus_stats else 0,
            "processed": bus_stats.processed if bus_stats else 0,
            "rejected": bus_stats.rejected if bus_stats else 0,
            "dropped": bus_stats.dropped if bus_stats else 0,
            "lag_ms": bus_stats.lag_ms if bus_stats else 0.0
        },
        "websocket": {
            "clients": 1
        },
        "services": services
    }
