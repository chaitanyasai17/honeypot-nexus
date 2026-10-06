"""
Honeypot Nexus - Structured JSON-Lines Logging
Separates logs into: app, security, detection, and audit streams.
"""

import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Formats log records as structured JSON lines."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
            "event_id": getattr(record, "event_id", None),
            "session_id": getattr(record, "session_id", None),
            "ip": getattr(record, "ip", None),
            "user": getattr(record, "user", None),
            "extra": getattr(record, "extra_data", None)
        }
        if record.exc_info:
            log_entry["exc"] = self.formatException(record.exc_info)
        return json.dumps({k: v for k, v in log_entry.items() if v is not None})


def configure_logging(log_dir: Path, log_level: str = "INFO"):
    """Configures the application loggers with rotating JSON-lines handlers."""
    log_dir.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, log_level.upper(), logging.INFO)

    streams = {
        "app": log_dir / "app.log",
        "security": log_dir / "security.log",
        "detection": log_dir / "detection.log",
        "audit": log_dir / "audit.log"
    }

    formatter = JsonFormatter()

    for name, file_path in streams.items():
        logger = logging.getLogger(f"honeypot_nexus.{name}")
        logger.setLevel(level)
        # Avoid duplicate handlers if reconfigured
        if not logger.handlers:
            handler = RotatingFileHandler(
                file_path,
                maxBytes=5 * 1024 * 1024, # 5MB
                backupCount=5,
                encoding="utf-8"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            # Also echo app info/warnings to console in development
            if name == "app":
                console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%H:%M:%S"
                )
                console_handler.setFormatter(console_formatter)
                logger.addHandler(console_handler)


def get_logger(stream: str = "app") -> logging.Logger:
    """Returns a specific named logger stream."""
    return logging.getLogger(f"honeypot_nexus.{stream}")
