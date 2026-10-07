"""
Honeypot Nexus - Central Configuration Management
Validates environment variables, enforces security baselines, and isolates configs.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
(INSTANCE_DIR / "logs").mkdir(exist_ok=True)

# Load .env file
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base runtime configuration."""
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    TESTING = False
    DEBUG = FLASK_ENV == "development"

    # Security Keys
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    EVENTBUS_HMAC_KEY = os.getenv("EVENTBUS_HMAC_KEY", "")
    PW_FINGERPRINT_KEY = os.getenv("PW_FINGERPRINT_KEY", "")

    # SQLite Database
    default_db = f"sqlite:///{INSTANCE_DIR / 'honeypot_nexus.db'}"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", default_db)
    # Convert relative sqlite:/// to absolute if needed
    if SQLALCHEMY_DATABASE_URI.startswith("sqlite:///instance/"):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{INSTANCE_DIR / 'honeypot_nexus.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Network Binding
    # Respect cloud platform PORT environment variable (Render, Railway, Fly.io)
    env_port = os.getenv("PORT")
    DASHBOARD_BIND_HOST = os.getenv("DASHBOARD_BIND_HOST", "0.0.0.0" if env_port else "127.0.0.1")
    DASHBOARD_PORT = int(env_port or os.getenv("DASHBOARD_PORT", "5000"))
    HONEYPOT_BIND_HOST = os.getenv("HONEYPOT_BIND_HOST", "0.0.0.0" if env_port else "127.0.0.1")
    HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "8080" if not env_port else env_port))
    ALLOW_NON_LOOPBACK = os.getenv("ALLOW_NON_LOOPBACK", "true" if env_port else "false").lower() in ("true", "1", "yes")
    TRUST_PROXY_HOPS = int(os.getenv("TRUST_PROXY_HOPS", "1" if env_port else "0"))
    PUBLIC_HTTPS = os.getenv("PUBLIC_HTTPS", "true" if env_port else "false").lower() in ("true", "1", "yes")

    # Session & Security
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    TOTP_ISSUER = os.getenv("TOTP_ISSUER", "Honeypot Nexus")
    SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "30")) # minutes
    SESSION_ABSOLUTE_HOURS = int(os.getenv("SESSION_ABSOLUTE_HOURS", "8"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = PUBLIC_HTTPS
    SESSION_COOKIE_NAME = "hnx_soc"

    # GeoIP & Intelligence
    GEOIP_PROVIDER = os.getenv("GEOIP_PROVIDER", "mock")
    GEOIP_DATABASE = os.getenv("GEOIP_DATABASE", str(BASE_DIR / "data" / "GeoLite2-City.mmdb"))
    GEOIP_ASN_DATABASE = os.getenv("GEOIP_ASN_DATABASE", str(BASE_DIR / "data" / "GeoLite2-ASN.mmdb"))
    LAB_LAT = float(os.getenv("LAB_LAT", "13.0827"))
    LAB_LON = float(os.getenv("LAB_LON", "80.2707"))
    MAP_TILES = os.getenv("MAP_TILES", "offline")
    MAPTILER_API_KEY = os.getenv("MAPTILER_API_KEY", "")

    # EventBus Pipeline
    EVENTBUS_MAX_QUEUE = int(os.getenv("EVENTBUS_MAX_QUEUE", "5000"))
    EVENTBUS_WORKERS = int(os.getenv("EVENTBUS_WORKERS", "1"))
    HEALTH_SAMPLE_SECONDS = int(os.getenv("HEALTH_SAMPLE_SECONDS", "5"))
    EVENT_RETENTION_DAYS = int(os.getenv("EVENT_RETENTION_DAYS", "30"))
    HONEYPOT_RESPONSE_JITTER_MS = os.getenv("HONEYPOT_RESPONSE_JITTER_MS", "0-0")

    # Demo & Reporting
    DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    ML_ADVISORY = os.getenv("ML_ADVISORY", "false").lower() in ("true", "1", "yes")
    REPORT_TEAM_LINE = os.getenv("REPORT_TEAM_LINE", "CSE (Cyber Security) Mini Project")
    APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Asia/Kolkata")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls):
        """Enforces critical secrets presence and bind security unless in TESTING."""
        if cls.TESTING:
            if not cls.SECRET_KEY:
                cls.SECRET_KEY = "test_secret_key_testing_environment_only_12345"
            if not cls.EVENTBUS_HMAC_KEY:
                cls.EVENTBUS_HMAC_KEY = "test_eventbus_hmac_key_testing_only_12345"
            if not cls.PW_FINGERPRINT_KEY:
                cls.PW_FINGERPRINT_KEY = "test_pw_fingerprint_key_testing_only_12345"
            return

        missing = []
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 16:
            missing.append("SECRET_KEY (must be at least 16 characters)")
        if not cls.EVENTBUS_HMAC_KEY or len(cls.EVENTBUS_HMAC_KEY) < 16:
            missing.append("EVENTBUS_HMAC_KEY (must be at least 16 characters)")
        if not cls.PW_FINGERPRINT_KEY or len(cls.PW_FINGERPRINT_KEY) < 16:
            missing.append("PW_FINGERPRINT_KEY (must be at least 16 characters)")

        if missing:
            raise ValueError(
                f"[SECURITY ERROR] Missing or insecure critical keys in configuration:\n"
                + "\n".join(f" - {m}" for m in missing)
                + "\nPlease update your .env file."
            )

        # Loopback check
        loopback_hosts = ("127.0.0.1", "localhost", "::1")
        if (
            cls.DASHBOARD_BIND_HOST not in loopback_hosts
            or cls.HONEYPOT_BIND_HOST not in loopback_hosts
        ) and not cls.ALLOW_NON_LOOPBACK:
            raise ValueError(
                f"[SECURITY ERROR] Attempting to bind to non-loopback host "
                f"(SOC: {cls.DASHBOARD_BIND_HOST}, Honeypot: {cls.HONEYPOT_BIND_HOST}) "
                f"without ALLOW_NON_LOOPBACK=true. Aborting for safety."
            )


class TestConfig(Config):
    """Configuration for pytest test suites."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    DEMO_MODE = True
    GEOIP_PROVIDER = "mock"
    HONEYPOT_RESPONSE_JITTER_MS = "0-0"
