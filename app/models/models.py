"""
Honeypot Nexus - Database Models
Complete SQLAlchemy schema for all 11 core tables with indexes, foreign keys, and SQLite WAL pragmas.
Designed to be directly portable to PostgreSQL.
"""

from datetime import datetime, timezone
import uuid
import sqlalchemy as sa
from sqlalchemy.orm import relationship
from app.extensions import db


def utc_now():
    """Returns timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def gen_uuid():
    """Generates standard 32-character hex UUID4 string."""
    return uuid.uuid4().hex


# ---------------------------------------------------------
# SQLite WAL and PRAGMA Optimization Listener
# ---------------------------------------------------------
@sa.event.listens_for(sa.engine.Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforces WAL mode, foreign keys, and concurrency optimizations for SQLite."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    except Exception:
        # Ignore if non-sqlite backend (e.g. PostgreSQL)
        pass
    finally:
        cursor.close()


# ---------------------------------------------------------
# 1. users
# ---------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id = sa.Column(sa.Integer, primary_key=True)
    username = sa.Column(sa.String(64), unique=True, nullable=False, index=True)
    password_hash = sa.Column(sa.String(256), nullable=False)
    role = sa.Column(sa.String(32), nullable=False, default="analyst") # admin, analyst, viewer
    mfa_enabled = sa.Column(sa.Boolean, default=False, nullable=False)
    totp_secret_enc = sa.Column(sa.String(256), nullable=True)
    last_totp_step = sa.Column(sa.Integer, default=0, nullable=False)
    failed_logins = sa.Column(sa.Integer, default=0, nullable=False)
    locked_until = sa.Column(sa.DateTime(timezone=True), nullable=True)
    last_login_at = sa.Column(sa.DateTime(timezone=True), nullable=True)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    sessions = relationship("AdminSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    acknowledged_alerts = relationship("Alert", back_populates="acknowledged_user")


# ---------------------------------------------------------
# 2. admin_sessions
# ---------------------------------------------------------
class AdminSession(db.Model):
    __tablename__ = "admin_sessions"

    id = sa.Column(sa.String(64), primary_key=True) # SHA-256 hash of session token
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = sa.Column(sa.String(64), nullable=False)
    user_agent = sa.Column(sa.String(256), nullable=True)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = sa.Column(sa.DateTime(timezone=True), nullable=False, index=True)
    revoked_at = sa.Column(sa.DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="sessions")


# ---------------------------------------------------------
# 3. geoip_records
# ---------------------------------------------------------
class GeoIPRecord(db.Model):
    __tablename__ = "geoip_records"

    id = sa.Column(sa.Integer, primary_key=True)
    ip = sa.Column(sa.String(64), unique=True, nullable=False, index=True)
    country = sa.Column(sa.String(128), nullable=True)
    country_code = sa.Column(sa.String(8), nullable=True)
    region = sa.Column(sa.String(128), nullable=True)
    city = sa.Column(sa.String(128), nullable=True)
    latitude = sa.Column(sa.Float, nullable=True)
    longitude = sa.Column(sa.Float, nullable=True)
    asn = sa.Column(sa.String(64), nullable=True)
    isp = sa.Column(sa.String(128), nullable=True)
    organization = sa.Column(sa.String(128), nullable=True)
    vpn = sa.Column(sa.Boolean, default=False, nullable=False)
    tor = sa.Column(sa.Boolean, default=False, nullable=False)
    source = sa.Column(sa.String(32), default="mock", nullable=False) # mock, maxmind
    fetched_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    profiles = relationship("AttackerProfile", back_populates="geo_record")


# ---------------------------------------------------------
# 4. attacker_profiles
# ---------------------------------------------------------
class AttackerProfile(db.Model):
    __tablename__ = "attacker_profiles"

    id = sa.Column(sa.Integer, primary_key=True)
    source_ip = sa.Column(sa.String(64), unique=True, nullable=False, index=True)
    geo_id = sa.Column(sa.Integer, sa.ForeignKey("geoip_records.id", ondelete="SET NULL"), nullable=True)
    first_seen = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    total_sessions = sa.Column(sa.Integer, default=1, nullable=False)
    total_events = sa.Column(sa.Integer, default=0, nullable=False)
    avg_risk = sa.Column(sa.Float, default=0.0, nullable=False)
    max_risk = sa.Column(sa.Integer, default=0, nullable=False, index=True)
    engagement_score = sa.Column(sa.Integer, default=0, nullable=False)
    top_attack_type = sa.Column(sa.String(64), default="NONE", nullable=False)
    vpn_detected = sa.Column(sa.Boolean, default=False, nullable=False)
    tor_detected = sa.Column(sa.Boolean, default=False, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    geo_record = relationship("GeoIPRecord", back_populates="profiles")
    sessions = relationship("AttackerSession", back_populates="profile", cascade="all, delete-orphan")


# ---------------------------------------------------------
# 5. attacker_sessions
# ---------------------------------------------------------
class AttackerSession(db.Model):
    __tablename__ = "attacker_sessions"

    id = sa.Column(sa.String(64), primary_key=True) # UUID or session string
    profile_id = sa.Column(sa.Integer, sa.ForeignKey("attacker_profiles.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ip = sa.Column(sa.String(64), nullable=False, index=True)
    first_seen = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    event_count = sa.Column(sa.Integer, default=0, nullable=False)
    risk_score = sa.Column(sa.Integer, default=0, nullable=False, index=True)
    engagement_score = sa.Column(sa.Integer, default=0, nullable=False)
    status = sa.Column(sa.String(32), default="active", nullable=False, index=True) # active, idle, closed
    attack_types_json = sa.Column(sa.JSON, default=dict, nullable=False)
    endpoints_json = sa.Column(sa.JSON, default=list, nullable=False)
    surfaces_json = sa.Column(sa.JSON, default=list, nullable=False)
    score_breakdown_json = sa.Column(sa.JSON, default=dict, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    profile = relationship("AttackerProfile", back_populates="sessions")
    events = relationship("HoneypotEventModel", back_populates="session", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="session")


# ---------------------------------------------------------
# 6. honeypot_events
# ---------------------------------------------------------
class HoneypotEventModel(db.Model):
    __tablename__ = "honeypot_events"

    event_id = sa.Column(sa.String(64), primary_key=True, default=gen_uuid)
    session_id = sa.Column(sa.String(64), sa.ForeignKey("attacker_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    received_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    source_ip = sa.Column(sa.String(64), nullable=False, index=True)
    source_port = sa.Column(sa.Integer, nullable=True)
    destination = sa.Column(sa.String(64), nullable=True)
    endpoint = sa.Column(sa.String(512), nullable=False)
    query_string = sa.Column(sa.String(1024), nullable=True)
    http_method = sa.Column(sa.String(16), nullable=False)
    user_agent = sa.Column(sa.String(256), nullable=True)
    surface = sa.Column(sa.String(32), nullable=False) # web, login, admin, api, files, database, shell
    event_type = sa.Column(sa.String(64), nullable=False)
    attack_type = sa.Column(sa.String(64), default="NONE", nullable=False, index=True)
    payload = sa.Column(sa.Text, nullable=True) # Capped at 2048 characters
    status = sa.Column(sa.String(32), default="info", nullable=False)
    http_status = sa.Column(sa.Integer, default=200, nullable=False)
    risk_score = sa.Column(sa.Integer, default=0, nullable=False, index=True)
    engagement_score = sa.Column(sa.Integer, default=0, nullable=False)
    severity = sa.Column(sa.String(32), default="NORMAL", nullable=False, index=True)
    geo_country = sa.Column(sa.String(128), nullable=True)
    geo_country_code = sa.Column(sa.String(8), nullable=True)
    geo_region = sa.Column(sa.String(128), nullable=True)
    geo_city = sa.Column(sa.String(128), nullable=True)
    latitude = sa.Column(sa.Float, nullable=True)
    longitude = sa.Column(sa.Float, nullable=True)
    asn = sa.Column(sa.String(64), nullable=True)
    isp = sa.Column(sa.String(128), nullable=True)
    vpn_detected = sa.Column(sa.Boolean, default=False, nullable=False)
    tor_detected = sa.Column(sa.Boolean, default=False, nullable=False)
    geo_source = sa.Column(sa.String(32), default="mock", nullable=False)
    is_synthetic = sa.Column(sa.Boolean, default=False, nullable=False)
    meta_json = sa.Column(sa.JSON, default=dict, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)

    session = relationship("AttackerSession", back_populates="events")
    detections = relationship("DetectionModel", back_populates="event", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="event")

    # Composite indexes for high performance querying
    __table_args__ = (
        sa.Index("ix_events_ts_sev", "timestamp", "severity"),
        sa.Index("ix_events_ip_ts", "source_ip", "timestamp"),
    )


# ---------------------------------------------------------
# 7. detections
# ---------------------------------------------------------
class DetectionModel(db.Model):
    __tablename__ = "detections"

    id = sa.Column(sa.Integer, primary_key=True)
    event_id = sa.Column(sa.String(64), sa.ForeignKey("honeypot_events.event_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = sa.Column(sa.String(64), nullable=False, index=True)
    rule_id = sa.Column(sa.String(64), nullable=False, index=True)
    attack_type = sa.Column(sa.String(64), nullable=False, index=True)
    severity = sa.Column(sa.String(32), nullable=False)
    points = sa.Column(sa.Integer, default=0, nullable=False)
    reason = sa.Column(sa.String(256), nullable=False)
    evidence_json = sa.Column(sa.JSON, default=dict, nullable=False)
    detected_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)

    event = relationship("HoneypotEventModel", back_populates="detections")

    __table_args__ = (
        sa.Index("ix_det_rule_time", "rule_id", "detected_at"),
    )


# ---------------------------------------------------------
# 8. alerts
# ---------------------------------------------------------
class Alert(db.Model):
    __tablename__ = "alerts"

    alert_id = sa.Column(sa.String(64), primary_key=True, default=gen_uuid)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    severity = sa.Column(sa.String(32), nullable=False) # HIGH, CRITICAL
    title = sa.Column(sa.String(256), nullable=False)
    description = sa.Column(sa.Text, nullable=True)
    source_ip = sa.Column(sa.String(64), nullable=False, index=True)
    session_id = sa.Column(sa.String(64), sa.ForeignKey("attacker_sessions.id", ondelete="CASCADE"), nullable=False)
    event_id = sa.Column(sa.String(64), sa.ForeignKey("honeypot_events.event_id", ondelete="SET NULL"), nullable=True)
    attack_type = sa.Column(sa.String(64), nullable=False)
    risk_score = sa.Column(sa.Integer, default=0, nullable=False)
    status = sa.Column(sa.String(32), default="NEW", nullable=False) # NEW, ACKNOWLEDGED, RESOLVED
    dedupe_key = sa.Column(sa.String(128), nullable=False, index=True)
    occurrences = sa.Column(sa.Integer, default=1, nullable=False)
    reasons_json = sa.Column(sa.JSON, default=list, nullable=False)
    last_occurrence_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    acknowledged_at = sa.Column(sa.DateTime(timezone=True), nullable=True)
    acknowledged_by = sa.Column(sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = sa.Column(sa.DateTime(timezone=True), nullable=True)

    session = relationship("AttackerSession", back_populates="alerts")
    event = relationship("HoneypotEventModel", back_populates="alerts")
    acknowledged_user = relationship("User", back_populates="acknowledged_alerts")

    __table_args__ = (
        sa.Index("ix_alerts_status_sev", "status", "severity"),
    )


# ---------------------------------------------------------
# 9. audit_logs
# ---------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = sa.Column(sa.String(64), nullable=True)
    action = sa.Column(sa.String(64), nullable=False, index=True)
    target = sa.Column(sa.String(128), nullable=True)
    ip = sa.Column(sa.String(64), nullable=True)
    detail_json = sa.Column(sa.JSON, default=dict, nullable=False)
    outcome = sa.Column(sa.String(32), default="success", nullable=False)

    user = relationship("User", back_populates="audit_logs")


# ---------------------------------------------------------
# 10. system_health
# ---------------------------------------------------------
class SystemHealth(db.Model):
    __tablename__ = "system_health"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    cpu = sa.Column(sa.Float, nullable=False)
    memory = sa.Column(sa.Float, nullable=False)
    disk = sa.Column(sa.Float, nullable=False)
    db_status = sa.Column(sa.String(32), default="operational", nullable=False)
    eventbus_status = sa.Column(sa.String(32), default="operational", nullable=False)
    queue_depth = sa.Column(sa.Integer, default=0, nullable=False)
    ws_clients = sa.Column(sa.Integer, default=0, nullable=False)
    services_json = sa.Column(sa.JSON, default=dict, nullable=False)


# ---------------------------------------------------------
# 11. honeypot_config
# ---------------------------------------------------------
class HoneypotConfig(db.Model):
    __tablename__ = "honeypot_config"

    key = sa.Column(sa.String(64), primary_key=True)
    value = sa.Column(sa.Text, nullable=False)
    value_type = sa.Column(sa.String(32), default="string", nullable=False) # string, int, float, bool, json
    description = sa.Column(sa.String(256), nullable=True)
    updated_by = sa.Column(sa.Integer, nullable=True)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
