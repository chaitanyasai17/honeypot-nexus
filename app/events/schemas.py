"""
Honeypot Nexus - Event Schemas and Enums
Defines HoneypotEvent, BusEnvelope, NormalizedEvent and canonical security taxonomy enums.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional
import ipaddress
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    NONE = "NONE"
    BRUTE_FORCE = "BRUTE_FORCE"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    SQL_INJECTION = "SQL_INJECTION"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    SCANNER = "SCANNER"
    RECONNAISSANCE = "RECONNAISSANCE"
    SUSPICIOUS_API = "SUSPICIOUS_API"
    SHELL_RECON = "SHELL_RECON"
    SENSITIVE_FILE_ACCESS = "SENSITIVE_FILE_ACCESS"
    AUTOMATED_ENUMERATION = "AUTOMATED_ENUMERATION"


class SurfaceType(str, Enum):
    web = "web"
    login = "login"
    admin = "admin"
    api = "api"
    files = "files"
    database = "database"
    shell = "shell"


class EventType(str, Enum):
    page_view = "page_view"
    login_attempt = "login_attempt"
    admin_access = "admin_access"
    admin_action = "admin_action"
    api_request = "api_request"
    file_list = "file_list"
    file_access = "file_access"
    file_download = "file_download"
    file_upload_attempt = "file_upload_attempt"
    db_query = "db_query"
    shell_command = "shell_command"
    recon_probe = "recon_probe"
    robots_fetch = "robots_fetch"
    not_found = "not_found"
    rate_limited = "rate_limited"


class EventStatus(str, Enum):
    success = "success"
    failure = "failure"
    denied = "denied"
    not_found = "not_found"
    error = "error"
    info = "info"


# -------------------------------------------------------------
# A. HoneypotEvent - What the untrusted honeypot emits
# -------------------------------------------------------------
class HoneypotEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex, max_length=36)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = Field(..., max_length=64)
    source_port: int = Field(default=0, ge=0, le=65535)
    destination: str = Field(default="127.0.0.1:8080", max_length=64)
    endpoint: str = Field(..., max_length=512)
    query_string: str = Field(default="", max_length=1024)
    http_method: str = Field(..., max_length=16)
    user_agent: str = Field(default="", max_length=256)
    session_id: str = Field(..., max_length=64)
    surface: SurfaceType
    event_type: EventType
    payload: str = Field(default="", max_length=2048)
    http_status: int = Field(default=200, ge=100, le=599)
    status: EventStatus = EventStatus.info
    headers: Dict[str, str] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)
    # Transient fields are never logged, persisted, or broadcast.
    # Excluded from repr and model_dump.
    transient: Dict[str, Any] = Field(default_factory=dict, exclude=True, repr=False)
    is_synthetic: bool = False

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


# -------------------------------------------------------------
# B. BusEnvelope - Transport wrapper with HMAC integrity
# -------------------------------------------------------------
class BusEnvelope(BaseModel):
    envelope_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    seq: int
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: int = 1
    payload_json: str
    signature: str


# -------------------------------------------------------------
# C. NormalizedEvent - Fully enriched, scored, and validated
# -------------------------------------------------------------
class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    received_at: datetime
    source_ip: str
    source_port: int
    destination: str
    endpoint: str
    query_string: str
    http_method: str
    user_agent: str
    session_id: str
    surface: str
    event_type: str
    attack_type: str
    payload: str
    status: str
    http_status: int
    risk_score: int
    engagement_score: int
    severity: str
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_region: Optional[str] = None
    geo_city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    vpn_detected: bool = False
    tor_detected: bool = False
    geo_source: str = "mock"
    is_synthetic: bool = False
    detection_ids: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)
