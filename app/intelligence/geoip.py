"""
Honeypot Nexus - GeoIP Intelligence Providers
Implements MockGeoIPProvider with RFC 5737 ranges and optional MaxMind fallback.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, Literal
import ipaddress
import json
import hashlib
from pathlib import Path
from app.config import BASE_DIR, Config
from app.logging_config import get_logger

logger = get_logger("app")


@dataclass
class GeoResult:
    ip: str
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "XX"
    region: Optional[str] = "Unknown"
    city: Optional[str] = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    vpn: bool = False
    tor: bool = False
    source: Literal["mock", "maxmind"] = "mock"
    approximate: bool = True
    note: str = "Approximate location derived from IP data; not the attacker's physical location."

    def to_dict(self):
        return asdict(self)


class GeoIPProvider(ABC):
    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def lookup(self, ip: str) -> Optional[GeoResult]:
        ...


class MockGeoIPProvider(GeoIPProvider):
    """Deterministic, offline synthetic GeoIP provider based on RFC 5737 & private ranges."""
    name = "mock"

    def __init__(self, data_file: Optional[Path] = None):
        self.data_file = data_file or (BASE_DIR / "data" / "mock_geoip.json")
        self.records = []
        self._load_records()

    def _load_records(self):
        if self.data_file.exists():
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        net = ipaddress.ip_network(item["cidr"])
                        self.records.append((net, item))
            except Exception as e:
                logger.error(f"Failed to load mock GeoIP records: {e}")

    def is_available(self) -> bool:
        return True

    def lookup(self, ip: str) -> Optional[GeoResult]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        # 1. Check local private/loopback
        if addr.is_loopback or addr.is_private or addr.is_link_local:
            return GeoResult(
                ip=ip,
                country="India",
                country_code="IN",
                region="Tamil Nadu",
                city="Chennai (Local Lab)",
                latitude=Config.LAB_LAT,
                longitude=Config.LAB_LON,
                asn="AS64500",
                isp="Campus Lab Gateway",
                organization="Local Deception Lab",
                vpn=False,
                tor=False,
                source="mock"
            )

        # 2. Check exact CIDR matches in mock database
        for net, rec in self.records:
            if addr in net:
                return GeoResult(
                    ip=ip,
                    country=rec.get("country"),
                    country_code=rec.get("country_code"),
                    region=rec.get("region"),
                    city=rec.get("city"),
                    latitude=rec.get("latitude"),
                    longitude=rec.get("longitude"),
                    asn=rec.get("asn"),
                    isp=rec.get("isp"),
                    organization=rec.get("organization"),
                    vpn=rec.get("vpn", False),
                    tor=rec.get("tor", False),
                    source="mock"
                )

        # 3. Deterministic hash-based fallback from mock records for arbitrary public IPs
        if self.records:
            hash_idx = int(hashlib.sha256(ip.encode("utf-8")).hexdigest(), 16) % len(self.records)
            _, rec = self.records[hash_idx]
            return GeoResult(
                ip=ip,
                country=rec.get("country"),
                country_code=rec.get("country_code"),
                region=rec.get("region"),
                city=rec.get("city"),
                latitude=rec.get("latitude"),
                longitude=rec.get("longitude"),
                asn=rec.get("asn"),
                isp=rec.get("isp"),
                organization=rec.get("organization"),
                vpn=rec.get("vpn", False),
                tor=rec.get("tor", False),
                source="mock"
            )

        return GeoResult(ip=ip, country="Unknown", source="mock")


class MaxMindGeoIPProvider(GeoIPProvider):
    """MaxMind MMDB reader with safe fallback."""
    name = "maxmind"

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or Config.GEOIP_DATABASE
        self.reader = None
        self._init_reader()

    def _init_reader(self):
        try:
            import geoip2.database
            p = Path(self.db_path)
            if p.exists() and p.is_file():
                self.reader = geoip2.database.Reader(str(p))
                logger.info(f"Loaded MaxMind database from {self.db_path}")
        except Exception as e:
            logger.warning(f"MaxMind reader unavailable: {e}")
            self.reader = None

    def is_available(self) -> bool:
        return self.reader is not None

    def lookup(self, ip: str) -> Optional[GeoResult]:
        if not self.is_available():
            return None
        try:
            res = self.reader.city(ip)
            return GeoResult(
                ip=ip,
                country=res.country.name or "Unknown",
                country_code=res.country.iso_code or "XX",
                region=res.subdivisions.most_specific.name or "Unknown",
                city=res.city.name or "Unknown",
                latitude=res.location.latitude,
                longitude=res.location.longitude,
                source="maxmind"
            )
        except Exception:
            return None


def build_provider(provider_type: str = "auto") -> GeoIPProvider:
    """Factory selecting GeoIP provider according to configuration."""
    if provider_type == "maxmind":
        maxmind = MaxMindGeoIPProvider()
        if maxmind.is_available():
            return maxmind
        logger.warning("MaxMind requested but unavailable, falling back to Mock provider")
        return MockGeoIPProvider()

    elif provider_type == "auto":
        maxmind = MaxMindGeoIPProvider()
        if maxmind.is_available():
            return maxmind
        return MockGeoIPProvider()

    return MockGeoIPProvider()
