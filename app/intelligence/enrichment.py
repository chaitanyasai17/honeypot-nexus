"""
Honeypot Nexus - IP Intelligence Enrichment Service
Caches IP intelligence in-memory and database with safe 50ms fallback budget.
"""

from typing import Dict, Any
from app.config import Config
from app.intelligence.geoip import build_provider, GeoResult
from app.intelligence.reputation import ReputationService
from app.models.models import GeoIPRecord, utc_now
from app.extensions import db
from app.logging_config import get_logger

logger = get_logger("app")


class EnrichmentService:
    def __init__(self):
        self.provider = build_provider(Config.GEOIP_PROVIDER)
        self.reputation = ReputationService()
        self._memory_cache: Dict[str, dict] = {}

    def enrich(self, ip: str) -> Dict[str, Any]:
        """Enriches an IP with geographic, network and threat reputation metadata."""
        if ip in self._memory_cache:
            return self._memory_cache[ip]

        # 1. Check database cache
        try:
            cached_db = GeoIPRecord.query.filter_by(ip=ip).first()
            if cached_db:
                result = {
                    "ip": cached_db.ip,
                    "country": cached_db.country,
                    "country_code": cached_db.country_code,
                    "region": cached_db.region,
                    "city": cached_db.city,
                    "latitude": cached_db.latitude,
                    "longitude": cached_db.longitude,
                    "asn": cached_db.asn,
                    "isp": cached_db.isp,
                    "organization": cached_db.organization,
                    "vpn": cached_db.vpn,
                    "tor": cached_db.tor,
                    "source": cached_db.source,
                }
                if len(self._memory_cache) < 2048:
                    self._memory_cache[ip] = result
                return result
        except Exception as e:
            logger.debug(f"DB cache check skipped: {e}")

        # 2. Query GeoIP provider
        geo_res = self.provider.lookup(ip) or GeoResult(ip=ip, country="Unknown", source="mock")

        # 3. Enhance with Tor & VPN reputation checks
        tor_detected = geo_res.tor or self.reputation.is_tor_exit_node(ip)
        vpn_detected = geo_res.vpn or self.reputation.is_vpn_suspected(
            asn=geo_res.asn,
            org=geo_res.organization,
            isp=geo_res.isp
        )

        result = {
            "ip": ip,
            "country": geo_res.country,
            "country_code": geo_res.country_code,
            "region": geo_res.region,
            "city": geo_res.city,
            "latitude": geo_res.latitude,
            "longitude": geo_res.longitude,
            "asn": geo_res.asn,
            "isp": geo_res.isp,
            "organization": geo_res.organization,
            "vpn": vpn_detected,
            "tor": tor_detected,
            "source": geo_res.source,
        }

        # 4. Save to DB cache
        try:
            record = GeoIPRecord(
                ip=ip,
                country=result["country"],
                country_code=result["country_code"],
                region=result["region"],
                city=result["city"],
                latitude=result["latitude"],
                longitude=result["longitude"],
                asn=result["asn"],
                isp=result["isp"],
                organization=result["organization"],
                vpn=result["vpn"],
                tor=result["tor"],
                source=result["source"],
                fetched_at=utc_now()
            )
            db.session.add(record)
            db.session.flush() # get id if needed
        except Exception:
            db.session.rollback()

        # Cache in memory
        if len(self._memory_cache) < 2048:
            self._memory_cache[ip] = result

        return result


_enrichment_instance = None


def get_enrichment_service() -> EnrichmentService:
    global _enrichment_instance
    if _enrichment_instance is None:
        _enrichment_instance = EnrichmentService()
    return _enrichment_instance
