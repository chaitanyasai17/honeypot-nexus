"""
Honeypot Nexus - GeoIP Intelligence Unit & Fallback Verification Suite
Validates Priority 1 requirements:
1. RFC 5737 testnet CIDRs return simulated data labeled is_simulated=True, source="mock".
2. Arbitrary public IPs NEVER receive invented synthetic locations/ISPs/ASNs (returns Unknown/None).
3. MaxMindGeoIPProvider gracefully falls back to MockGeoIPProvider when database files are absent.
4. Data enrichment pipeline attaches is_simulated and source fields to profiles and DB cache.
"""

import pytest
from app.intelligence.geoip import MockGeoIPProvider, MaxMindGeoIPProvider, build_provider, GeoResult
from app.intelligence.enrichment import enrich_ip
from app.models.models import GeoIPRecord
from app.extensions import db


def test_rfc5737_returns_explicitly_simulated():
    """Verifies that RFC 5737 documentation addresses return clearly simulated telemetry."""
    provider = MockGeoIPProvider()

    for test_ip in ["192.0.2.14", "198.51.100.18", "203.0.113.72"]:
        res = provider.lookup(test_ip)
        assert res.source == "mock"
        assert res.is_simulated is True
        assert res.approximate is True
        assert res.country != "Unknown"
        assert res.city != "Unknown"
        assert res.latitude is not None
        assert res.longitude is not None
        assert res.asn is not None
        assert "RFC 5737" in res.note


def test_arbitrary_public_ips_never_invent_fake_geodata():
    """
    CRITICAL: Verifies that arbitrary public IPs without verified MMDB records
    are NEVER assigned fake countries, cities, coordinates, or ASNs.
    """
    provider = MockGeoIPProvider()

    arbitrary_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.190.46",
        "104.244.42.1",
        "185.199.108.153"
    ]

    for ip in arbitrary_ips:
        res = provider.lookup(ip)
        assert res.country == "Unknown", f"Expected 'Unknown' country for {ip}, got {res.country}"
        assert res.city == "Unknown", f"Expected 'Unknown' city for {ip}, got {res.city}"
        assert res.latitude is None, f"Expected None latitude for {ip}, got {res.latitude}"
        assert res.longitude is None, f"Expected None longitude for {ip}, got {res.longitude}"
        assert res.asn is None, f"Expected None asn for {ip}, got {res.asn}"
        assert res.isp is None, f"Expected None isp for {ip}, got {res.isp}"
        assert res.is_simulated is False
        assert res.source == "mock"
        assert "Unmapped public IP" in res.note


def test_private_and_loopback_handling():
    """Verifies local lab and internal/loopback IP addresses are handled as simulated without false geo."""
    provider = MockGeoIPProvider()

    # 127.0.0.1 is configured as local deception lab in mock database
    res_local = provider.lookup("127.0.0.1")
    assert res_local.city == "Chennai (Local Lab)"
    assert res_local.is_simulated is True

    # Generic unmapped RFC 1918 / IPv6 loopback
    for ip in ["::1", "10.0.0.5", "192.168.1.100", "172.16.0.1"]:
        res = provider.lookup(ip)
        assert res.country == "Internal Network"
        assert res.city == "Loopback / LAN"
        assert res.is_simulated is True


def test_maxmind_fallback_when_database_missing():
    """
    Verifies that MaxMindGeoIPProvider reports unavailable when files are absent,
    and build_provider("maxmind") gracefully falls back to MockGeoIPProvider.
    """
    maxmind_raw = MaxMindGeoIPProvider(
        db_path="nonexistent/path/GeoLite2-City.mmdb",
        asn_db_path="nonexistent/path/GeoLite2-ASN.mmdb"
    )
    assert maxmind_raw.is_available() is False
    assert maxmind_raw.lookup("8.8.8.8") is None

    # build_provider factory safely falls back to MockGeoIPProvider
    provider = build_provider("maxmind")
    assert isinstance(provider, MockGeoIPProvider)

    # Lookup through fallback provider works safely
    res_rfc = provider.lookup("192.0.2.14")
    assert res_rfc.is_simulated is True
    assert res_rfc.country != "Unknown"

    res_pub = provider.lookup("8.8.8.8")
    assert res_pub.country == "Unknown"
    assert res_pub.is_simulated is False


def test_enrich_ip_persists_simulation_metadata(soc_app):
    """Verifies that the enrichment service persists and returns simulation metadata."""
    with soc_app.app_context():
        # RFC 5737 IP
        data_sim = enrich_ip("192.0.2.99")
        assert data_sim["is_simulated"] is True
        assert data_sim["source"] == "mock"
        assert data_sim["country"] != "Unknown"

        # Verify cached in GeoIPRecord
        rec = GeoIPRecord.query.filter_by(ip="192.0.2.99").first()
        assert rec is not None
        assert rec.source == "mock"

        # Arbitrary public IP
        data_pub = enrich_ip("142.250.190.1")
        assert data_pub["is_simulated"] is False
        assert data_pub["country"] == "Unknown"
        assert data_pub["latitude"] is None
