"""
Honeypot Nexus - Reputation & Anomaly Intelligence
Detects suspected VPN and Tor Exit Node membership using synthetic local threat lists.
"""

from pathlib import Path
from typing import Set
import re
from app.config import BASE_DIR


class ReputationService:
    def __init__(self):
        self.tor_ips: Set[str] = set()
        self.vpn_asns: Set[str] = set()
        self.vpn_keywords = re.compile(r"(vpn|proxy|hosting|datacenter|cloud|colocation|server)", re.IGNORECASE)
        self._load_threat_data()

    def _load_threat_data(self):
        tor_path = BASE_DIR / "data" / "tor_exit_nodes.txt"
        if tor_path.exists():
            with open(tor_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.tor_ips.add(line)

        vpn_path = BASE_DIR / "data" / "vpn_asns.txt"
        if vpn_path.exists():
            with open(vpn_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.vpn_asns.add(line)

    def is_tor_exit_node(self, ip: str) -> bool:
        return ip in self.tor_ips

    def is_vpn_suspected(self, asn: str = None, org: str = None, isp: str = None) -> bool:
        if asn and asn in self.vpn_asns:
            return True
        for candidate in (org, isp):
            if candidate and self.vpn_keywords.search(candidate):
                return True
        return False
