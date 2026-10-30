"""GeoIP: turn an attacker's IP address into a country code like "CN".

Uses MaxMind's free GeoLite2-Country database, an offline file.
If the geoip2 library or the .mmdb file is missing, the server still works,
`country` just stays null. Set LANTERN_GEOIP_DB to point at the file
(default: GeoLite2-Country.mmdb in the folder you start the server from).
"""
import ipaddress
import logging
import os
from typing import Optional

log = logging.getLogger("uvicorn.error")


def alert_ip(alert: dict) -> Optional[str]:
    """Which IP of this alert is worth looking up?

    inbound  -> the attacker on the internet = source
    outbound -> the remote server our device talks to = target
    inside   -> LAN addresses have no country = None
    Private / reserved / invalid addresses are skipped.
    """
    zone = alert.get("zone")
    side = {"inbound": "source", "outbound": "target"}.get(zone)
    if side is None:
        return None
    ip = (alert.get(side) or {}).get("ip")
    if not ip:
        return None
    try:
        return ip if ipaddress.ip_address(ip).is_global else None
    except ValueError:
        return None


class GeoLookup:
    def __init__(self, path: Optional[str] = None):
        path = path or os.environ.get("LANTERN_GEOIP_DB", "GeoLite2-Country.mmdb")
        self.reader = None
        try:
            import geoip2.database  # optional dependency
            self.reader = geoip2.database.Reader(path)
            log.info("GeoIP enabled (%s)", path)
        except ImportError:
            log.warning("GeoIP disabled: run 'pip install geoip2'")
        except Exception as e:
            log.warning("GeoIP disabled: could not open %s (%s)", path, e)

    @property
    def enabled(self) -> bool:
        return self.reader is not None

    def lookup(self, ip: str) -> Optional[str]:
        """Country code for an IP, or None if unknown / disabled."""
        if self.reader is None:
            return None
        try:
            return self.reader.country(ip).country.iso_code
        except Exception:  # address not in the database, bad input, ...
            return None
