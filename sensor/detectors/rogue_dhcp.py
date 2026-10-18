"""Rogue DHCP server.

An attacker runs a fake address-giver so new devices take their network
settings (router, DNS server) from the attacker. We catch it when DHCP
offers or acks come from a server that isn't the real one.

If trusted servers are configured, anything else is rogue. Otherwise the
first DHCP server seen is assumed to be the real one.
"""

from __future__ import annotations

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from sensor.alert import Alert, Endpoint, Severity, Zone
from sensor.detectors.base import Detector

# Scapy gives the message type as an int once parsed, or a name when built in code.
SERVER_MESSAGES = {2: "offer", 5: "ack", "offer": "offer", "ack": "ack"}


def _options(pkt) -> dict:
    return {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple) and len(opt) >= 2}


class RogueDhcpDetector(Detector):
    name = "rogue_dhcp"

    def __init__(self, trusted_servers: list[str] | None = None, cooldown: float = 60.0) -> None:
        super().__init__(cooldown)
        self.trusted = set(trusted_servers or [])
        self._learn = not self.trusted

    def process(self, pkt, now: float) -> list[Alert]:
        if DHCP not in pkt:
            return []
        opts = _options(pkt)
        msg = SERVER_MESSAGES.get(opts.get("message-type"))
        if msg is None:
            return []

        server = opts.get("server_id") or (pkt[IP].src if IP in pkt else None)
        if not server:
            return []
        if self._learn and not self.trusted:
            self.trusted.add(server)
            return []
        if server in self.trusted or not self.should_alert(server, now):
            return []

        mac = pkt[Ether].src.lower() if Ether in pkt else None
        router = opts.get("router")
        dns = opts.get("name_server")
        hijack = []
        if router:
            hijack.append(f"router {router}")
        if dns:
            hijack.append(f"DNS server {dns}")
        effect = (f" It is telling devices to use {' and '.join(hijack)}, so it could "
                  "redirect their traffic.") if hijack else ""
        return [Alert(
            zone=Zone.INSIDE,
            attack="rogue_dhcp",
            severity=Severity.HIGH,
            reason=(f"Device {server} is handing out network addresses, but it isn't your "
                    f"real DHCP server ({', '.join(sorted(self.trusted))}).{effect}"),
            source=Endpoint(ip=server, mac=mac),
            details={"message": msg, "trusted_servers": sorted(self.trusted),
                     "offered_router": router, "offered_dns": dns},
            timestamp=now,
        )]
