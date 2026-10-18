"""ARP spoofing (man-in-the-middle).

An attacker sends forged ARP replies claiming "I am the router", so victims
send their traffic through the attacker's laptop. We catch it when an IP
address we have already seen suddenly maps to a different MAC address.
"""

from __future__ import annotations

from scapy.layers.l2 import ARP

from sensor.alert import Alert, Endpoint, Severity, Zone
from sensor.detectors.base import Detector

ARP_REPLY = 2


class ArpSpoofDetector(Detector):
    name = "arp_spoof"

    def __init__(
        self,
        gateway_ip: str | None = None,
        gateway_mac: str | None = None,
        cooldown: float = 60.0,
    ) -> None:
        super().__init__(cooldown)
        self.gateway_ip = gateway_ip
        self.ip_to_mac: dict[str, str] = {}
        self.mac_to_ip: dict[str, str] = {}
        if gateway_ip and gateway_mac:
            self.ip_to_mac[gateway_ip] = gateway_mac.lower()

    def process(self, pkt, now: float) -> list[Alert]:
        if ARP not in pkt:
            return []
        arp = pkt[ARP]
        ip, mac = arp.psrc, (arp.hwsrc or "").lower()
        if not ip or ip == "0.0.0.0" or not mac:
            return []

        known_mac = self.ip_to_mac.get(ip)
        alerts = []
        if known_mac is None:
            self.ip_to_mac[ip] = mac
        elif known_mac != mac and self.should_alert((ip, mac), now):
            alerts.append(self._alert(ip, known_mac, mac, arp.op == ARP_REPLY, now))
        # Remember the attacker's own address so the alert can name them.
        self.mac_to_ip.setdefault(mac, ip)
        return alerts

    def _alert(self, ip: str, real_mac: str, fake_mac: str, is_reply: bool, now: float) -> Alert:
        attacker_ip = self.mac_to_ip.get(fake_mac)
        if attacker_ip == ip:
            attacker_ip = None
        who = f"Device {attacker_ip} ({fake_mac})" if attacker_ip else f"Device {fake_mac}"
        is_gateway = ip == self.gateway_ip
        if is_gateway:
            reason = (f"{who} is pretending to be your router {ip}. "
                      "Someone may be reading your traffic.")
        else:
            reason = (f"{who} is claiming to be {ip}, which belongs to {real_mac}. "
                      "Traffic meant for that device may be intercepted.")
        return Alert(
            zone=Zone.INSIDE,
            attack="arp_spoofing",
            severity=Severity.CRITICAL if is_gateway else Severity.HIGH,
            reason=reason,
            source=Endpoint(ip=attacker_ip, mac=fake_mac),
            target=Endpoint(ip=ip, mac=real_mac),
            details={"spoofed_ip": ip, "expected_mac": real_mac, "seen_mac": fake_mac,
                     "arp_reply": is_reply, "is_gateway": is_gateway},
            timestamp=now,
        )
