"""Port scan.

A scanner knocks on many ports to find open ones. We catch it when one
device sends bare SYN packets (connection attempts) to many different ports
within a short window.
"""

from __future__ import annotations

from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP

from sensor.alert import Alert, Endpoint, Severity, Zone
from sensor.detectors.base import Detector

SYN, ACK = 0x02, 0x10


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self, threshold: int = 50, window: float = 10.0, cooldown: float = 60.0) -> None:
        super().__init__(cooldown)
        self.threshold = threshold
        self.window = window
        # (src, dst) -> recent (time, port) SYNs, oldest first
        self._syns: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)

    def process(self, pkt, now: float) -> list[Alert]:
        if IP not in pkt or TCP not in pkt:
            return []
        flags = int(pkt[TCP].flags)
        if not flags & SYN or flags & ACK:
            return []

        src, dst, port = pkt[IP].src, pkt[IP].dst, pkt[TCP].dport
        recent = self._syns[(src, dst)]
        recent.append((now, port))
        while recent and now - recent[0][0] > self.window:
            recent.popleft()

        ports = {p for _, p in recent}
        if len(ports) < self.threshold or not self.should_alert((src, dst), now):
            return []
        return [Alert(
            zone=Zone.INSIDE,
            attack="port_scan",
            severity=Severity.MEDIUM,
            reason=(f"Device {src} probed {len(ports)} different ports on {dst} in "
                    f"{self.window:g} seconds. It is looking for weak spots to attack."),
            source=Endpoint(ip=src),
            target=Endpoint(ip=dst),
            details={"ports_probed": len(ports), "window_seconds": self.window,
                     "sample_ports": sorted(ports)[:20]},
            timestamp=now,
        )]
