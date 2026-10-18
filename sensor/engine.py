"""Feeds packets through every detector and hands alerts to the outputs."""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterable

from sensor.alert import Alert
from sensor.detectors import Detector

log = logging.getLogger(__name__)

Sink = Callable[[Alert], None]


class Sensor:
    def __init__(self, detectors: Iterable[Detector], sinks: Iterable[Sink], name: str = "sensor") -> None:
        self.detectors = list(detectors)
        self.sinks = list(sinks)
        self.name = name
        self.packets_seen = 0
        self.alerts_raised = 0

    def handle(self, pkt) -> list[Alert]:
        self.packets_seen += 1
        now = float(getattr(pkt, "time", None) or time.time())
        alerts = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.process(pkt, now))
            except Exception:
                # One malformed packet must never take the whole sensor down.
                log.exception("detector %s failed on packet %s", detector.name, pkt.summary())
        for alert in alerts:
            alert.sensor = self.name
            self.alerts_raised += 1
            for sink in self.sinks:
                sink(alert)
        return alerts
