from __future__ import annotations

from typing import Any

from sensor.alert import Alert


class Detector:
    """Base class for one attack-pattern detector.

    Subclasses implement `process`, which receives every packet (with its
    capture time, so replayed captures behave like live traffic) and returns
    any alerts it raises.
    """

    name = "detector"

    def __init__(self, cooldown: float = 60.0) -> None:
        # Stops one ongoing attack from flooding the feed with identical alerts.
        self.cooldown = cooldown
        self._last_alert: dict[Any, float] = {}

    def process(self, pkt, now: float) -> list[Alert]:
        raise NotImplementedError

    def should_alert(self, key: Any, now: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cooldown:
            return False
        self._last_alert[key] = now
        return True
