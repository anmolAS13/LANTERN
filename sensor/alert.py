"""The shared alert format.

Every detector, on every sensor, emits alerts in this one shape. Keeping a
single format is what lets all detectors plug into the same server and
dashboard. See docs/alert-format.md for the field reference.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Zone(str, Enum):
    INSIDE = "inside"      # Zone 1: devices on our network attacking each other
    INBOUND = "inbound"    # Zone 2: internet attackers hitting our server
    OUTBOUND = "outbound"  # Zone 3: our devices talking to attackers


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Endpoint:
    ip: str | None = None
    mac: str | None = None
    port: int | None = None

    def __str__(self) -> str:
        parts = [p for p in (self.ip, self.mac) if p]
        return " / ".join(parts) or "unknown"


@dataclass
class Alert:
    zone: Zone
    attack: str
    severity: Severity
    reason: str
    source: Endpoint
    target: Endpoint | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    sensor: str = "sensor"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["zone"] = self.zone.value
        data["severity"] = self.severity.value
        data["timestamp"] = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
