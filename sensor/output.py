"""Where alerts go. The central server sink will be added once it exists."""

from __future__ import annotations

from datetime import datetime

from sensor.alert import Alert, Severity

ICONS = {Severity.LOW: "ℹ️ ", Severity.MEDIUM: "⚠️ ", Severity.HIGH: "🚨", Severity.CRITICAL: "🔥"}


def console_sink(alert: Alert) -> None:
    ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
    print(f"{ICONS[alert.severity]} [{ts}] {alert.severity.value.upper():8} "
          f"{alert.zone.value}/{alert.attack}: {alert.reason}", flush=True)


class JsonlSink:
    """Appends one JSON alert per line, ready to ship to the server later."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __call__(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(alert.to_json() + "\n")
