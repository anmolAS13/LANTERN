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


class HttpSink:
    """Send alerts to the central server; report failures without stopping capture.

    JSONL output can be enabled alongside this sink as a local backup.
    """

    def __init__(self, server_url: str, api_key: str | None = None) -> None:
        import httpx
        self.client = httpx.Client(timeout=3.0, trust_env=False)
        self.url = server_url.rstrip("/") + "/alerts"
        self.headers = {"X-API-Key": api_key} if api_key else {}

    def __call__(self, alert: Alert) -> None:
        import logging
        import httpx
        try:
            response = self.client.post(self.url, json=alert.to_dict(), headers=self.headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logging.getLogger(__name__).warning("Alert %s was not delivered: %s", alert.id, exc)

    def close(self) -> None:
        self.client.close()
