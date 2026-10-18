# Shared alert format

Every detector on every sensor emits alerts in this one shape (`sensor/alert.py`).
The central server and dashboard rely on it, so change it only as a team.

```json
{
  "id": "3f2c9a…",
  "timestamp": "2025-10-09T08:53:25+00:00",
  "sensor": "sensor-a",
  "zone": "inside",
  "attack": "arp_spoofing",
  "severity": "critical",
  "reason": "Device 192.168.1.7 (cc:cc:cc:cc:cc:07) is pretending to be your router 192.168.1.1. Someone may be reading your traffic.",
  "source": {"ip": "192.168.1.7", "mac": "cc:cc:cc:cc:cc:07", "port": null},
  "target": {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01", "port": null},
  "details": {"spoofed_ip": "192.168.1.1", "expected_mac": "aa:aa:aa:aa:aa:01", "...": "..."}
}
```

| Field | Meaning |
| --- | --- |
| `id` | Unique alert ID |
| `timestamp` | When the triggering packet was captured (UTC, ISO 8601). In replay mode this is the capture time, not now |
| `sensor` | Which sensor raised it (`--name`) |
| `zone` | `inside`, `inbound` or `outbound` |
| `attack` | Short machine name, e.g. `arp_spoofing`, `port_scan`, `rogue_dhcp` |
| `severity` | `low`, `medium`, `high` or `critical` |
| `reason` | One plain-English sentence anyone can act on |
| `source` | The attacker (or the infected device, for outbound) |
| `target` | Who is being attacked, if known |
| `details` | Detector-specific evidence for the curious |

## Writing a new detector

1. Add a module in `sensor/detectors/` with a class that extends `Detector`.
2. Implement `process(pkt, now) -> list[Alert]`. Use `now` (the packet's capture time), never `time.time()`, so replay behaves like live traffic.
3. Wrap each alert in `self.should_alert(key, now)` so one ongoing attack doesn't flood the feed.
4. Register it in `sensor/detectors/__init__.py` and `build_sensor` in `sensor/__main__.py`.
5. Add a packet builder to `tools/make_captures.py` and tests in `tests/`.
