# LANTERN server

FastAPI + SQLite. Receives alerts from sensors, stores them, pushes them live to the dashboard.

## Run it (from the repo root)

    pip install fastapi uvicorn httpx pytest
    uvicorn server.app:app --reload
    # in a second terminal, make some fake alerts:
    python tools/send_fake_alerts.py

Interactive docs (try every endpoint in the browser): http://127.0.0.1:8000/docs
Tests: `pytest tests/test_server.py`

## For the dashboard (Aryan)

| Endpoint | Use it for |
|---|---|
| `GET /alerts?zone=&severity=&attack=&limit=&offset=` | Load recent alerts on page load (newest first) |
| `WS ws://127.0.0.1:8000/ws` | Live feed: every new alert arrives as one JSON message |
| `GET /stats` | Counters: `{total, by_zone, by_severity, by_attack}` |
| `GET /alerts/{id}` | One alert |
| `GET /health` | Is the server up? |

Allowed values: zone = `inside` / `inbound` / `outbound`; severity = `low` / `medium` / `high` / `critical`.

### One alert (this exact shape is what `/alerts` and `/ws` return)

    {
      "id": "9f2c...",
      "zone": "inside",
      "attack": "arp_spoofing",
      "severity": "critical",
      "reason": "Device 192.168.1.7 is pretending to be your router 192.168.1.1. Someone may be reading your traffic.",
      "source": {"ip": "192.168.1.7", "mac": "aa:bb:cc:00:00:07", "port": null},
      "target": {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "port": null},
      "details": {"is_gateway": true},
      "timestamp": "2025-10-09T10:00:00+00:00",
      "sensor": "sensor-a",
      "country": null
    }

Notes: `target` can be null. `details` differs per attack. Timestamps are UTC.

`country` is a 2-letter code like `"CN"`, filled in by the server (never the sensor) from
the attacker's IP: the `source` for `inbound` alerts, the `target` for `outbound` ones.
It is `null` for `inside` alerts, private/reserved IPs, IPs the database doesn't know, and
whenever GeoIP isn't set up. The dashboard must handle `null`.

## For sensors

`POST /alerts` with the JSON from the sensor's `Alert.to_json()`. Returns 201 (stored) or
200 (this id was already stored, so a retry is harmless). Bad data returns 422 with the reason.
Optional: set `LANTERN_API_KEY` on the server and send an `X-API-Key` header.

## GeoIP setup (optional)

1. `pip install geoip2`
2. Free account at MaxMind, download **GeoLite2 Country** (the .mmdb file) from the account portal.
3. Put `GeoLite2-Country.mmdb` in the folder you start the server from, or set `LANTERN_GEOIP_DB`
   to its path. Never commit the file (it is git-ignored).
4. Check: `GET /health` shows `"geoip": true`.

Test with real public IPs: `python tools/send_fake_alerts.py --real-ips`

Database file: `lantern.db` (override with `LANTERN_DB`). Keep it out of git.
