"""Send realistic FAKE alerts to the LANTERN server so the dashboard can be
built and demoed without any sensors running.

    python tools/send_fake_alerts.py                 # 20 alerts, 1 per second
    python tools/send_fake_alerts.py --count 100 --interval 0.2
    python tools/send_fake_alerts.py --url http://192.168.1.10:8000 --api-key secret

Uses only the standard library. All IPs are reserved documentation/private ranges.
"""
import argparse
import json
import random
import time
import urllib.request
import uuid
from datetime import datetime, timezone


def ep(ip=None, mac=None, port=None):
    return {"ip": ip, "mac": mac, "port": port}


def make_alert():
    atk = random.choice([
        ("inside", "arp_spoofing", "critical",
         "Device 192.168.1.7 is pretending to be your router 192.168.1.1. Someone may be reading your traffic.",
         ep("192.168.1.7", "aa:bb:cc:00:00:07"), ep("192.168.1.1", "aa:bb:cc:00:00:01"), {"is_gateway": True}),
        ("inside", "port_scan", "high",
         "Device 192.168.1.7 probed 50 different ports on 192.168.1.20 in 10 seconds.",
         ep("192.168.1.7"), ep("192.168.1.20"), {"ports_probed": 50}),
        ("inside", "rogue_dhcp", "high",
         "Device 192.168.1.9 is handing out network addresses, but it isn't your real DHCP server.",
         ep("192.168.1.9", "aa:bb:cc:00:00:09"), None, {"offered_dns": "192.168.1.9"}),
        ("inbound", "ssh_brute_force", "high",f"{(ip := '203.0.113.%d' % random.randint(2, 250))} tried 40 passwords on your server's SSH login in one minute.",
         ep(ip, None, random.randint(40000, 60000)), ep("198.51.100.10", None, 22),
         {"attempts": 40}),
        ("inbound", "sql_injection", "medium",
         "A request to /login contained SQL code meant to trick the database.",
         ep("203.0.113.%d" % random.randint(2, 250)), ep("198.51.100.10", None, 80), {"path": "/login"}),
        ("outbound", "beaconing", "medium",
         "Device 192.168.1.15 contacts 198.51.100.77 every 10 seconds, like malware phoning home.",
         ep("192.168.1.15"), ep("198.51.100.77", None, 443), {"interval_seconds": 10}),
        ("outbound", "dns_tunneling", "high",
         "Device 192.168.1.15 is sending unusually long DNS names, which can hide stolen data.",
         ep("192.168.1.15"), ep("192.0.2.53", None, 53), {"avg_label_length": 52}),
    ])
    zone, attack, sev, reason, src, tgt, details = atk
    return {"id": uuid.uuid4().hex, "zone": zone, "attack": attack, "severity": sev,
            "reason": reason, "source": src, "target": tgt, "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(), "sensor": "fake-sensor"}


def post(url, alert, api_key=None):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url + "/alerts", json.dumps(alert).encode(), headers)
    with urllib.request.urlopen(req) as r:
        return r.status


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--api-key")
    a = p.parse_args()
    for i in range(a.count):
        alert = make_alert()
        status = post(a.url, alert, a.api_key)
        print(f"[{i + 1}/{a.count}] {status} {alert['zone']}/{alert['attack']} ({alert['severity']})")
        time.sleep(a.interval)
