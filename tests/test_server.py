import time

import pytest
from fastapi.testclient import TestClient

from server.app import create_app

ARP = {
    "id": "a1", "zone": "inside", "attack": "arp_spoofing", "severity": "critical",
    "reason": "Device 192.168.1.7 is pretending to be your router 192.168.1.1.",
    "source": {"ip": "192.168.1.7", "mac": "aa:bb:cc:00:00:07", "port": None},
    "target": {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "port": None},
    "details": {"is_gateway": True}, "timestamp": "2025-10-09T10:00:00+00:00",
    "sensor": "sensor-a",
}


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "t.db")))


def test_post_and_get_keeps_nested_shape(client):
    r = client.post("/alerts", json=ARP)
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "a1" and body["source"]["ip"] == "192.168.1.7"
    assert body["target"]["mac"] == "aa:bb:cc:00:00:01"
    assert body["details"] == {"is_gateway": True} and body["country"] is None
    assert client.get("/alerts/a1").json()["attack"] == "arp_spoofing"


def test_missing_id_and_timestamp_are_filled(client):
    a = {k: v for k, v in ARP.items() if k not in ("id", "timestamp")}
    body = client.post("/alerts", json=a).json()
    assert len(body["id"]) == 32 and body["timestamp"]


def test_duplicate_id_is_not_stored_twice(client):
    assert client.post("/alerts", json=ARP).status_code == 201
    assert client.post("/alerts", json=ARP).status_code == 200
    assert len(client.get("/alerts").json()) == 1


def test_bad_alerts_rejected(client):
    assert client.post("/alerts", json={k: v for k, v in ARP.items() if k != "reason"}).status_code == 422
    assert client.post("/alerts", json={**ARP, "zone": "lan"}).status_code == 422
    assert client.post("/alerts", json={**ARP, "severity": "huge"}).status_code == 422


def test_case_is_normalised(client):
    body = client.post("/alerts", json={**ARP, "zone": "INSIDE", "severity": "High"}).json()
    assert body["zone"] == "inside" and body["severity"] == "high"


def test_filters_newest_first_and_stats(client):
    client.post("/alerts", json=ARP)
    client.post("/alerts", json={**ARP, "id": "b2", "zone": "outbound", "attack": "beaconing",
                                 "severity": "medium", "timestamp": "2025-10-09T11:00:00+00:00"})
    ids = [a["id"] for a in client.get("/alerts").json()]
    assert ids == ["b2", "a1"]
    assert len(client.get("/alerts?zone=outbound").json()) == 1
    assert len(client.get("/alerts?attack=arp_spoofing").json()) == 1
    s = client.get("/stats").json()
    assert s["total"] == 2 and s["by_zone"] == {"inside": 1, "outbound": 1}


def test_unknown_alert_404(client):
    assert client.get("/alerts/nope").status_code == 404


def test_websocket_pushes_new_alert_once(client):
    with client.websocket_connect("/ws") as ws:
        client.post("/alerts", json=ARP)
        assert ws.receive_json()["attack"] == "arp_spoofing"


def test_api_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_API_KEY", "secret")
    c = TestClient(create_app(str(tmp_path / "k.db")))
    assert c.post("/alerts", json=ARP).status_code == 401
    assert c.post("/alerts", json=ARP, headers={"X-API-Key": "secret"}).status_code == 201


def test_real_sensor_alert_is_accepted(client):
    """The sensor's own Alert.to_json() output must be accepted as-is."""
    pytest.importorskip("sensor.alert")
    import json
    from sensor.alert import Alert, Endpoint, Severity, Zone
    alert = Alert(zone=Zone.INSIDE, attack="rogue_dhcp", severity=Severity.HIGH,
                  reason="Device 10.0.0.9 isn't your real DHCP server.",
                  source=Endpoint(ip="10.0.0.9", mac="aa:aa:aa:aa:aa:09"),
                  details={"offered_dns": "10.0.0.9"}, timestamp=time.time(), sensor="sensor-a")
    r = client.post("/alerts", json=json.loads(alert.to_json()))
    assert r.status_code == 201
    assert r.json()["id"] == alert.id and r.json()["details"]["offered_dns"] == "10.0.0.9"
