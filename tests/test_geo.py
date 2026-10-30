from fastapi.testclient import TestClient

from server.app import create_app
from server.geo import GeoLookup, alert_ip


class FakeGeo:
    """Stands in for the real database so tests need no MaxMind file."""
    enabled = True

    def __init__(self):
        self.asked = []

    def lookup(self, ip):
        self.asked.append(ip)
        return {"8.8.8.8": "US", "114.114.114.114": "CN"}.get(ip)


def alert(zone, src, tgt, id_="g1"):
    return {"id": id_, "zone": zone, "attack": "x", "severity": "low", "reason": "r",
            "source": {"ip": src}, "target": {"ip": tgt} if tgt else None}


def test_inbound_looks_up_source():
    assert alert_ip(alert("inbound", "8.8.8.8", "198.51.100.10")) == "8.8.8.8"


def test_outbound_looks_up_target():
    assert alert_ip(alert("outbound", "192.168.1.15", "114.114.114.114")) == "114.114.114.114"


def test_inside_is_never_looked_up():
    assert alert_ip(alert("inside", "8.8.8.8", "8.8.4.4")) is None


def test_private_reserved_missing_and_invalid_are_skipped():
    for ip in ("192.168.1.7", "10.0.0.1", "127.0.0.1", "203.0.113.5", "not-an-ip", None):
        assert alert_ip(alert("inbound", ip, None)) is None
    assert alert_ip(alert("outbound", "192.168.1.15", None)) is None


def test_country_is_filled_on_the_server(tmp_path):
    c = TestClient(create_app(str(tmp_path / "g.db"), geo=FakeGeo()))
    assert c.post("/alerts", json=alert("inbound", "114.114.114.114", None, "a")).json()["country"] == "CN"
    assert c.post("/alerts", json=alert("inside", "192.168.1.7", None, "b")).json()["country"] is None
    assert c.post("/alerts", json=alert("inbound", "9.9.9.9", None, "c")).json()["country"] is None  # not in db
    assert c.get("/alerts/a").json()["country"] == "CN"  # and it was stored


def test_missing_database_file_is_harmless(tmp_path):
    geo = GeoLookup(str(tmp_path / "does-not-exist.mmdb"))
    assert geo.enabled is False and geo.lookup("8.8.8.8") is None
    c = TestClient(create_app(str(tmp_path / "h.db"), geo=geo))
    assert c.post("/alerts", json=alert("inbound", "8.8.8.8", None)).json()["country"] is None
    assert c.get("/health").json() == {"status": "ok", "geoip": False}
