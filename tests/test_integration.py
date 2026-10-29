"""Exercise sensor -> HTTP -> database -> WebSocket and dashboard serving."""
import httpx
from fastapi.testclient import TestClient
from server.app import create_app
from sensor.output import HttpSink
from sensor.alert import Alert, Endpoint, Severity, Zone
from sensor.__main__ import prediction_alert


def test_sensor_delivery_and_dashboard(tmp_path):
    app = create_app(str(tmp_path / "integration.db"))
    client = TestClient(app)
    sink = HttpSink("http://testserver")
    sink.client.close()
    sink.client = client
    alert = Alert(zone=Zone.INSIDE, attack="port_scan", severity=Severity.HIGH,
                  reason="Test scan", source=Endpoint(ip="192.168.1.7"), timestamp=1)
    with client.websocket_connect("/ws") as ws:
        sink(alert)
        assert ws.receive_json()["id"] == alert.id
    assert client.get("/stats").json()["total"] == 1
    assert client.get("/alerts").json()[0]["reason"] == "Test scan"
    assert client.get("/").status_code == 200
    assert "window.location.origin" in client.get("/js/api.js").text


def test_failed_delivery_does_not_crash(caplog):
    sink = HttpSink("http://testserver")
    sink.client.close()
    def unavailable(request):
        raise httpx.ConnectError("offline", request=request)
    sink.client = httpx.Client(transport=httpx.MockTransport(unavailable))
    sink(Alert(zone=Zone.INSIDE, attack="test", severity=Severity.LOW,
               reason="test", source=Endpoint(ip="192.168.1.2"), timestamp=1))
    sink.close()
    assert "was not delivered" in caplog.text


def test_ml_benign_and_flagged_contract():
    flow = {"metadata": {"src_ip": "192.168.1.2", "dst_ip": "192.168.1.3",
                         "src_port": 40000, "dst_port": 80}}
    prediction = {"attack_class": "BENIGN", "is_anomaly": False}
    assert prediction_alert(flow, prediction, "inside", "test") is None
    alert = prediction_alert(flow, {**prediction, "is_anomaly": True}, "inside", "test")
    assert alert.attack == "ml_anomaly"
    attack = prediction_alert(flow, {"attack_class": "PortScan", "is_anomaly": False}, "inbound", "test")
    assert attack.zone == Zone.INBOUND and attack.attack == "ml_portscan"
