from sensor.alert import Severity, Zone
from sensor.detectors import ArpSpoofDetector, PortScanDetector, RogueDhcpDetector
from sensor.engine import Sensor
from tools.make_captures import (
    ATTACKER_IP, ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC, START, VICTIM_IP, VICTIM_MAC,
    arp_reply, arp_spoof_capture, dhcp_offer, port_scan_capture, rogue_dhcp_capture, syn,
)


def run(detector, packets):
    alerts = []
    sensor = Sensor([detector], [alerts.append])
    for pkt in packets:
        sensor.handle(pkt)
    return alerts


# --- ARP spoofing ---

def test_arp_spoof_of_gateway_is_critical_and_names_attacker():
    alerts = run(ArpSpoofDetector(gateway_ip=GATEWAY_IP), arp_spoof_capture())
    assert len(alerts) == 1  # cooldown suppresses the repeated lies
    a = alerts[0]
    assert (a.zone, a.attack, a.severity) == (Zone.INSIDE, "arp_spoofing", Severity.CRITICAL)
    assert a.source.ip == ATTACKER_IP and a.source.mac == ATTACKER_MAC
    assert a.target.mac == GATEWAY_MAC
    assert "pretending to be your router" in a.reason


def test_arp_spoof_with_pinned_gateway_mac_catches_first_lie():
    det = ArpSpoofDetector(gateway_ip=GATEWAY_IP, gateway_mac=GATEWAY_MAC)
    alerts = run(det, [arp_reply(GATEWAY_IP, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC, START)])
    assert len(alerts) == 1 and alerts[0].severity == Severity.CRITICAL


def test_arp_spoof_of_non_gateway_is_high():
    pkts = [arp_reply(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC, START),
            arp_reply(VICTIM_IP, ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC, START + 1)]
    alerts = run(ArpSpoofDetector(gateway_ip=GATEWAY_IP), pkts)
    assert len(alerts) == 1 and alerts[0].severity == Severity.HIGH


def test_normal_arp_is_quiet():
    pkts = [arp_reply(GATEWAY_IP, GATEWAY_MAC, VICTIM_IP, VICTIM_MAC, START + i) for i in range(5)]
    assert run(ArpSpoofDetector(gateway_ip=GATEWAY_IP), pkts) == []


def test_arp_cooldown_expires():
    det = ArpSpoofDetector(gateway_ip=GATEWAY_IP, gateway_mac=GATEWAY_MAC, cooldown=60)
    pkts = [arp_reply(GATEWAY_IP, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC, START + t) for t in (0, 30, 61)]
    assert len(run(det, pkts)) == 2


# --- Port scan ---

def test_port_scan_detected_once():
    alerts = run(PortScanDetector(threshold=50, window=10), port_scan_capture())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.attack == "port_scan" and a.source.ip == ATTACKER_IP and a.target.ip == VICTIM_IP
    assert a.details["ports_probed"] == 50


def test_slow_probing_outside_window_is_quiet():
    pkts = [syn(ATTACKER_IP, VICTIM_IP, port, START + port) for port in range(1, 100)]
    assert run(PortScanDetector(threshold=50, window=10), pkts) == []


def test_repeated_connections_to_one_port_are_quiet():
    pkts = [syn(VICTIM_IP, GATEWAY_IP, 443, START + i * 0.01, sport=50000 + i) for i in range(200)]
    assert run(PortScanDetector(threshold=50, window=10), pkts) == []


# --- Rogue DHCP ---

def test_rogue_dhcp_learns_first_server():
    alerts = run(RogueDhcpDetector(), rogue_dhcp_capture())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.attack == "rogue_dhcp" and a.source.ip == ATTACKER_IP and a.source.mac == ATTACKER_MAC
    assert a.details["offered_dns"] == ATTACKER_IP
    assert "isn't your real DHCP server" in a.reason


def test_rogue_dhcp_with_trusted_list():
    det = RogueDhcpDetector(trusted_servers=[GATEWAY_IP])
    alerts = run(det, [dhcp_offer(ATTACKER_IP, ATTACKER_MAC, START)])
    assert len(alerts) == 1


def test_trusted_dhcp_is_quiet():
    det = RogueDhcpDetector(trusted_servers=[GATEWAY_IP])
    assert run(det, [dhcp_offer(GATEWAY_IP, GATEWAY_MAC, START + i) for i in range(3)]) == []


# --- Engine & format ---

def test_alert_json_has_shared_fields():
    alerts = run(ArpSpoofDetector(gateway_ip=GATEWAY_IP), arp_spoof_capture())
    data = alerts[0].to_dict()
    for key in ("id", "timestamp", "sensor", "zone", "attack", "severity", "reason", "source"):
        assert key in data
    assert data["zone"] == "inside" and data["severity"] == "critical"
    assert data["timestamp"].startswith("2025-10-09")


def test_broken_detector_does_not_stop_others():
    class Boom(PortScanDetector):
        name = "boom"

        def process(self, pkt, now):
            raise ValueError("bad packet")

    alerts = []
    sensor = Sensor([Boom(), ArpSpoofDetector(gateway_ip=GATEWAY_IP)], [alerts.append])
    for pkt in arp_spoof_capture():
        sensor.handle(pkt)
    assert len(alerts) == 1
