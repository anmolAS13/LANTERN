"""LANTERN sensor command line.

    sudo python -m sensor live -i wlan0 --gateway-ip 192.168.1.1
    python -m sensor replay captures/arp_spoof.pcap --gateway-ip 192.168.1.1
"""

from __future__ import annotations

import argparse
import logging
import sys
import json
import os
import time
from pathlib import Path


from sensor.output import HttpSink, JsonlSink, console_sink
from sensor.alert import Alert, Endpoint, Severity, Zone

# Only the traffic our detectors look at, so the kernel drops the rest early.
CAPTURE_FILTER = "arp or (udp and (port 67 or port 68)) or tcp"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sensor", description="LANTERN network sensor")
    sub = parser.add_subparsers(dest="mode", required=True)

    live = sub.add_parser("live", help="capture packets from a network interface (needs root)")
    live.add_argument("-i", "--iface", help="interface to listen on (default: scapy's default)")

    replay = sub.add_parser("replay", help="run detections over a saved .pcap file")
    replay.add_argument("pcap", help="path to a .pcap or .pcapng file")

    for p in (live, replay):
        p.add_argument("--server", help="central server URL, e.g. http://127.0.0.1:8000")
        p.add_argument("--ml", action="store_true", help="enable saved ML models (requires matching training dependencies)")
        p.add_argument("--zone", choices=["inside", "inbound", "outbound"], default="inside", help="zone for ML flow alerts")
        p.add_argument("--name", default="sensor-a", help="sensor name shown on alerts")
        p.add_argument("--gateway-ip", help="the router's IP; spoofing it is critical")
        p.add_argument("--gateway-mac", help="the router's real MAC, if known")
        p.add_argument("--trusted-dhcp", action="append", default=[], metavar="IP",
                       help="a legitimate DHCP server (repeatable); otherwise the first one seen is trusted")
        p.add_argument("--scan-threshold", type=int, default=50,
                       help="distinct ports probed within the window that count as a scan")
        p.add_argument("--scan-window", type=float, default=10.0, help="port scan window in seconds")
        p.add_argument("--jsonl", metavar="PATH", help="also append alerts as JSON lines to this file")
    return parser


def build_sensor(args: argparse.Namespace) -> Sensor:
    from sensor.detectors import ArpSpoofDetector, PortScanDetector, RogueDhcpDetector
    from sensor.engine import Sensor
    detectors = [
        ArpSpoofDetector(gateway_ip=args.gateway_ip, gateway_mac=args.gateway_mac),
        PortScanDetector(threshold=args.scan_threshold, window=args.scan_window),
        RogueDhcpDetector(trusted_servers=args.trusted_dhcp),
    ]
    sinks = [console_sink]
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    if args.server:
        sinks.append(HttpSink(args.server, os.environ.get("LANTERN_API_KEY")))
    return Sensor(detectors, sinks, name=args.name)


def prediction_alert(flow, prediction, zone, sensor_name):
    """Keep benign flows in prediction logs; publish only flagged flows as alerts."""
    label = str(prediction["attack_class"])
    benign = label.strip().lower() in {"benign", "normal", "normal traffic", "0"}
    if benign and not prediction["is_anomaly"]:
        return None
    meta = flow["metadata"]
    attack = "ml_anomaly" if benign else "ml_" + label.lower().replace(" ", "_")
    reason = (f"ML detected unusual traffic from {meta['src_ip']} to {meta['dst_ip']}; "
              "the classifier labelled it benign. Review this flow.") if benign else (
              f"ML classified traffic from {meta['src_ip']} to {meta['dst_ip']} as {label}. "
              "This is a model prediction requiring review.")
    return Alert(zone=Zone(zone), attack=attack, severity=Severity.MEDIUM if benign else Severity.HIGH,
                 reason=reason, source=Endpoint(ip=meta["src_ip"], port=meta["src_port"]),
                 target=Endpoint(ip=meta["dst_ip"], port=meta["dst_port"]),
                 details={"prediction": prediction, "flow": meta},
                 timestamp=time.time(), sensor=sensor_name)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    sensor = build_sensor(args)

    extractor = inference = None
    if args.ml:
        from ml_module.feature_extraction import FlowFeatureExtractor
        from ml_module.inference import MLInference
        try:
            extractor = FlowFeatureExtractor()
            inference = MLInference()
        except Exception as exc:
            print(f"Cannot enable ML: {exc}. Check the model training versions, or omit --ml for rule detections.", file=sys.stderr)
            for sink in sensor.sinks:
                if hasattr(sink, "close"):
                    sink.close()
            return 1

    output_path = Path(__file__).resolve().parents[1] / "ml_module" / "output" / "predictions.jsonl"

    def process_flow(flow):
        prediction = inference.predict(flow["features"])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as output_file:
            output_file.write(json.dumps({"metadata": flow["metadata"], "prediction": prediction}, default=str) + "\n")
        alert = prediction_alert(flow, prediction, args.zone, args.name)
        if alert is not None:
            sensor.alerts_raised += 1
            for sink in sensor.sinks:
                sink(alert)

    def handle_packet(pkt):
        sensor.handle(pkt)
        if extractor is not None:
            for flow in extractor.add_packet(pkt):
                process_flow(flow)


    if args.mode == "replay":
        from scapy.utils import PcapReader

        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                handle_packet(pkt)
    else:
        from scapy.sendrecv import sniff

        print(f"LANTERN {args.name} listening on {args.iface or 'default interface'} (Ctrl+C to stop)")
        try:
            sniff(iface=args.iface, filter=CAPTURE_FILTER, prn=handle_packet, store=False)
        except PermissionError:
            print("Live capture needs root. Try: sudo python -m sensor live ...", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            pass

    if extractor is not None:
        for flow in extractor.flush():
            process_flow(flow)
    for sink in sensor.sinks:
        if hasattr(sink, "close"):
            sink.close()

    print(f"\n{sensor.packets_seen} packets inspected, {sensor.alerts_raised} alerts raised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
