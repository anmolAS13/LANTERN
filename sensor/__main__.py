"""LANTERN sensor command line.

    sudo python -m sensor live -i wlan0 --gateway-ip 192.168.1.1
    python -m sensor replay captures/arp_spoof.pcap --gateway-ip 192.168.1.1
"""

from __future__ import annotations

import argparse
import logging
import sys

from sensor.detectors import ArpSpoofDetector, PortScanDetector, RogueDhcpDetector
from sensor.engine import Sensor
from sensor.output import JsonlSink, console_sink

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
    detectors = [
        ArpSpoofDetector(gateway_ip=args.gateway_ip, gateway_mac=args.gateway_mac),
        PortScanDetector(threshold=args.scan_threshold, window=args.scan_window),
        RogueDhcpDetector(trusted_servers=args.trusted_dhcp),
    ]
    sinks = [console_sink]
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    return Sensor(detectors, sinks, name=args.name)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    sensor = build_sensor(args)

    if args.mode == "replay":
        from scapy.utils import PcapReader

        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                sensor.handle(pkt)
    else:
        from scapy.sendrecv import sniff

        print(f"LANTERN {args.name} listening on {args.iface or 'default interface'} (Ctrl+C to stop)")
        try:
            sniff(iface=args.iface, filter=CAPTURE_FILTER, prn=sensor.handle, store=False)
        except PermissionError:
            print("Live capture needs root. Try: sudo python -m sensor live ...", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            pass

    print(f"\n{sensor.packets_seen} packets inspected, {sensor.alerts_raised} alerts raised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
