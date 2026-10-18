"""Generate synthetic attack captures for replay testing.

    python tools/make_captures.py            # writes into captures/

Each capture mixes normal background traffic with one attack, using the lab
addressing below. Nothing is sent on the network; packets are only written
to .pcap files.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

GATEWAY_IP, GATEWAY_MAC = "192.168.1.1", "aa:aa:aa:aa:aa:01"
VICTIM_IP, VICTIM_MAC = "192.168.1.5", "bb:bb:bb:bb:bb:05"
ATTACKER_IP, ATTACKER_MAC = "192.168.1.7", "cc:cc:cc:cc:cc:07"
BROADCAST = "ff:ff:ff:ff:ff:ff"
START = 1_760_000_000.0


def _at(pkt, t: float):
    pkt.time = t
    return pkt


def arp_reply(ip: str, mac: str, to_ip: str, to_mac: str, t: float):
    return _at(Ether(src=mac, dst=to_mac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst=to_ip, hwdst=to_mac), t)


def arp_request(ip: str, mac: str, who_has: str, t: float):
    return _at(Ether(src=mac, dst=BROADCAST) / ARP(op=1, psrc=ip, hwsrc=mac, pdst=who_has), t)


def syn(src: str, dst: str, dport: int, t: float, sport: int = 40000):
    return _at(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"), t)


def dhcp_offer(server_ip: str, server_mac: str, t: float, router: str | None = None,
               dns: str | None = None, msg: str = "offer"):
    opts = [("message-type", msg), ("server_id", server_ip), ("subnet_mask", "255.255.255.0")]
    if router:
        opts.append(("router", router))
    if dns:
        opts.append(("name_server", dns))
    opts.append("end")
    return _at(Ether(src=server_mac, dst=BROADCAST) / IP(src=server_ip, dst="255.255.255.255")
               / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr="192.168.1.50") / DHCP(options=opts), t)


def arp_spoof_capture() -> list:
    pkts = [
        arp_request(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, START),
        arp_reply(GATEWAY_IP, GATEWAY_MAC, VICTIM_IP, VICTIM_MAC, START + 0.01),
        arp_request(ATTACKER_IP, ATTACKER_MAC, GATEWAY_IP, START + 1),
        arp_reply(GATEWAY_IP, GATEWAY_MAC, ATTACKER_IP, ATTACKER_MAC, START + 1.01),
    ]
    # arpspoof-style: repeat the lie every 2 seconds
    for i in range(10):
        pkts.append(arp_reply(GATEWAY_IP, ATTACKER_MAC, VICTIM_IP, VICTIM_MAC, START + 5 + 2 * i))
    return pkts


def port_scan_capture() -> list:
    pkts = [syn(VICTIM_IP, GATEWAY_IP, 443, START + i, sport=50000 + i) for i in range(5)]
    for i, port in enumerate(range(1, 201)):
        pkts.append(syn(ATTACKER_IP, VICTIM_IP, port, START + 10 + i * 0.01))
    return sorted(pkts, key=lambda p: p.time)


def rogue_dhcp_capture() -> list:
    return [
        dhcp_offer(GATEWAY_IP, GATEWAY_MAC, START, router=GATEWAY_IP, dns=GATEWAY_IP),
        dhcp_offer(GATEWAY_IP, GATEWAY_MAC, START + 0.1, router=GATEWAY_IP, dns=GATEWAY_IP, msg="ack"),
        dhcp_offer(ATTACKER_IP, ATTACKER_MAC, START + 30, router=ATTACKER_IP, dns=ATTACKER_IP),
    ]


CAPTURES = {
    "arp_spoof.pcap": arp_spoof_capture,
    "port_scan.pcap": port_scan_capture,
    "rogue_dhcp.pcap": rogue_dhcp_capture,
}


def main(out_dir: str = "captures") -> None:
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    for name, build in CAPTURES.items():
        wrpcap(str(out / name), build())
        print(f"wrote {out / name}")


if __name__ == "__main__":
    main(*sys.argv[1:])
