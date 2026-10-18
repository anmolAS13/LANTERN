# Captures

Saved packet captures for replay testing. Generate the synthetic demo captures with:

```bash
python tools/make_captures.py
```

This writes `arp_spoof.pcap`, `port_scan.pcap` and `rogue_dhcp.pcap` here (they are git-ignored).
Only add real captures taken on **our own lab network**, with dummy credentials.
