from sensor.__main__ import main
from tools.make_captures import main as make_captures


def test_replay_end_to_end(tmp_path, capsys):
    make_captures(str(tmp_path))
    jsonl = tmp_path / "alerts.jsonl"
    for name in ("arp_spoof", "port_scan", "rogue_dhcp"):
        assert main(["replay", str(tmp_path / f"{name}.pcap"),
                     "--gateway-ip", "192.168.1.1", "--jsonl", str(jsonl)]) == 0

    lines = jsonl.read_text().splitlines()
    assert len(lines) == 3
    out = capsys.readouterr().out
    assert "inside/arp_spoofing" in out and "inside/port_scan" in out and "inside/rogue_dhcp" in out
