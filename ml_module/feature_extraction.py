
# ml_module/feature_extraction.py

from collections import defaultdict
from statistics import mean, pstdev, variance
from scapy.all import IP, TCP, UDP
import time


class FlowFeatureExtractor:
    """
    Converts Scapy packets into flow-level features expected by
    LANTERN's trained model.

    Flow keys are bidirectional 5-tuples:
        IPs, ports, protocol

    Call add_packet(packet) for every captured packet.
    It returns completed flow records.
    """

    IDLE_TIMEOUT = 15.0
    ACTIVE_TIMEOUT = 120.0
    MAX_PACKETS = 5000

    def __init__(self):
        self.flows = {}

    # ---------------------------------------------------------
    # Packet parsing
    # ---------------------------------------------------------

    @staticmethod
    def _parse_packet(pkt):
        if IP not in pkt:
            return None

        ip = pkt[IP]
        protocol = int(ip.proto)

        tcp = pkt[TCP] if TCP in pkt else None
        udp = pkt[UDP] if UDP in pkt else None

        if tcp is not None:
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            flags = int(tcp.flags)
            tcp_header_len = int(tcp.dataofs or 5) * 4
            window = int(tcp.window)
            transport_header_len = tcp_header_len
        elif udp is not None:
            sport = int(udp.sport)
            dport = int(udp.dport)
            flags = 0
            window = 0
            transport_header_len = 8
        else:
            sport = dport = flags = window = 0
            transport_header_len = 0

        ip_header_len = int(ip.ihl or 5) * 4
        ip_total_len = int(ip.len) if ip.len else len(ip)
        ip_total_len = max(ip_header_len, ip_total_len)

        packet_time = float(getattr(pkt, "time", time.time()))
        payload_len = max(
            0, ip_total_len - ip_header_len - transport_header_len
        )

        return {
            "src": str(ip.src),
            "dst": str(ip.dst),
            "sport": sport,
            "dport": dport,
            "proto": protocol,
            "time": packet_time,
            "length": ip_total_len,
            "ip_header_len": ip_header_len,
            "transport_header_len": transport_header_len,
            "header_len": ip_header_len + transport_header_len,
            "payload_len": payload_len,
            "flags": flags,
            "window": window,
            "is_tcp": tcp is not None,
            "is_udp": udp is not None,
        }

    @staticmethod
    def _flow_key(info):
        # Keep packet direction consistent with the first packet.
        endpoint_a = (info["src"], info["sport"])
        endpoint_b = (info["dst"], info["dport"])
        low, high = sorted((endpoint_a, endpoint_b))
        return low, high, info["proto"]

    # ---------------------------------------------------------
    # Public packet API
    # ---------------------------------------------------------

    def add_packet(self, pkt, now=None):
        """
        Add a Scapy packet.

        Returns:
            list[dict]: completed flows, each containing:
                metadata: endpoints and protocol
                features: dictionary of 68 model features
        """
        info = self._parse_packet(pkt)
        if info is None:
            return []

        if not info["time"]:
            info["time"] = float(now or time.time())

        current_time = info["time"]
        completed = []

        # Close flows that have timed out.
        for key, flow in list(self.flows.items()):
            idle = current_time - flow["last_time"]
            duration = current_time - flow["first_time"]

            if idle >= self.IDLE_TIMEOUT or duration >= self.ACTIVE_TIMEOUT:
                record = self._finish(key)
                if record:
                    completed.append(record)

        key = self._flow_key(info)

        if key not in self.flows:
            self.flows[key] = {
                "first_src": info["src"],
                "first_dst": info["dst"],
                "first_sport": info["sport"],
                "first_dport": info["dport"],
                "proto": info["proto"],
                "packets": [],
                "first_time": current_time,
                "last_time": current_time,
                "active_periods": [],
                "idle_periods": [],
            }

        flow = self.flows[key]
        flow["packets"].append(info)
        flow["last_time"] = current_time

        if (
            info["is_tcp"]
            and (info["flags"] & 0x01 or info["flags"] & 0x04)
        ):
            record = self._finish(key)
            if record:
                completed.append(record)

        elif len(flow["packets"]) >= self.MAX_PACKETS:
            record = self._finish(key)
            if record:
                completed.append(record)

        return completed

    def flush(self):
        """Finish and return every flow still being tracked."""
        records = []
        for key in list(self.flows):
            record = self._finish(key)
            if record:
                records.append(record)
        return records

    # ---------------------------------------------------------
    # Statistics helpers
    # ---------------------------------------------------------

    @staticmethod
    def _mean(values):
        return mean(values) if values else 0.0

    @staticmethod
    def _std(values):
        return pstdev(values) if len(values) > 1 else 0.0

    @staticmethod
    def _stats(values):
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        return max(values), min(values), mean(values), pstdev(values)

    @staticmethod
    def _iat(times):
        return [
            (times[i] - times[i - 1]) * 1_000_000
            for i in range(1, len(times))
        ]

    @staticmethod
    def _rate(count, duration_us):
        return count / (duration_us / 1_000_000) if duration_us > 0 else 0.0

    # ---------------------------------------------------------
    # Flow feature calculation
    # ---------------------------------------------------------

    def _finish(self, key):
        flow = self.flows.pop(key, None)
        if not flow or not flow["packets"]:
            return None

        packets = flow["packets"]

        first_src = flow["first_src"]
        first_sport = flow["first_sport"]

        forward = [
            p for p in packets
            if p["src"] == first_src and p["sport"] == first_sport
        ]
        backward = [
            p for p in packets
            if not (
                p["src"] == first_src and p["sport"] == first_sport
            )
        ]

        times = [p["time"] for p in packets]
        f_times = [p["time"] for p in forward]
        b_times = [p["time"] for p in backward]

        f_lengths = [p["length"] for p in forward]
        b_lengths = [p["length"] for p in backward]
        all_lengths = [p["length"] for p in packets]

        duration_us = max(0.0, (max(times) - min(times)) * 1_000_000)

        f_iat = self._iat(f_times)
        b_iat = self._iat(b_times)
        all_iat = self._iat(times)

        f_header = sum(p["header_len"] for p in forward)
        b_header = sum(p["header_len"] for p in backward)
        f_bytes = sum(f_lengths)
        b_bytes = sum(b_lengths)

        f_max, f_min, f_mean, f_std = self._stats(f_lengths)
        b_max, b_min, b_mean, b_std = self._stats(b_lengths)
        p_max, p_min, p_mean, p_std = self._stats(all_lengths)

        flags = [p["flags"] for p in packets]
        fwd_flags = [p["flags"] for p in forward]

        # TCP flags
        fin_count = sum(bool(x & 0x01) for x in flags)
        syn_count = sum(bool(x & 0x02) for x in flags)
        rst_count = sum(bool(x & 0x04) for x in flags)
        psh_count = sum(bool(x & 0x08) for x in flags)
        ack_count = sum(bool(x & 0x10) for x in flags)
        urg_count = sum(bool(x & 0x20) for x in flags)
        ece_count = sum(bool(x & 0x40) for x in flags)
        fwd_psh_count = sum(bool(x & 0x08) for x in fwd_flags)

        # Active/idle periods: divide packet timestamps into periods
        # using a 5-second gap threshold.
        active_threshold = 5.0
        active_periods = []
        idle_periods = []

        period_start = times[0]
        previous = times[0]

        for packet_time in times[1:]:
            gap = packet_time - previous
            if gap > active_threshold:
                active_periods.append(
                    max(0.0, (previous - period_start) * 1_000_000)
                )
                idle_periods.append(gap * 1_000_000)
                period_start = packet_time
            previous = packet_time

        active_periods.append(
            max(0.0, (previous - period_start) * 1_000_000)
        )

        total_packets = len(packets)
        total_bytes = f_bytes + b_bytes

        first_forward = forward[0] if forward else None
        first_backward = backward[0] if backward else None

        features = {
            "Destination Port": flow["first_dport"],
            "Flow Duration": duration_us,
            "Total Fwd Packets": len(forward),
            "Total Backward Packets": len(backward),
            "Total Length of Fwd Packets": f_bytes,
            "Total Length of Bwd Packets": b_bytes,
            "Fwd Packet Length Max": f_max,
            "Fwd Packet Length Min": f_min,
            "Fwd Packet Length Mean": f_mean,
            "Fwd Packet Length Std": f_std,
            "Bwd Packet Length Max": b_max,
            "Bwd Packet Length Min": b_min,
            "Bwd Packet Length Mean": b_mean,
            "Bwd Packet Length Std": b_std,
            "Flow Bytes/s": self._rate(total_bytes, duration_us),
            "Flow Packets/s": self._rate(total_packets, duration_us),
            "Flow IAT Mean": self._mean(all_iat),
            "Flow IAT Std": self._std(all_iat),
            "Flow IAT Max": max(all_iat, default=0.0),
            "Flow IAT Min": min(all_iat, default=0.0),
            "Fwd IAT Total": sum(f_iat),
            "Fwd IAT Mean": self._mean(f_iat),
            "Fwd IAT Std": self._std(f_iat),
            "Fwd IAT Max": max(f_iat, default=0.0),
            "Fwd IAT Min": min(f_iat, default=0.0),
            "Bwd IAT Total": sum(b_iat),
            "Bwd IAT Mean": self._mean(b_iat),
            "Bwd IAT Std": self._std(b_iat),
            "Bwd IAT Max": max(b_iat, default=0.0),
            "Bwd IAT Min": min(b_iat, default=0.0),
            "Fwd PSH Flags": fwd_psh_count,
            "Fwd Header Length": f_header,
            "Bwd Header Length": b_header,
            "Fwd Packets/s": self._rate(len(forward), duration_us),
            "Bwd Packets/s": self._rate(len(backward), duration_us),
            "Min Packet Length": p_min,
            "Max Packet Length": p_max,
            "Packet Length Mean": p_mean,
            "Packet Length Std": p_std,
            "Packet Length Variance": (
                variance(all_lengths) if len(all_lengths) > 1 else 0.0
            ),
            "FIN Flag Count": fin_count,
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": urg_count,
            "ECE Flag Count": ece_count,
            "Down/Up Ratio": (
                len(backward) / len(forward) if forward else 0.0
            ),
            "Average Packet Size": (
                total_bytes / total_packets if total_packets else 0.0
            ),
            "Avg Fwd Segment Size": self._mean(f_lengths),
            "Avg Bwd Segment Size": self._mean(b_lengths),
            "Fwd Header Length_duplicated_0": f_header,
            "Subflow Fwd Packets": len(forward),
            "Subflow Fwd Bytes": f_bytes,
            "Subflow Bwd Packets": len(backward),
            "Subflow Bwd Bytes": b_bytes,
            "Init_Win_bytes_forward": (
                first_forward["window"] if first_forward else 0
            ),
            "Init_Win_bytes_backward": (
                first_backward["window"] if first_backward else 0
            ),
            "act_data_pkt_fwd": sum(
                p["payload_len"] > 0 for p in forward
            ),
            "min_seg_size_forward": min(
                (p["header_len"] for p in forward), default=0
            ),
            "Active Mean": self._mean(active_periods),
            "Active Std": self._std(active_periods),
            "Active Max": max(active_periods, default=0.0),
            "Active Min": min(active_periods, default=0.0),
            "Idle Mean": self._mean(idle_periods),
            "Idle Std": self._std(idle_periods),
            "Idle Max": max(idle_periods, default=0.0),
            "Idle Min": min(idle_periods, default=0.0),
        }

        metadata = {
            "src_ip": flow["first_src"],
            "dst_ip": flow["first_dst"],
            "src_port": flow["first_sport"],
            "dst_port": flow["first_dport"],
            "protocol": flow["proto"],
            "packet_count": total_packets,
            "duration_us": duration_us,
        }

        return {"metadata": metadata, "features": features}
