"""
Feature L2.7 - generates a deterministic, non-malicious PCAP for comparing
CyberChess's PCAP extractor against a CICFlowMeter reference implementation
on the exact same capture.

The existing tests/fixtures/pcap/synthetic_benign.pcap (Feature L2) covers
TCP handshake+data+close, a TCP idle-gap flow, and 9 UDP flows, but has no
zero-duration/single-packet flow, which Feature L2.7 explicitly requires
for edge-case comparison (Flow Byts/s, Fwd/Bwd Pkts/s). Rather than modify
the protected L2 fixture, this is a separate, dedicated capture.

Covers: TCP handshake+bidirectional data+clean FIN/FIN/ACK close, a TCP
flow with an idle gap (Active/Idle), a TCP flow closed by RST, a
bidirectional UDP flow, a single-packet zero-duration TCP flow, a
single-packet zero-duration UDP flow, and a same-timestamp two-packet
(zero-duration, nonzero-bytes) TCP flow.
"""

from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

OUT_PATH = Path(__file__).resolve().parent.parent.parent.parent / "results/pcap_cicflowmeter_reference/comparison_capture.pcap"

BASE_TIME = 1_800_000_000.0  # fixed, arbitrary epoch second - deterministic, distinct from the L2 fixture's base time
CLIENT_MAC = "aa:aa:aa:aa:aa:01"
SERVER_MAC = "aa:aa:aa:aa:aa:02"


def _pkt(layer, t_offset_s: float):
    frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / layer
    frame.time = BASE_TIME + t_offset_s
    return frame


def build_packets() -> list:
    packets = []

    # --- Flow A: TCP handshake + bidirectional data + clean FIN/FIN/ACK close ---
    c, s = ("10.1.0.5", 51000), ("10.1.0.10", 443)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=1000, window=64240), 0.000))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA", seq=2000, ack=1001, window=65535), 0.050))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A", seq=1001, ack=2001, window=64240), 0.100))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA", seq=1001, ack=2001, window=64240) / b"GET /index HTTP/1.1", 0.150))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="A", seq=2001, ack=1021, window=65535), 0.200))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="PA", seq=2001, ack=1021, window=65535) / (b"HTTP/1.1 200 OK" + b"x" * 400), 0.250))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A", seq=1021, ack=2417, window=64240), 0.300))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="FA", seq=1021, ack=2417, window=64240), 0.350))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="FA", seq=2417, ack=1022, window=65535), 0.400))

    # --- Flow B: TCP with an idle gap (~6.5s) between two bursts (Active/Idle) ---
    c, s = ("10.1.0.6", 52000), ("10.1.0.11", 8080)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=5000, window=64240), 1.000))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA", seq=9000, ack=5001, window=65535), 1.040))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A", seq=5001, ack=9001, window=64240), 1.080))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA", seq=5001, ack=9001, window=64240) / b"ping", 7.600))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="A", seq=9001, ack=5005, window=65535), 7.650))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="FA", seq=5005, ack=9001, window=64240), 7.700))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="FA", seq=9001, ack=5006, window=65535), 7.750))

    # --- Flow C: TCP closed by RST (not FIN) ---
    c, s = ("10.1.0.9", 55000), ("10.1.0.12", 22)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=100, window=64240), 3.000))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA", seq=200, ack=101, window=65535), 3.020))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="R", seq=201, ack=101, window=65535), 3.050))

    # --- Flow D: bidirectional UDP, multiple packets each way ---
    c, s = ("10.1.0.7", 53000), ("10.1.0.20", 53)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / UDP(sport=c[1], dport=s[1]) / b"query-a", 2.000))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / UDP(sport=s[1], dport=c[1]) / b"response-a-payload", 2.030))
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / UDP(sport=c[1], dport=s[1]) / b"query-b", 2.500))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / UDP(sport=s[1], dport=c[1]) / b"response-b-payload", 2.530))

    # --- Flow E: single-packet, zero-duration TCP flow (no response ever arrives) ---
    c, s = ("10.1.0.30", 60000), ("10.1.0.31", 9999)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=1, window=64240), 5.000))

    # --- Flow F: single-packet, zero-duration UDP flow ---
    c, s = ("10.1.0.32", 61000), ("10.1.0.33", 12345)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / UDP(sport=c[1], dport=s[1]) / b"single-datagram", 5.500))

    # --- Flow G: two packets at the EXACT SAME timestamp (zero duration, nonzero bytes) ---
    c, s = ("10.1.0.34", 62000), ("10.1.0.35", 8443)
    packets.append(_pkt(IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA", seq=1, ack=1, window=64240) / (b"A" * 100), 6.000))
    packets.append(_pkt(IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="A", seq=1, ack=101, window=65535), 6.000))

    return packets


def main():
    packets = build_packets()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} frames to {OUT_PATH}")


if __name__ == "__main__":
    main()
