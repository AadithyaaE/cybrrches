"""
Feature L2 - synthetic PCAP fixture generator.

Generates a small, fully deterministic, NON-MALICIOUS capture covering:
  - a TCP flow with a full handshake, a data packet in each direction,
    and a clean FIN/FIN/ACK close
  - a second TCP flow with an idle gap (~6s) between two bursts, to
    exercise the Active/Idle segmentation algorithm
  - a UDP flow (no handshake/close semantics, several datagrams each way)
  - one malformed/truncated raw frame, to exercise malformed-packet
    handling in pcap_reader.py

All addresses are private-range (10.0.0.0/8), all payloads are inert
ASCII placeholder bytes (never executed or interpreted by this project -
see pcap_reader.py's own docstring). This script only ever writes a local
.pcap file; it opens no socket and sends nothing.

Run with the Python 3.12 interpreter that has scapy installed (see
results/pcap/tool_availability_report.json).
"""

from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

OUT_PATH = Path(__file__).resolve().parent / "fixtures" / "pcap" / "synthetic_benign.pcap"

BASE_TIME = 1_700_000_000.0  # fixed, arbitrary epoch second - deterministic across runs

CLIENT_MAC = "aa:aa:aa:aa:aa:01"
SERVER_MAC = "aa:aa:aa:aa:aa:02"


def _pkt(layer, t_offset_s: float):
    frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / layer
    frame.time = BASE_TIME + t_offset_s
    return frame


def build_packets() -> list:
    packets = []

    # --- Flow 1: TCP handshake + 1 data packet each way + clean close ---
    c1, s1 = ("10.0.0.5", 51000), ("10.0.0.10", 443)
    packets.append(_pkt(IP(src=c1[0], dst=s1[0]) / TCP(sport=c1[1], dport=s1[1], flags="S", seq=1000, window=65535), 0.000))
    packets.append(_pkt(IP(src=s1[0], dst=c1[0]) / TCP(sport=s1[1], dport=c1[1], flags="SA", seq=2000, ack=1001, window=65535), 0.050))
    packets.append(_pkt(IP(src=c1[0], dst=s1[0]) / TCP(sport=c1[1], dport=s1[1], flags="A", seq=1001, ack=2001, window=65535), 0.100))
    packets.append(_pkt(IP(src=c1[0], dst=s1[0]) / TCP(sport=c1[1], dport=s1[1], flags="PA", seq=1001, ack=2001, window=65535) / b"GET /index HTTP/1.1", 0.150))
    packets.append(_pkt(IP(src=s1[0], dst=c1[0]) / TCP(sport=s1[1], dport=c1[1], flags="A", seq=2001, ack=1021, window=65535), 0.200))
    packets.append(_pkt(IP(src=s1[0], dst=c1[0]) / TCP(sport=s1[1], dport=c1[1], flags="PA", seq=2001, ack=1021, window=65535) / (b"HTTP/1.1 200 OK" + b"x" * 400), 0.250))
    packets.append(_pkt(IP(src=c1[0], dst=s1[0]) / TCP(sport=c1[1], dport=s1[1], flags="A", seq=1021, ack=2417, window=65535), 0.300))
    packets.append(_pkt(IP(src=c1[0], dst=s1[0]) / TCP(sport=c1[1], dport=s1[1], flags="FA", seq=1021, ack=2417, window=65535), 0.350))
    packets.append(_pkt(IP(src=s1[0], dst=c1[0]) / TCP(sport=s1[1], dport=c1[1], flags="FA", seq=2417, ack=1022, window=65535), 0.400))

    # --- Flow 2: TCP, two bursts separated by a ~6s idle gap (Active/Idle test) ---
    c2, s2 = ("10.0.0.6", 52000), ("10.0.0.11", 8080)
    packets.append(_pkt(IP(src=c2[0], dst=s2[0]) / TCP(sport=c2[1], dport=s2[1], flags="S", seq=5000, window=65535), 1.000))
    packets.append(_pkt(IP(src=s2[0], dst=c2[0]) / TCP(sport=s2[1], dport=c2[1], flags="SA", seq=9000, ack=5001, window=65535), 1.040))
    packets.append(_pkt(IP(src=c2[0], dst=s2[0]) / TCP(sport=c2[1], dport=s2[1], flags="A", seq=5001, ack=9001, window=65535), 1.080))
    # idle gap: next packet ~6.5s later (>= default 5s active/idle threshold)
    packets.append(_pkt(IP(src=c2[0], dst=s2[0]) / TCP(sport=c2[1], dport=s2[1], flags="PA", seq=5001, ack=9001, window=65535) / b"ping", 7.600))
    packets.append(_pkt(IP(src=s2[0], dst=c2[0]) / TCP(sport=s2[1], dport=c2[1], flags="A", seq=9001, ack=5005, window=65535), 7.650))
    packets.append(_pkt(IP(src=c2[0], dst=s2[0]) / TCP(sport=c2[1], dport=s2[1], flags="FA", seq=5005, ack=9001, window=65535), 7.700))
    packets.append(_pkt(IP(src=s2[0], dst=c2[0]) / TCP(sport=s2[1], dport=c2[1], flags="FA", seq=9001, ack=5006, window=65535), 7.750))

    # --- Flow 3: UDP, several datagrams each direction, no close signal (times out via end-of-capture) ---
    c3, s3 = ("10.0.0.7", 53000), ("10.0.0.20", 53)
    packets.append(_pkt(IP(src=c3[0], dst=s3[0]) / UDP(sport=c3[1], dport=s3[1]) / b"query-a", 2.000))
    packets.append(_pkt(IP(src=s3[0], dst=c3[0]) / UDP(sport=s3[1], dport=c3[1]) / b"response-a-payload", 2.030))
    packets.append(_pkt(IP(src=c3[0], dst=s3[0]) / UDP(sport=c3[1], dport=s3[1]) / b"query-b", 2.500))
    packets.append(_pkt(IP(src=s3[0], dst=c3[0]) / UDP(sport=s3[1], dport=c3[1]) / b"response-b-payload", 2.530))

    # --- Flows 4-11: one minimal UDP flow per second (t=3..10) so the resulting
    # per-second windows form ONE continuous 11-window segment (seconds 0-10),
    # which is enough to exercise the 10-step sequence builder end to end
    # (10 input windows + 1 target window = exactly 1 sequence). Each uses a
    # distinct client port so it is its own flow. ---
    for i, t in enumerate(range(3, 11)):
        cport = 54000 + i
        c, s = ("10.0.0.8", cport), ("10.0.0.21", 9000 + i)
        packets.append(_pkt(IP(src=c[0], dst=s[0]) / UDP(sport=c[1], dport=s[1]) / b"hb-req", float(t) + 0.000))
        packets.append(_pkt(IP(src=s[0], dst=c[0]) / UDP(sport=s[1], dport=c[1]) / b"hb-resp", float(t) + 0.030))

    return packets


def build_malformed_frame():
    """A truncated Ethernet+partial-IP frame with no valid transport layer - exercises pcap_reader's malformed-packet path."""
    frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / bytes.fromhex("4500001400004000")  # truncated IP header, no full 20 bytes
    frame.time = BASE_TIME + 3.000
    return frame


def main():
    packets = build_packets()
    packets.append(build_malformed_frame())
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} frames to {OUT_PATH}")


if __name__ == "__main__":
    main()
