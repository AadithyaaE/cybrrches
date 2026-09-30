"""
Feature L2 - offline PCAP/PCAPNG reader.

Reads a capture file and produces a normalized, immutable list of
PacketRecord objects containing ONLY information legitimately present in
the capture. Never invents an IP, port, timestamp, or protocol value.

Uses scapy (already installed in this environment's Python 3.12
interpreter - see results/pcap/tool_availability_report.json - no new
dependency was installed for this feature). Purely offline: rdpcap()
reads a file from disk; nothing here opens a live interface, sends a
packet, or connects to any host.

Security note: this module NEVER executes, evaluates, or acts on packet
payload content. Payload bytes are only ever measured (len()), never
interpreted or executed.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PacketRecord:
    index: int  # 0-based position in the capture file
    timestamp_us: int  # microseconds since epoch, from the capture's own packet timestamp
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: int | None  # IP protocol number, e.g. 6=TCP, 17=UDP; None if no IP layer
    ip_total_len: int  # IP header's declared total length if present, else the raw frame length
    ip_header_len: int  # IP header length in bytes (0 if no IP layer)
    transport_header_len: int  # TCP/UDP header length in bytes (0 if neither)
    payload_len: int  # bytes after the transport header
    tcp_flags: frozenset[str] | None  # e.g. frozenset({"SYN","ACK"}); None if not TCP
    tcp_window: int | None  # TCP window field; None if not TCP


@dataclass(frozen=True)
class MalformedPacket:
    index: int
    reason: str


@dataclass(frozen=True)
class PcapReadResult:
    source_file: str
    packets: list[PacketRecord]
    malformed: list[MalformedPacket]
    total_frames_in_capture: int


_TCP_FLAG_BITS = [
    ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
    ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80),
]


def _decode_tcp_flags(flags_field) -> frozenset[str]:
    """scapy's TCP.flags can be an int, a FlagValue, or a string depending on version - handle all safely."""
    try:
        value = int(flags_field)
    except (TypeError, ValueError):
        value = 0
        for name in str(flags_field):
            for flag_name, bit in _TCP_FLAG_BITS:
                if flag_name[0] == name:
                    value |= bit
    return frozenset(name for name, bit in _TCP_FLAG_BITS if value & bit)


def read_pcap(path: str | Path) -> PcapReadResult:
    """
    Read a .pcap or .pcapng file offline and return normalized packet
    records. Malformed/unsupported packets are reported, never silently
    dropped without a record of why.
    """
    from scapy.all import rdpcap  # imported lazily so importing this module never requires scapy unless actually reading a file
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    raw_packets = rdpcap(str(path))
    total = len(raw_packets)

    packets: list[PacketRecord] = []
    malformed: list[MalformedPacket] = []

    for i, pkt in enumerate(raw_packets):
        try:
            if pkt.time is None:
                malformed.append(MalformedPacket(i, "Packet has no capture timestamp."))
                continue
            timestamp_us = int(round(float(pkt.time) * 1_000_000))

            ip_layer = None
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                # IPv6 is present in the capture but this project's schema/state pipeline
                # is IPv4-only (Protocol_0/6/17 derive from IPv4's protocol field); report,
                # do not silently coerce.
                malformed.append(MalformedPacket(i, "IPv6 packet - not supported by the IPv4-only CyberChess Protocol_0/6/17 schema."))
                continue

            if ip_layer is None:
                malformed.append(MalformedPacket(i, "No IPv4 layer present (e.g. ARP or other non-IP frame)."))
                continue

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = int(ip_layer.proto)
            ip_header_len = int(ip_layer.ihl) * 4 if getattr(ip_layer, "ihl", None) else 20
            ip_total_len = int(ip_layer.len) if getattr(ip_layer, "len", None) else len(bytes(pkt))

            src_port = dst_port = None
            transport_header_len = 0
            payload_len = max(0, ip_total_len - ip_header_len)
            tcp_flags = None
            tcp_window = None

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                transport_header_len = int(tcp_layer.dataofs) * 4 if getattr(tcp_layer, "dataofs", None) else 20
                payload_len = max(0, ip_total_len - ip_header_len - transport_header_len)
                tcp_flags = _decode_tcp_flags(tcp_layer.flags)
                tcp_window = int(tcp_layer.window)
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                transport_header_len = 8  # fixed UDP header size
                payload_len = max(0, ip_total_len - ip_header_len - transport_header_len)

            packets.append(PacketRecord(
                index=i,
                timestamp_us=timestamp_us,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                ip_total_len=ip_total_len,
                ip_header_len=ip_header_len,
                transport_header_len=transport_header_len,
                payload_len=payload_len,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            ))
        except Exception as e:  # noqa: BLE001 - deliberately broad: any parse failure must be reported, not crash the whole file
            malformed.append(MalformedPacket(i, f"{type(e).__name__}: {e}"))

    return PcapReadResult(source_file=str(path), packets=packets, malformed=malformed, total_frames_in_capture=total)
