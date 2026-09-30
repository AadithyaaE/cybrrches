"""
Feature L2 - deterministic bidirectional flow reconstruction.

Groups PacketRecord objects (from pcap_reader.py) into network flows using
an explicit, documented rule set. No arbitrary/undocumented choices: every
decision below (flow key, direction, timeout, closure) is stated and fixed.

FLOW KEY (canonical, bidirectional)
    A flow is identified by the unordered pair of its two endpoints plus
    protocol: {(ip_a, port_a), (ip_b, port_b), protocol}. Packets in either
    direction (A->B or B->A) map to the SAME flow. The canonical key is
    built by sorting the two (ip, port) endpoint tuples, so key computation
    is order-independent.

DIRECTION
    "Forward" = the direction of the FIRST packet observed for a flow (the
    initiator). All subsequent packets are classified relative to that
    initiator, matching CICFlowMeter's own convention (flow direction is
    fixed at flow creation, not re-evaluated per packet).

TIMEOUT
    A flow is closed if the gap between a packet's timestamp and the
    flow's last-seen timestamp exceeds `flow_timeout_us` (default
    120,000,000us = 120s, CICFlowMeter's commonly documented default). The
    NEXT packet matching that same key starts a brand-new flow record.

TCP CLOSURE
    - RST in either direction closes the flow immediately (after the
      packet carrying it is added to the flow).
    - FIN from BOTH directions (each direction's own FIN seen at least
      once) closes the flow immediately after the second FIN is added.
    A closed flow is finalized; a further packet matching the same key
    opens a new flow (its own key includes an instance counter so it does
    not merge with the closed one).

UDP CLOSURE
    UDP has no closure signal; UDP flows only end via `flow_timeout_us` or
    end-of-capture.

UNASSIGNABLE PACKETS
    A packet with no src/dst port (e.g. protocol other than TCP/UDP) has no
    valid flow key under this scheme and is reported as unassigned, never
    silently dropped and never forced into an arbitrary flow.
"""

from dataclasses import dataclass, field

from .pcap_reader import PacketRecord

DEFAULT_FLOW_TIMEOUT_US = 120_000_000  # 120s


@dataclass
class Flow:
    flow_id: int
    key: tuple  # (endpoint_a, endpoint_b, protocol) - sorted, order-independent
    protocol: int
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    packets: list[PacketRecord] = field(default_factory=list)
    start_time_us: int = 0
    end_time_us: int = 0
    closed_reason: str = "open"  # "open" | "timeout" | "tcp_rst" | "tcp_fin_both" | "end_of_capture"

    def direction_of(self, pkt: PacketRecord) -> str:
        """'fwd' if pkt was sent by the initiator, 'bwd' otherwise."""
        if pkt.src_ip == self.initiator_ip and pkt.src_port == self.initiator_port:
            return "fwd"
        return "bwd"


@dataclass
class UnassignedPacket:
    index: int
    reason: str


@dataclass
class FlowReconstructionResult:
    flows: list[Flow]
    unassigned: list[UnassignedPacket]
    flow_timeout_us: int


def _canonical_key(pkt: PacketRecord) -> tuple | None:
    if pkt.src_port is None or pkt.dst_port is None or pkt.protocol is None:
        return None
    endpoint_a = (pkt.src_ip, pkt.src_port)
    endpoint_b = (pkt.dst_ip, pkt.dst_port)
    sorted_endpoints = tuple(sorted((endpoint_a, endpoint_b)))
    return (sorted_endpoints[0], sorted_endpoints[1], pkt.protocol)


def reconstruct_flows(
    packets: list[PacketRecord],
    flow_timeout_us: int = DEFAULT_FLOW_TIMEOUT_US,
) -> FlowReconstructionResult:
    """
    Deterministically group packets into flows. Input packets are assumed
    to already be capture order; they are re-sorted by (timestamp_us,
    index) defensively so flow construction is independent of input order.
    """
    ordered = sorted(packets, key=lambda p: (p.timestamp_us, p.index))

    open_flows: dict[tuple, Flow] = {}  # canonical_key -> currently-open Flow
    finished_flows: list[Flow] = []
    unassigned: list[UnassignedPacket] = []
    next_flow_id = 0
    fin_seen: dict[int, set[str]] = {}  # flow_id -> set of directions ("fwd"/"bwd") that have sent FIN

    def _close(flow: Flow, reason: str) -> None:
        flow.closed_reason = reason
        finished_flows.append(flow)
        del open_flows[flow.key]
        fin_seen.pop(flow.flow_id, None)

    for pkt in ordered:
        key = _canonical_key(pkt)
        if key is None:
            unassigned.append(UnassignedPacket(pkt.index, f"Packet has no usable src/dst port for protocol={pkt.protocol}."))
            continue

        flow = open_flows.get(key)
        if flow is not None and (pkt.timestamp_us - flow.end_time_us) > flow_timeout_us:
            _close(flow, "timeout")
            flow = None

        if flow is None:
            flow = Flow(
                flow_id=next_flow_id,
                key=key,
                protocol=pkt.protocol,
                initiator_ip=pkt.src_ip,
                initiator_port=pkt.src_port,
                responder_ip=pkt.dst_ip,
                responder_port=pkt.dst_port,
                start_time_us=pkt.timestamp_us,
                end_time_us=pkt.timestamp_us,
            )
            next_flow_id += 1
            open_flows[key] = flow
            fin_seen[flow.flow_id] = set()

        flow.packets.append(pkt)
        flow.end_time_us = pkt.timestamp_us

        if pkt.tcp_flags is not None:
            direction = flow.direction_of(pkt)
            if "RST" in pkt.tcp_flags:
                _close(flow, "tcp_rst")
                continue
            if "FIN" in pkt.tcp_flags:
                fin_seen[flow.flow_id].add(direction)
                if {"fwd", "bwd"}.issubset(fin_seen[flow.flow_id]):
                    _close(flow, "tcp_fin_both")
                    continue

    for flow in list(open_flows.values()):
        _close(flow, "end_of_capture")

    finished_flows.sort(key=lambda f: (f.start_time_us, f.flow_id))
    return FlowReconstructionResult(flows=finished_flows, unassigned=unassigned, flow_timeout_us=flow_timeout_us)
