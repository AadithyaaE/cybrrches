"""
Feature L2 - per-flow feature computation.

Computes exactly the 65 numeric CyberChess features (per feature_mapping.py)
for each reconstructed Flow, plus the Timestamp/Protocol metadata columns.
Output shape matches what src/data/prepare_unlabeled_state.py's
build_model_ready_table_unlabeled() expects as "clean_df": a Timestamp
column (real pandas datetime), a Protocol column (raw IP protocol number),
and the 65 named numeric feature columns - nothing else invented.

Formulas here MUST match feature_mapping.py exactly; this module does not
introduce any formula not documented there.

FEATURE L2.6 CORRECTIONS (see results/pcap_formula_corrections/ for the
full audit trail): Feature L2.5's empirical validation against the real
331,027-row CSE-CIC-IDS2018 training CSV found 4 concrete formula
problems, corrected here:
  - Fwd Seg Size Min was aliased to Fwd Pkt Len Min (2.16% real-data
    match). Real Fwd Seg Size Min takes only 10 distinct values
    {0,8,20,24,28,32,36,40,44,48} that correlate EXACTLY with Protocol
    (100% of Protocol==17/UDP rows show exactly 8; 100% of Protocol==0
    rows show exactly 0; Protocol==6/TCP rows cluster at 20 plus 4-byte
    steps up to 48) - consistent with the minimum TRANSPORT-LAYER HEADER
    LENGTH (TCP data-offset-derived length, or the fixed 8-byte UDP
    header) among forward packets, not packet length. Corrected to
    min(transport_header_len) over forward packets.
  - Flow Byts/s previously returned Infinity for EVERY zero-duration flow.
    Feature 3's own existing audit (results/feature_selection_report.txt,
    STEP 5) already documented that real zero-duration/zero-byte flows
    produce NaN (0/0), while zero-duration/nonzero-byte flows produce
    Infinity. Corrected to match.
  - Fwd Pkts/s and Bwd Pkts/s previously returned Infinity for every
    zero-duration flow. Real training data contains ZERO Infinity values
    for either column anywhere in 331,027 rows (confirmed both by L2.5's
    own cross-check and by the ABSENCE of these two columns from Feature
    3's STEP 5 infinity/missingness findings, which only lists Flow
    Byts/s and Flow Pkts/s as having any infinite values at all).
    Corrected to return 0.0 on zero duration instead of Infinity.
  - Flow Pkts/s was NOT changed - Feature L2.5 found it already matches
    real data 100% (total packet count is always >=1 for a real flow, so
    the 0/0 case this feature is vulnerable to never actually occurs).

None of these corrections claim CICFlowMeter semantic compatibility has
been established. See results/pcap_formula_corrections/
formula_corrections_report.txt for exactly what is, and is not, now
supported by evidence.

Only TCP and UDP flows exist at all under flow_reconstruction.py's key
scheme (a flow key requires a valid src/dst port, which pcap_reader.py
only ever sets for TCP/UDP packets). Protocol therefore only ever takes
the values 6 (TCP) or 17 (UDP) in this pipeline's output - it never
produces Protocol 0, unlike the original training data which may contain
other/unknown protocol codes. This is a known, documented scope
consequence of PCAP-only flow reconstruction, not a bug.
"""

import math

import pandas as pd

from .feature_mapping import FEATURE_MAPPING, DEFAULT_ACTIVE_IDLE_THRESHOLD_US
from .flow_reconstruction import Flow
from .pcap_reader import PacketRecord

TIMESTAMP_COLUMN = "Timestamp"
PROTOCOL_COLUMN = "Protocol"


def _split_directions(flow: Flow) -> tuple[list[PacketRecord], list[PacketRecord]]:
    fwd, bwd = [], []
    for pkt in flow.packets:
        (fwd if flow.direction_of(pkt) == "fwd" else bwd).append(pkt)
    return fwd, bwd


def _mean(values: list) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _pop_std(values: list) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return float(math.sqrt(variance))


def _pop_var(values: list) -> float:
    if not values:
        return 0.0
    m = _mean(values)
    return float(sum((v - m) ** 2 for v in values) / len(values))


def _iat_series(packets: list[PacketRecord]) -> list[int]:
    ts = sorted(p.timestamp_us for p in packets)
    return [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]


def _active_idle_bursts(all_packets: list[PacketRecord], threshold_us: int) -> tuple[list[int], list[int]]:
    ts = sorted(p.timestamp_us for p in all_packets)
    if not ts:
        return [], []
    active, idle = [], []
    burst_start = ts[0]
    prev = ts[0]
    for t in ts[1:]:
        gap = t - prev
        if gap >= threshold_us:
            active.append(prev - burst_start)
            idle.append(gap)
            burst_start = t
        prev = t
    active.append(prev - burst_start)
    return active, idle


def compute_flow_features(
    flow: Flow,
    active_idle_threshold_us: int = DEFAULT_ACTIVE_IDLE_THRESHOLD_US,
) -> dict:
    """Compute all 65 CyberChess numeric features for one flow, following feature_mapping.py exactly."""
    fwd, bwd = _split_directions(flow)
    all_pkts = flow.packets

    fwd_lens = [p.ip_total_len for p in fwd]
    bwd_lens = [p.ip_total_len for p in bwd]
    all_lens = [p.ip_total_len for p in all_pkts]

    tot_fwd_pkts = len(fwd)
    tot_bwd_pkts = len(bwd)
    totlen_fwd = sum(fwd_lens)
    totlen_bwd = sum(bwd_lens)

    def _flag_count(flag: str, packets: list[PacketRecord]) -> int:
        return sum(1 for p in packets if p.tcp_flags is not None and flag in p.tcp_flags)

    def _first_tcp_window(packets: list[PacketRecord]):
        for p in packets:
            if p.tcp_window is not None:
                return int(p.tcp_window)
        return -1

    flow_duration_us = max(0, flow.end_time_us - flow.start_time_us)
    duration_s = flow_duration_us / 1_000_000.0

    def _rate_flow_pkts(count: int) -> float:
        """Flow Pkts/s: Infinity on zero duration - matches real data 100% (packet count is always >=1)."""
        return float(count) / duration_s if duration_s > 0 else math.inf

    def _rate_flow_byts(byte_count: int) -> float:
        """Flow Byts/s: NaN for the genuine 0/0 case (zero bytes AND zero duration), else Infinity - per
        results/feature_selection_report.txt STEP 5's own documented finding on real training data."""
        if duration_s > 0:
            return float(byte_count) / duration_s
        return math.nan if byte_count == 0 else math.inf

    def _rate_directional_pkts(count: int) -> float:
        """Fwd/Bwd Pkts/s: real training data contains zero Infinity values for these two columns anywhere
        in 331,027 rows - use 0.0 on zero duration instead of Infinity."""
        return float(count) / duration_s if duration_s > 0 else 0.0

    def _min_transport_header_len(packets: list[PacketRecord]) -> int:
        """Fwd Seg Size Min: minimum transport-layer (TCP/UDP) header length among the given packets.
        Real Fwd Seg Size Min values {0,8,20,24,28,32,36,40,44,48} correlate exactly with Protocol in the
        training data (UDP flows -> exactly 8; Protocol==0 flows -> exactly 0; TCP flows -> 20 plus 4-byte
        steps up to 48), matching transport header length rather than packet length."""
        headers = [p.transport_header_len for p in packets]
        return min(headers) if headers else 0

    fwd_iat = _iat_series(fwd)
    bwd_iat = _iat_series(bwd)
    flow_iat = _iat_series(all_pkts)
    active_bursts, idle_gaps = _active_idle_bursts(all_pkts, active_idle_threshold_us)

    values: dict = {
        # Category A
        "Tot Fwd Pkts": tot_fwd_pkts,
        "Tot Bwd Pkts": tot_bwd_pkts,
        "TotLen Fwd Pkts": totlen_fwd,
        "TotLen Bwd Pkts": totlen_bwd,
        "ACK Flag Cnt": _flag_count("ACK", all_pkts),
        "SYN Flag Cnt": _flag_count("SYN", all_pkts),
        "RST Flag Cnt": _flag_count("RST", all_pkts),
        "PSH Flag Cnt": _flag_count("PSH", all_pkts),
        "URG Flag Cnt": _flag_count("URG", all_pkts),
        "ECE Flag Cnt": _flag_count("ECE", all_pkts),
        "Fwd PSH Flags": _flag_count("PSH", fwd),
        "Fwd Act Data Pkts": sum(1 for p in fwd if p.payload_len > 0),
        "Init Fwd Win Byts": _first_tcp_window(fwd),
        "Init Bwd Win Byts": _first_tcp_window(bwd),
        "Fwd Header Len": sum(p.ip_header_len + p.transport_header_len for p in fwd),
        "Bwd Header Len": sum(p.ip_header_len + p.transport_header_len for p in bwd),
        # Category B
        "Flow Duration": flow_duration_us,
        "Fwd Pkt Len Max": max(fwd_lens) if fwd_lens else 0,
        "Fwd Pkt Len Min": min(fwd_lens) if fwd_lens else 0,
        "Fwd Pkt Len Mean": _mean(fwd_lens),
        "Fwd Pkt Len Std": _pop_std(fwd_lens),
        "Bwd Pkt Len Max": max(bwd_lens) if bwd_lens else 0,
        "Bwd Pkt Len Min": min(bwd_lens) if bwd_lens else 0,
        "Bwd Pkt Len Mean": _mean(bwd_lens),
        "Bwd Pkt Len Std": _pop_std(bwd_lens),
        "Pkt Len Max": max(all_lens) if all_lens else 0,
        "Pkt Len Min": min(all_lens) if all_lens else 0,
        "Pkt Len Mean": _mean(all_lens),
        "Pkt Len Std": _pop_std(all_lens),
        "Pkt Len Var": _pop_var(all_lens),
        "Pkt Size Avg": _mean(all_lens),
        "Down/Up Ratio": int(tot_bwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0,
        "Flow Byts/s": _rate_flow_byts(totlen_fwd + totlen_bwd),
        "Flow Pkts/s": _rate_flow_pkts(tot_fwd_pkts + tot_bwd_pkts),
        "Fwd Pkts/s": _rate_directional_pkts(tot_fwd_pkts),
        "Bwd Pkts/s": _rate_directional_pkts(tot_bwd_pkts),
        # Category C
        "Flow IAT Mean": _mean(flow_iat),
        "Flow IAT Std": _pop_std(flow_iat),
        "Flow IAT Max": max(flow_iat) if flow_iat else 0,
        "Flow IAT Min": min(flow_iat) if flow_iat else 0,
        "Fwd IAT Tot": sum(fwd_iat),
        "Fwd IAT Mean": _mean(fwd_iat),
        "Fwd IAT Std": _pop_std(fwd_iat),
        "Fwd IAT Max": max(fwd_iat) if fwd_iat else 0,
        "Fwd IAT Min": min(fwd_iat) if fwd_iat else 0,
        "Bwd IAT Tot": sum(bwd_iat),
        "Bwd IAT Mean": _mean(bwd_iat),
        "Bwd IAT Std": _pop_std(bwd_iat),
        "Bwd IAT Max": max(bwd_iat) if bwd_iat else 0,
        "Bwd IAT Min": min(bwd_iat) if bwd_iat else 0,
        "Active Mean": _mean(active_bursts),
        "Active Std": _pop_std(active_bursts),
        "Active Max": max(active_bursts) if active_bursts else 0,
        "Active Min": min(active_bursts) if active_bursts else 0,
        "Idle Mean": _mean(idle_gaps),
        "Idle Std": _pop_std(idle_gaps),
        "Idle Max": max(idle_gaps) if idle_gaps else 0,
        "Idle Min": min(idle_gaps) if idle_gaps else 0,
        "Fwd Seg Size Avg": _mean(fwd_lens),
        "Fwd Seg Size Min": _min_transport_header_len(fwd),
        "Bwd Seg Size Avg": _mean(bwd_lens),
        # Category D (documented single-subflow simplification)
        "Subflow Fwd Pkts": tot_fwd_pkts,
        "Subflow Fwd Byts": totlen_fwd,
        "Subflow Bwd Pkts": tot_bwd_pkts,
        "Subflow Bwd Byts": totlen_bwd,
    }

    missing = set(FEATURE_MAPPING) - set(values)
    extra = set(values) - set(FEATURE_MAPPING)
    if missing or extra:
        raise RuntimeError(f"flow_features/feature_mapping mismatch. missing={sorted(missing)} extra={sorted(extra)}")

    for feature, value in values.items():
        dtype = FEATURE_MAPPING[feature].dtype
        values[feature] = int(value) if dtype == "int64" else float(value)

    return values


def build_flow_feature_table(
    flows: list[Flow],
    active_idle_threshold_us: int = DEFAULT_ACTIVE_IDLE_THRESHOLD_US,
) -> pd.DataFrame:
    """
    One row per flow, in flow start-time order (matching flow_reconstruction's
    own finished_flows ordering). Columns: Timestamp, Protocol, then the 65
    named numeric features. This is the "clean_df" shape that
    prepare_unlabeled_state.build_model_ready_table_unlabeled() expects.
    """
    rows = []
    for flow in flows:
        feature_values = compute_flow_features(flow, active_idle_threshold_us)
        row = {
            TIMESTAMP_COLUMN: pd.to_datetime(flow.start_time_us, unit="us"),
            PROTOCOL_COLUMN: flow.protocol,
        }
        row.update(feature_values)
        rows.append(row)

    columns = [TIMESTAMP_COLUMN, PROTOCOL_COLUMN] + list(FEATURE_MAPPING.keys())
    if not rows:
        return pd.DataFrame(columns=columns)
    df = pd.DataFrame(rows, columns=columns)
    return df
