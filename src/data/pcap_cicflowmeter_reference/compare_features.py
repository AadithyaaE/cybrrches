"""
Feature L2.7 - feature-by-feature comparison between CyberChess's PCAP
extractor and the pip-installed `cicflowmeter` 0.5.0 reference package, on
the exact same capture (results/pcap_cicflowmeter_reference/comparison_capture.pcap).

Read-only w.r.t. Features 1-16/L1/L2/L2.5/L2.6 and the frontend. Only
writes under results/pcap_cicflowmeter_reference/. Does not run any model.

IMPORTANT KNOWN REFERENCE-TOOL BUG (see acquisition_report.txt for full
detail): cicflowmeter 0.5.0's FlowSession.process() adds the very first
packet of every new flow TWICE - once inside Flow.__init__ (self.packets
= [(packet, direction)]) and once more via the unconditional
flow.add_packet(pkt, direction) call that follows the if/elif branch that
created the flow. This inflates the reference's packet count (and every
count/length/flag statistic depending on it) for whichever direction the
flow-initiating packet was in - confirmed empirically below. This is a bug
in the reference tool, not in CyberChess; every mismatch this bug could
plausibly explain is flagged as such, never silently "corrected".
"""

import hashlib
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.feature_mapping import FEATURE_MAPPING  # noqa: E402

OUT_DIR = ROOT / "results/pcap_cicflowmeter_reference"

# Reference (snake_case) -> CyberChess canonical feature name, for all 65 required features.
COLUMN_MAP = {
    "flow_duration": "Flow Duration", "flow_byts_s": "Flow Byts/s", "flow_pkts_s": "Flow Pkts/s",
    "fwd_pkts_s": "Fwd Pkts/s", "bwd_pkts_s": "Bwd Pkts/s",
    "tot_fwd_pkts": "Tot Fwd Pkts", "tot_bwd_pkts": "Tot Bwd Pkts",
    "totlen_fwd_pkts": "TotLen Fwd Pkts", "totlen_bwd_pkts": "TotLen Bwd Pkts",
    "fwd_pkt_len_max": "Fwd Pkt Len Max", "fwd_pkt_len_min": "Fwd Pkt Len Min",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean", "fwd_pkt_len_std": "Fwd Pkt Len Std",
    "bwd_pkt_len_max": "Bwd Pkt Len Max", "bwd_pkt_len_min": "Bwd Pkt Len Min",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean", "bwd_pkt_len_std": "Bwd Pkt Len Std",
    "pkt_len_max": "Pkt Len Max", "pkt_len_min": "Pkt Len Min", "pkt_len_mean": "Pkt Len Mean",
    "pkt_len_std": "Pkt Len Std", "pkt_len_var": "Pkt Len Var",
    "fwd_header_len": "Fwd Header Len", "bwd_header_len": "Bwd Header Len",
    "fwd_seg_size_min": "Fwd Seg Size Min", "fwd_act_data_pkts": "Fwd Act Data Pkts",
    "flow_iat_mean": "Flow IAT Mean", "flow_iat_max": "Flow IAT Max", "flow_iat_min": "Flow IAT Min", "flow_iat_std": "Flow IAT Std",
    "fwd_iat_tot": "Fwd IAT Tot", "fwd_iat_max": "Fwd IAT Max", "fwd_iat_min": "Fwd IAT Min", "fwd_iat_mean": "Fwd IAT Mean", "fwd_iat_std": "Fwd IAT Std",
    "bwd_iat_tot": "Bwd IAT Tot", "bwd_iat_max": "Bwd IAT Max", "bwd_iat_min": "Bwd IAT Min", "bwd_iat_mean": "Bwd IAT Mean", "bwd_iat_std": "Bwd IAT Std",
    "fwd_psh_flags": "Fwd PSH Flags", "syn_flag_cnt": "SYN Flag Cnt", "rst_flag_cnt": "RST Flag Cnt",
    "psh_flag_cnt": "PSH Flag Cnt", "ack_flag_cnt": "ACK Flag Cnt", "urg_flag_cnt": "URG Flag Cnt", "ece_flag_cnt": "ECE Flag Cnt",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Pkt Size Avg",
    "init_fwd_win_byts": "Init Fwd Win Byts", "init_bwd_win_byts": "Init Bwd Win Byts",
    "active_max": "Active Max", "active_min": "Active Min", "active_mean": "Active Mean", "active_std": "Active Std",
    "idle_max": "Idle Max", "idle_min": "Idle Min", "idle_mean": "Idle Mean", "idle_std": "Idle Std",
    "fwd_seg_size_avg": "Fwd Seg Size Avg", "bwd_seg_size_avg": "Bwd Seg Size Avg",
    "subflow_fwd_pkts": "Subflow Fwd Pkts", "subflow_bwd_pkts": "Subflow Bwd Pkts",
    "subflow_fwd_byts": "Subflow Fwd Byts", "subflow_bwd_byts": "Subflow Bwd Byts",
}

# Four DISTINCT, empirically-confirmed root causes of reference-vs-CyberChess disagreement
# (see acquisition_report.txt for the full evidence for each). A feature is assigned to AT
# MOST one bucket below (its single most likely explanation from source-code + empirical
# inspection); features in none of them have no known confound.

# 1. cicflowmeter 0.5.0 uses raw scapy packet.time (seconds) for all timing features, while
#    CyberChess uses microseconds throughout (matching the real training CSV's own scale -
#    e.g. Flow Duration's real max is ~120,000,000, clearly microseconds not seconds).
UNIT_SCALE_SECONDS_VS_MICROSECONDS = {
    "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
}

# 2. cicflowmeter 0.5.0 measures "packet length" as len(packet) on the FULL scapy packet
#    object (14-byte Ethernet header included), while CyberChess measures the IP header's own
#    "total length" field (Ethernet header excluded) - confirmed empirically: a 40-byte
#    (IP+TCP, no payload) ACK packet was measured as 40 by CyberChess and 54 by the reference
#    (exactly +14).
PACKET_LENGTH_BASIS_ETHERNET_VS_IP = {
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Pkt Len Max", "Pkt Len Min", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Subflow Fwd Byts", "Subflow Bwd Byts", "Flow Byts/s",
}

# 3. cicflowmeter 0.5.0's header-length helper (_header_size) returns ONLY the IP header
#    length (ihl*4); CyberChess sums IP header + TCP/UDP transport header. Confirmed
#    empirically: a TCP ACK packet (IP=20, TCP=20) measured 40 by CyberChess, 20 by reference.
HEADER_LEN_IP_ONLY_VS_IP_PLUS_TRANSPORT = {"Fwd Header Len", "Bwd Header Len", "Fwd Seg Size Min"}

# 4. cicflowmeter 0.5.0 defaults Init Win Byts to 0 for a direction with no TCP packet (e.g.
#    a UDP flow), never -1. CyberChess uses -1, matching the "-1 for N/A" convention Feature
#    L2.5 confirmed IS actually present in the real training CSV (min observed value == -1).
INIT_WIN_BYTS_CONVENTION_DIFFERENCE = {"Init Fwd Win Byts", "Init Bwd Win Byts"}

# 5. cicflowmeter 0.5.0's FlowSession.process() adds the flow-initiating packet twice (once
#    in Flow.__init__, once more via an unconditional flow.add_packet() call right after) -
#    every flow in this capture was initiated by its "forward" side, so this inflates
#    forward-direction counts/flags by whatever that one packet contributed.
FIRST_PACKET_DOUBLE_COUNT_SUSPECT = {
    "Tot Fwd Pkts", "Fwd Act Data Pkts", "Down/Up Ratio", "Fwd Pkts/s", "Flow Pkts/s", "Subflow Fwd Pkts",
    "ACK Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "URG Flag Cnt", "ECE Flag Cnt", "Fwd PSH Flags",
}

ROOT_CAUSE_EXPLANATIONS = {}
for _f in UNIT_SCALE_SECONDS_VS_MICROSECONDS:
    ROOT_CAUSE_EXPLANATIONS[_f] = (
        "Reference tool reports this timing feature in SECONDS (raw scapy packet.time), while CyberChess reports "
        "microseconds (matching the real training CSV's scale). Values typically differ by a factor of ~1,000,000. "
        "This is a units convention difference in the reference tool, not evidence CyberChess's formula is wrong."
    )
for _f in PACKET_LENGTH_BASIS_ETHERNET_VS_IP:
    ROOT_CAUSE_EXPLANATIONS[_f] = (
        "Reference tool measures packet length as the full captured frame (len(packet), includes the 14-byte "
        "Ethernet header); CyberChess measures the IP header's own 'total length' field (Ethernet header excluded). "
        "Confirmed empirically as a consistent +14-bytes-per-packet offset on this capture."
    )
for _f in HEADER_LEN_IP_ONLY_VS_IP_PLUS_TRANSPORT:
    ROOT_CAUSE_EXPLANATIONS[_f] = (
        "Reference tool's header-length formula counts ONLY the IP header (ihl*4); CyberChess counts IP header + "
        "TCP/UDP transport header. Confirmed empirically (a 20-byte-IP+20-byte-TCP packet measured 40 by CyberChess, "
        "20 by the reference)."
    )
for _f in INIT_WIN_BYTS_CONVENTION_DIFFERENCE:
    ROOT_CAUSE_EXPLANATIONS[_f] = (
        "Reference tool defaults to 0 for a direction with no TCP packet (e.g. a UDP flow); CyberChess uses -1. "
        "Feature L2.5 confirmed the real training CSV's OWN minimum value for this column is exactly -1, so "
        "CyberChess's convention - not the reference's - matches the real dataset here."
    )
for _f in FIRST_PACKET_DOUBLE_COUNT_SUSPECT:
    ROOT_CAUSE_EXPLANATIONS[_f] = (
        "Reference value is plausibly inflated by cicflowmeter 0.5.0's confirmed first-packet-double-counting bug "
        "(see acquisition_report.txt) - attributed to the REFERENCE TOOL's bug, not evaluated as a CyberChess defect, "
        "but the comparison for this feature is inconclusive as a result."
    )


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _match_flows(cc_df: pd.DataFrame, ref_df: pd.DataFrame) -> list:
    """Match CyberChess and reference flows by (src_ip, dst_ip, src_port, dst_port, protocol).
    Both tools independently use 'first packet observed = forward/initiator', so for this
    capture (every flow initiated by its listed source) the raw tuples should align directly."""
    ref_df = ref_df.copy()
    ref_df["_key"] = list(zip(ref_df["src_ip"], ref_df["dst_ip"], ref_df["src_port"], ref_df["dst_port"], ref_df["protocol"]))
    matches = []
    for i, row in cc_df.iterrows():
        # CyberChess's table doesn't carry IP/port columns directly - reconstructed separately, see main().
        matches.append(row.get("_match_key"))
    return matches


def classify(feature: str, exact_match: bool, tolerance_match: bool, cc_val, ref_val) -> tuple:
    """Returns (status, explanation) for STEP 7's classification, using exactly the 4 allowed values."""
    both_nan = isinstance(cc_val, float) and isinstance(ref_val, float) and math.isnan(cc_val) and math.isnan(ref_val)
    if exact_match or both_nan:
        return "VALIDATED", "Exact (or NaN==NaN) match against the CICFlowMeter-reimplementation reference on this capture."
    known_cause = ROOT_CAUSE_EXPLANATIONS.get(feature)
    if known_cause is not None:
        return "UNVALIDATED", known_cause
    if tolerance_match:
        return "PARTIALLY_VALIDATED", "Within numeric tolerance but not an exact match against the reference on this capture."
    return "UNVALIDATED", "Value disagrees with the reference beyond tolerance, and is not attributable to any of the 5 known root causes documented in acquisition_report.txt - a genuinely unexplained disagreement."


def main():
    cc_path = OUT_DIR / "cyberchess_output_run1.csv"
    ref_path = OUT_DIR / "cicflowmeter_reference_output_run1.csv"
    cc_df = pd.read_csv(cc_path)
    ref_df = pd.read_csv(ref_path)

    # Re-derive CyberChess's flow-matching key by re-running flow reconstruction (already deterministic,
    # verified separately) to get IP/port tuples alongside the feature table's row order.
    from data.pcap.pcap_reader import read_pcap
    from data.pcap.flow_reconstruction import reconstruct_flows
    pcap_path = OUT_DIR / "comparison_capture.pcap"
    r = read_pcap(pcap_path)
    recon = reconstruct_flows(r.packets)
    cc_keys = [(f.initiator_ip, f.responder_ip, f.initiator_port, f.responder_port, f.protocol) for f in recon.flows]
    assert len(cc_keys) == len(cc_df), "CyberChess flow count mismatch between reconstruction and feature table"
    cc_df = cc_df.copy()
    cc_df["_key"] = cc_keys

    ref_df = ref_df.copy()
    ref_df["_key"] = list(zip(ref_df["src_ip"], ref_df["dst_ip"], ref_df["src_port"], ref_df["dst_port"], ref_df["protocol"]))

    matched_keys = sorted(set(cc_df["_key"]) & set(ref_df["_key"]))
    cc_only = sorted(set(cc_df["_key"]) - set(ref_df["_key"]))
    ref_only = sorted(set(ref_df["_key"]) - set(cc_df["_key"]))

    rows = []
    for feature in FEATURE_MAPPING.keys():
        ref_col = {v: k for k, v in COLUMN_MAP.items()}.get(feature)
        for key in matched_keys:
            cc_val = cc_df.loc[cc_df["_key"] == key, feature].iloc[0]
            ref_val = ref_df.loc[ref_df["_key"] == key, ref_col].iloc[0] if ref_col else None

            cc_is_inf = isinstance(cc_val, float) and math.isinf(cc_val)
            cc_is_nan = isinstance(cc_val, float) and math.isnan(cc_val)
            ref_is_inf = isinstance(ref_val, float) and math.isinf(ref_val) if ref_val is not None else False

            if ref_col is None:
                exact_match = False
                tolerance_match = False
                abs_diff = None
                rel_diff = None
            elif cc_is_inf or ref_is_inf or cc_is_nan:
                exact_match = (cc_is_inf and ref_is_inf) or (cc_is_nan and isinstance(ref_val, float) and math.isnan(ref_val))
                tolerance_match = exact_match
                abs_diff = None
                rel_diff = None
            else:
                abs_diff = float(abs(cc_val - ref_val))
                rel_diff = float(abs_diff / abs(ref_val)) if ref_val not in (0, 0.0) else (0.0 if abs_diff == 0 else None)
                exact_match = bool(cc_val == ref_val) if isinstance(cc_val, (int, np.integer)) and isinstance(ref_val, (int, np.integer)) else bool(abs_diff < 1e-9)
                tolerance_match = bool(abs_diff < 1e-6) or (rel_diff is not None and rel_diff < 1e-3)

            status, explanation = classify(feature, exact_match, tolerance_match, cc_val, ref_val) if ref_col else (
                "NOT_REPRODUCIBLE", "Reference column could not be mapped for this feature."
            )

            rows.append({
                "feature": feature,
                "flow_key": str(key),
                "cyberchess_value": cc_val,
                "cicflowmeter_reference_value": ref_val,
                "abs_diff": abs_diff,
                "rel_diff": rel_diff,
                "exact_match": exact_match,
                "tolerance_match": tolerance_match,
                "known_root_cause": ROOT_CAUSE_EXPLANATIONS.get(feature) is not None,
                "status": status,
                "explanation": explanation,
            })

    comparison_df = pd.DataFrame(rows)
    comparison_df.to_csv(OUT_DIR / "feature_comparison.csv", index=False)

    def _default(o):
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return None if math.isnan(o) else (str(o) if math.isinf(o) else float(o))
        if isinstance(o, (np.bool_,)):
            return bool(o)
        return str(o)

    (OUT_DIR / "feature_comparison.json").write_text(
        json.dumps(rows, indent=2, default=_default), encoding="utf-8"
    )

    # Per-feature overall status: a feature is VALIDATED only if VALIDATED on every matched flow;
    # else UNVALIDATED/NOT_REPRODUCIBLE takes precedence, else PARTIALLY_VALIDATED.
    per_feature_status = {}
    for feature in FEATURE_MAPPING.keys():
        statuses = comparison_df.loc[comparison_df["feature"] == feature, "status"].tolist()
        if all(s == "VALIDATED" for s in statuses):
            per_feature_status[feature] = "VALIDATED"
        elif any(s == "NOT_REPRODUCIBLE" for s in statuses):
            per_feature_status[feature] = "NOT_REPRODUCIBLE"
        elif all(s in ("VALIDATED", "PARTIALLY_VALIDATED") for s in statuses):
            per_feature_status[feature] = "PARTIALLY_VALIDATED"
        else:
            per_feature_status[feature] = "UNVALIDATED"

    from collections import Counter
    status_counts = Counter(per_feature_status.values())

    summary_lines = []
    summary_lines.append("=" * 70)
    summary_lines.append("FEATURE L2.7 - VALIDATION SUMMARY (Step 7 classification)")
    summary_lines.append("=" * 70)
    summary_lines.append(f"\nMatched flows: {len(matched_keys)} / CyberChess-only: {len(cc_only)} / Reference-only: {len(ref_only)}")
    summary_lines.append(f"\nStatus counts (per-feature, across {len(matched_keys)} matched flows each):")
    for s in ["VALIDATED", "PARTIALLY_VALIDATED", "UNVALIDATED", "NOT_REPRODUCIBLE"]:
        feats = sorted(f for f, v in per_feature_status.items() if v == s)
        summary_lines.append(f"\n{s} ({len(feats)}):")
        for f in feats:
            summary_lines.append(f"  - {f}")
    (OUT_DIR / "validation_summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

    print(f"Matched flows: {len(matched_keys)}, CyberChess-only: {cc_only}, Reference-only: {ref_only}")
    print(f"Status counts: {dict(status_counts)}")
    return {
        "matched_keys": matched_keys, "cc_only": cc_only, "ref_only": ref_only,
        "per_feature_status": per_feature_status, "status_counts": dict(status_counts),
    }


if __name__ == "__main__":
    main()
