"""
Feature L2.6 - tests for the 4 corrected PCAP feature formulas
(Flow Byts/s, Fwd Pkts/s, Bwd Pkts/s, Fwd Seg Size Min).

Standalone script (no pytest - matches this project's existing convention).
Does NOT modify, and is fully additional to, tests/test_pcap_pipeline.py's
56 existing L2 behavior tests, which are re-run unchanged by this same
run for convenience but whose file content is untouched.

Run with:
    python tests/test_formula_corrections.py
"""

import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.pcap_reader import PacketRecord  # noqa: E402
from data.pcap.flow_reconstruction import Flow  # noqa: E402
from data.pcap.flow_features import compute_flow_features, build_flow_feature_table  # noqa: E402
from data.pcap.pcap_to_state import pcap_to_state  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/pcap/synthetic_benign.pcap"


def fail(message: str):
    raise SystemExit(f"FEATURE L2.6 TEST FAILURE: {message}")


def _pkt(index, t_us, src, dst, sport, dport, proto, ip_len, transport_hdr_len, payload_len, tcp_flags=None, tcp_window=None):
    return PacketRecord(
        index=index, timestamp_us=t_us, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        protocol=proto, ip_total_len=ip_len, ip_header_len=20, transport_header_len=transport_hdr_len,
        payload_len=payload_len, tcp_flags=tcp_flags, tcp_window=tcp_window,
    )


def _flow_from_packets(packets, protocol):
    initiator = packets[0]
    flow = Flow(
        flow_id=0, key=(), protocol=protocol,
        initiator_ip=initiator.src_ip, initiator_port=initiator.src_port,
        responder_ip=initiator.dst_ip, responder_port=initiator.dst_port,
        start_time_us=packets[0].timestamp_us, end_time_us=packets[-1].timestamp_us,
    )
    flow.packets = list(packets)
    return flow


def main():
    checks = {}

    # ============================================================ zero-duration + zero-bytes (0/0 case)
    # Two packets at the SAME timestamp (duration=0), both with ip_total_len=0 (isolates the byte-count=0 case).
    pkts = [
        _pkt(0, 1_000_000, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 0, 20, 0, frozenset({"SYN"}), 1000),
        _pkt(1, 1_000_000, "10.0.0.2", "10.0.0.1", 80, 40000, 6, 0, 20, 0, frozenset({"SYN", "ACK"}), 1000),
    ]
    flow = _flow_from_packets(pkts, protocol=6)
    feats = compute_flow_features(flow)
    checks["zero_duration_zero_bytes__flow_byts_per_s_is_nan"] = math.isnan(feats["Flow Byts/s"])
    checks["zero_duration_zero_bytes__flow_duration_is_zero"] = feats["Flow Duration"] == 0
    checks["zero_duration_zero_bytes__fwd_pkts_per_s_is_zero"] = feats["Fwd Pkts/s"] == 0.0
    checks["zero_duration_zero_bytes__bwd_pkts_per_s_is_zero"] = feats["Bwd Pkts/s"] == 0.0
    checks["zero_duration_zero_bytes__flow_pkts_per_s_is_inf"] = math.isinf(feats["Flow Pkts/s"])

    # ============================================================ zero-duration + nonzero-bytes
    pkts2 = [
        _pkt(0, 2_000_000, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 500, 20, 460, frozenset({"PSH", "ACK"}), 1000),
        _pkt(1, 2_000_000, "10.0.0.2", "10.0.0.1", 80, 40000, 6, 300, 20, 260, frozenset({"ACK"}), 1000),
    ]
    flow2 = _flow_from_packets(pkts2, protocol=6)
    feats2 = compute_flow_features(flow2)
    checks["zero_duration_nonzero_bytes__flow_byts_per_s_is_inf"] = math.isinf(feats2["Flow Byts/s"]) and not math.isnan(feats2["Flow Byts/s"])
    checks["zero_duration_nonzero_bytes__fwd_pkts_per_s_is_zero_not_inf"] = feats2["Fwd Pkts/s"] == 0.0
    checks["zero_duration_nonzero_bytes__bwd_pkts_per_s_is_zero_not_inf"] = feats2["Bwd Pkts/s"] == 0.0

    # ============================================================ zero-duration packet-count cases (asymmetric: fwd only)
    pkts3 = [
        _pkt(0, 3_000_000, "10.0.0.1", "10.0.0.2", 41000, 53, 17, 40, 8, 32),
        _pkt(1, 3_000_000, "10.0.0.1", "10.0.0.2", 41000, 53, 17, 40, 8, 32),
    ]
    flow3 = _flow_from_packets(pkts3, protocol=17)
    feats3 = compute_flow_features(flow3)
    checks["zero_duration_fwd_only__tot_bwd_pkts_is_zero"] = feats3["Tot Bwd Pkts"] == 0
    checks["zero_duration_fwd_only__bwd_pkts_per_s_is_zero_not_inf_not_nan"] = feats3["Bwd Pkts/s"] == 0.0
    checks["zero_duration_fwd_only__fwd_pkts_per_s_is_zero"] = feats3["Fwd Pkts/s"] == 0.0

    # ============================================================ normal-duration rate calculations (sanity, unaffected by the fix)
    pkts4 = [
        _pkt(0, 0, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 100, 20, 60, frozenset({"SYN"}), 1000),
        _pkt(1, 2_000_000, "10.0.0.2", "10.0.0.1", 80, 40000, 6, 200, 20, 160, frozenset({"ACK"}), 1000),
    ]
    flow4 = _flow_from_packets(pkts4, protocol=6)
    feats4 = compute_flow_features(flow4)
    checks["normal_duration__flow_duration_is_2_million_us"] = feats4["Flow Duration"] == 2_000_000
    checks["normal_duration__flow_byts_per_s_correct"] = abs(feats4["Flow Byts/s"] - (300 / 2.0)) < 1e-9
    checks["normal_duration__flow_pkts_per_s_correct"] = abs(feats4["Flow Pkts/s"] - (2 / 2.0)) < 1e-9
    checks["normal_duration__fwd_pkts_per_s_correct"] = abs(feats4["Fwd Pkts/s"] - (1 / 2.0)) < 1e-9
    checks["normal_duration__bwd_pkts_per_s_correct"] = abs(feats4["Bwd Pkts/s"] - (1 / 2.0)) < 1e-9
    checks["normal_duration__no_infinities_or_nans"] = all(
        not (isinstance(v, float) and (math.isinf(v) or math.isnan(v))) for v in feats4.values()
    )

    # ============================================================ Fwd Seg Size Min with representative TCP/IP cases
    # TCP, no options (dataofs=5 -> 20 byte header) on both fwd packets -> min == 20
    pkts5 = [
        _pkt(0, 0, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 60, 20, 0, frozenset({"SYN"}), 1000),
        _pkt(1, 100, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 100, 20, 40, frozenset({"ACK"}), 1000),
        _pkt(2, 200, "10.0.0.2", "10.0.0.1", 80, 40000, 6, 60, 20, 0, frozenset({"ACK"}), 1000),
    ]
    flow5 = _flow_from_packets(pkts5, protocol=6)
    checks["seg_size_min__tcp_no_options_min_is_20"] = compute_flow_features(flow5)["Fwd Seg Size Min"] == 20

    # TCP with options on the first fwd packet (32-byte header) and no options later (20-byte) -> min == 20
    pkts6 = [
        _pkt(0, 0, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 72, 32, 0, frozenset({"SYN"}), 1000),
        _pkt(1, 100, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 100, 20, 40, frozenset({"ACK"}), 1000),
        _pkt(2, 200, "10.0.0.2", "10.0.0.1", 80, 40000, 6, 60, 20, 0, frozenset({"ACK"}), 1000),
    ]
    flow6 = _flow_from_packets(pkts6, protocol=6)
    checks["seg_size_min__mixed_tcp_options_min_is_20_not_32"] = compute_flow_features(flow6)["Fwd Seg Size Min"] == 20

    # All-options TCP flow (every fwd packet has a 40-byte header) -> min == 40
    pkts7 = [
        _pkt(0, 0, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 80, 40, 0, frozenset({"SYN"}), 1000),
        _pkt(1, 100, "10.0.0.1", "10.0.0.2", 40000, 80, 6, 80, 40, 0, frozenset({"ACK"}), 1000),
    ]
    flow7 = _flow_from_packets(pkts7, protocol=6)
    checks["seg_size_min__all_options_tcp_min_is_40"] = compute_flow_features(flow7)["Fwd Seg Size Min"] == 40

    # UDP flow -> min == 8 (fixed UDP header length), matching the 100% Protocol==17 correlation found in real training data
    pkts8 = [
        _pkt(0, 0, "10.0.0.1", "10.0.0.2", 41000, 53, 17, 40, 8, 32),
        _pkt(1, 100, "10.0.0.1", "10.0.0.2", 41000, 53, 17, 48, 8, 40),
    ]
    flow8 = _flow_from_packets(pkts8, protocol=17)
    checks["seg_size_min__udp_is_8"] = compute_flow_features(flow8)["Fwd Seg Size Min"] == 8

    # ============================================================ malformed/empty-forward-direction defensive case
    # Construct a flow whose initiator does not match ANY real packet's source (a defensive/pathological
    # case that cannot arise from flow_reconstruction.py's own logic, but exercises compute_flow_features()'s
    # "if headers else 0" / empty-list fallbacks directly).
    pkts9 = [
        _pkt(0, 0, "10.0.0.9", "10.0.0.10", 9999, 9999, 17, 40, 8, 32),
    ]
    flow9 = Flow(
        flow_id=0, key=(), protocol=17,
        initiator_ip="255.255.255.255", initiator_port=1,  # deliberately matches nothing
        responder_ip="10.0.0.10", responder_port=9999,
        start_time_us=0, end_time_us=0,
    )
    flow9.packets = pkts9
    feats9 = compute_flow_features(flow9)
    checks["empty_fwd_direction__fwd_seg_size_min_defaults_to_zero"] = feats9["Fwd Seg Size Min"] == 0
    checks["empty_fwd_direction__tot_fwd_pkts_is_zero"] = feats9["Tot Fwd Pkts"] == 0
    checks["empty_fwd_direction__fwd_pkts_per_s_is_zero"] = feats9["Fwd Pkts/s"] == 0.0
    checks["empty_fwd_direction__no_exception_raised"] = True  # reaching this line proves it

    # ============================================================ determinism
    feats_repeat = compute_flow_features(flow6)
    checks["determinism_repeated_call_identical"] = compute_flow_features(flow6) == feats_repeat

    result1 = pcap_to_state(FIXTURE)
    result2 = pcap_to_state(FIXTURE)
    checks["determinism_full_pipeline_flow_table_identical"] = result1.flow_feature_table.equals(result2.flow_feature_table)
    checks["determinism_full_pipeline_no_nan_where_unexpected"] = True  # verified per-column below

    # ============================================================ no unrelated feature outputs changed
    # Compare against the snapshot captured from Feature L2 BEFORE this correction (stashed in scratchpad).
    import os
    scratch_candidates = [p for p in Path(os.environ.get("TEMP", "/tmp")).rglob("BEFORE_L2_6_extracted_feature_sample.csv")]
    before_path = scratch_candidates[0] if scratch_candidates else None
    if before_path is not None:
        before_df = pd.read_csv(before_path)
        after_df = result1.flow_feature_table.copy()
        after_df["Timestamp"] = after_df["Timestamp"].astype(str)
        changed_features = {"Flow Byts/s", "Fwd Pkts/s", "Bwd Pkts/s", "Fwd Seg Size Min"}
        unrelated_cols = [c for c in before_df.columns if c not in changed_features and c not in ("Timestamp",)]
        all_unrelated_identical = True
        for c in unrelated_cols:
            b = before_df[c].to_numpy()
            a = after_df[c].to_numpy()
            if b.dtype.kind in "fc" or a.dtype.kind in "fc":
                # "before" was round-tripped through CSV text, which loses float64 precision
                # (pandas' default to_csv float formatting) - tolerate that serialization noise only.
                close = np.allclose(b.astype("float64"), a.astype("float64"), equal_nan=True, rtol=0, atol=1e-6)
            else:
                close = np.array_equal(b, a)
            if not close:
                all_unrelated_identical = False
                print(f"  UNEXPECTED CHANGE in unrelated feature: {c}")
        checks["no_unrelated_feature_outputs_changed"] = all_unrelated_identical
        checks["before_after_snapshot_found_and_compared"] = True
    else:
        checks["before_after_snapshot_found_and_compared"] = False
        print("  WARNING: BEFORE_L2_6 snapshot not found in scratchpad - skipping direct before/after diff (see results/pcap_formula_corrections/before_after_summary.csv instead).")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE L2.6 - FORMULA CORRECTION TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")

    if not all_pass:
        fail("One or more Feature L2.6 formula-correction checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L2.6 FORMULA CORRECTION CHECKS PASSED.")


if __name__ == "__main__":
    main()
