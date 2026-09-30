"""
Feature L2 - test suite for the offline PCAP -> CyberChess state pipeline.

Standalone script (no pytest - matches this project's existing convention,
see test_unlabeled_state_pipeline.py): plain assertions + a PASS/FAIL
summary, non-zero exit on failure.

Run with the Python interpreter that has scapy installed (see
results/pcap/tool_availability_report.json), e.g.:
    python tests/test_pcap_pipeline.py

Covers all 13 required areas:
  1. PCAP parsing                       6. feature extraction
  2. malformed-packet handling          7. feature mapping (65/65, categories)
  3. deterministic flow reconstruction  8. canonical feature order
  4. TCP flow handling                  9. timestamp ordering
  5. UDP flow handling                 10. transform-only preprocessing
                                        11. deterministic repeated execution
                                        12. Feature L1 integration (68D / 10-step)
                                        13. unsupported/compatibility reporting

Also hashes protected files (Feature 1-16 artifacts, Feature L1's own
module, and frontend/ source) before and after, verifying zero changes.
"""

import ast
import hashlib
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.pcap_reader import read_pcap  # noqa: E402
from data.pcap.flow_reconstruction import reconstruct_flows, DEFAULT_FLOW_TIMEOUT_US  # noqa: E402
from data.pcap.flow_features import build_flow_feature_table, compute_flow_features  # noqa: E402
from data.pcap.feature_mapping import FEATURE_MAPPING, CATEGORY_COUNTS  # noqa: E402
from data.pcap.pcap_to_state import pcap_to_state, build_compatibility_report, STATUS_COMPLETE  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/pcap/synthetic_benign.pcap"

PCAP_MODULE_PATHS = [
    ROOT / "src/data/pcap/pcap_reader.py",
    ROOT / "src/data/pcap/flow_reconstruction.py",
    ROOT / "src/data/pcap/flow_features.py",
    ROOT / "src/data/pcap/feature_mapping.py",
    ROOT / "src/data/pcap/pcap_to_state.py",
]

PROTECTED_DIRS = [
    ROOT / "data/processed/splits",
    ROOT / "results",
]
PROTECTED_FILES = [
    ROOT / "data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv",
    ROOT / "src/data/prepare_unlabeled_state.py",
]
PROTECTED_FRONTEND_ROOT = ROOT / "frontend"
FRONTEND_EXCLUDE_DIRS = {"node_modules", "dist"}


def fail(message: str):
    raise SystemExit(f"FEATURE L2 TEST FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


RESULTS_PCAP_DIR = ROOT / "results/pcap"  # Feature L2's OWN output area - deliberately excluded from protection


def hash_protected_state() -> dict:
    paths = list(PROTECTED_FILES)
    for d in PROTECTED_DIRS:
        if d.exists():
            paths.extend(p for p in d.rglob("*") if p.is_file() and RESULTS_PCAP_DIR not in p.parents)
    if PROTECTED_FRONTEND_ROOT.exists():
        for p in PROTECTED_FRONTEND_ROOT.rglob("*"):
            if p.is_file() and not any(part in FRONTEND_EXCLUDE_DIRS for part in p.relative_to(PROTECTED_FRONTEND_ROOT).parts):
                paths.append(p)
    return {str(p): file_md5(p) for p in paths}


def no_fit_calls_anywhere(paths: list) -> bool:
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "fit_transform"):
                return False
    return True


def main():
    if not FIXTURE.exists():
        fail(f"PCAP fixture not found: {FIXTURE}. Run tests/generate_pcap_fixture.py first.")

    print(f"Fixture: {FIXTURE}")
    print("Hashing protected files (pre-run) ...")
    protected_before = hash_protected_state()
    print(f"  {len(protected_before)} protected files hashed.")

    checks = {}

    # ============================================================ 1. PCAP parsing
    read_result = read_pcap(FIXTURE)
    checks["1_pcap_read_returns_nonzero_frames"] = read_result.total_frames_in_capture > 0
    checks["1_pcap_all_frames_accounted_for"] = (
        len(read_result.packets) + len(read_result.malformed) == read_result.total_frames_in_capture
    )
    checks["1_parsed_packets_have_real_ipv4_endpoints"] = all(
        p.src_ip is not None and p.dst_ip is not None for p in read_result.packets
    )

    # ============================================================ 2. malformed-packet handling
    checks["2_malformed_packet_detected"] = len(read_result.malformed) >= 1
    checks["2_malformed_packet_has_a_reason_string"] = all(m.reason for m in read_result.malformed)
    checks["2_malformed_packet_not_silently_dropped"] = len(read_result.malformed) > 0 and read_result.total_frames_in_capture == 37

    # ============================================================ 3. deterministic flow reconstruction
    recon_1 = reconstruct_flows(read_result.packets, flow_timeout_us=DEFAULT_FLOW_TIMEOUT_US)
    recon_2 = reconstruct_flows(read_result.packets, flow_timeout_us=DEFAULT_FLOW_TIMEOUT_US)
    checks["3_flow_count_deterministic"] = len(recon_1.flows) == len(recon_2.flows)
    checks["3_flow_keys_deterministic"] = [f.key for f in recon_1.flows] == [f.key for f in recon_2.flows]
    checks["3_flow_packet_counts_deterministic"] = [len(f.packets) for f in recon_1.flows] == [len(f.packets) for f in recon_2.flows]
    checks["3_reversed_input_order_same_flow_count"] = len(reconstruct_flows(list(reversed(read_result.packets))).flows) == len(recon_1.flows)
    checks["3_expected_flow_count"] = len(recon_1.flows) == 11  # 1 TCP handshake flow + 1 TCP idle-gap flow + 9 UDP flows

    # ============================================================ 4. TCP flow handling
    tcp_flows = [f for f in recon_1.flows if f.protocol == 6]
    checks["4_tcp_flows_present"] = len(tcp_flows) == 2
    handshake_flow = min(tcp_flows, key=lambda f: f.start_time_us)
    checks["4_tcp_handshake_flow_closed_by_fin_both"] = handshake_flow.closed_reason == "tcp_fin_both"
    checks["4_tcp_handshake_flow_has_5_fwd_4_bwd"] = (
        sum(1 for p in handshake_flow.packets if handshake_flow.direction_of(p) == "fwd") == 5
        and sum(1 for p in handshake_flow.packets if handshake_flow.direction_of(p) == "bwd") == 4
    )
    idle_gap_flow = max(tcp_flows, key=lambda f: f.start_time_us)
    checks["4_tcp_idle_gap_flow_closed_by_fin_both"] = idle_gap_flow.closed_reason == "tcp_fin_both"
    idle_gap_feats = compute_flow_features(idle_gap_flow)
    checks["4_tcp_idle_gap_flow_has_nonzero_idle_mean"] = idle_gap_feats["Idle Mean"] > 5_000_000  # > default 5s threshold

    # ============================================================ 5. UDP flow handling
    udp_flows = [f for f in recon_1.flows if f.protocol == 17]
    checks["5_udp_flows_present"] = len(udp_flows) == 9
    checks["5_udp_flows_closed_by_end_of_capture"] = all(f.closed_reason == "end_of_capture" for f in udp_flows)
    dns_like_flow = min(udp_flows, key=lambda f: f.start_time_us)
    dns_feats = compute_flow_features(dns_like_flow)
    checks["5_udp_flow_has_2_fwd_2_bwd"] = dns_feats["Tot Fwd Pkts"] == 2 and dns_feats["Tot Bwd Pkts"] == 2
    checks["5_udp_flow_init_win_byts_is_minus1"] = dns_feats["Init Fwd Win Byts"] == -1 and dns_feats["Init Bwd Win Byts"] == -1

    # ============================================================ 6. feature extraction
    flow_table = build_flow_feature_table(recon_1.flows)
    checks["6_flow_table_row_count_matches_flow_count"] = len(flow_table) == len(recon_1.flows)
    checks["6_no_nan_values_in_flow_table"] = not flow_table[list(FEATURE_MAPPING.keys())].isna().any().any()
    checks["6_no_none_values_in_flow_table"] = not flow_table[list(FEATURE_MAPPING.keys())].isnull().any().any()
    handshake_row = flow_table.iloc[flow_table["Timestamp"].argsort().iloc[0]]
    checks["6_syn_flag_count_correct_for_handshake_flow"] = int(handshake_row["SYN Flag Cnt"]) == 2

    # ============================================================ 7. feature mapping
    checks["7_feature_mapping_has_65_entries"] = len(FEATURE_MAPPING) == 65
    checks["7_category_counts_sum_to_65"] = sum(CATEGORY_COUNTS.values()) == 65
    checks["7_all_features_marked_training_definition_unvalidated"] = all(
        e.training_definition_validated is False for e in FEATURE_MAPPING.values()
    )
    checks["7_all_features_have_a_nonempty_limitation_string"] = all(len(e.limitation) > 0 for e in FEATURE_MAPPING.values())

    # ============================================================ 8. canonical feature order
    expected_columns = ["Timestamp", "Protocol"] + list(FEATURE_MAPPING.keys())
    checks["8_flow_table_columns_match_expected_set"] = set(flow_table.columns) == set(expected_columns)
    checks["8_flow_table_column_order_matches_feature_mapping_order"] = list(flow_table.columns) == expected_columns
    with open(ROOT / "results/model_feature_list.json", encoding="utf-8") as f:
        import json
        required_65 = [f_ for f_ in json.load(f)["selected_features"] if f_ != "Protocol"]
    checks["8_all_65_required_features_present"] = set(required_65) == set(FEATURE_MAPPING.keys())

    # ============================================================ 9. timestamp ordering
    checks["9_flow_table_timestamps_ascending"] = list(flow_table["Timestamp"]) == sorted(flow_table["Timestamp"])
    checks["9_flow_start_times_match_packet_evidence"] = all(
        flow_table["Timestamp"].iloc[i] == pd.to_datetime(recon_1.flows[i].start_time_us, unit="us")
        for i in range(len(recon_1.flows))
    )

    # ============================================================ 10. transform-only preprocessing
    checks["10_no_fit_call_anywhere_in_pcap_modules"] = no_fit_calls_anywhere(PCAP_MODULE_PATHS)

    # ============================================================ 11. deterministic repeated execution
    result_1 = pcap_to_state(FIXTURE)
    result_2 = pcap_to_state(FIXTURE)
    checks["11_repeated_packet_count_identical"] = result_1.packets_parsed == result_2.packets_parsed
    checks["11_repeated_malformed_count_identical"] = result_1.packets_malformed == result_2.packets_malformed
    checks["11_repeated_flow_count_identical"] = result_1.flows_reconstructed == result_2.flows_reconstructed
    checks["11_repeated_flow_table_identical"] = result_1.flow_feature_table.equals(result_2.flow_feature_table)
    checks["11_repeated_num_windows_identical"] = result_1.num_windows == result_2.num_windows
    checks["11_repeated_num_sequences_identical"] = result_1.num_sequences == result_2.num_sequences
    if result_1.num_windows > 0:
        checks["11_repeated_windows_scaled_identical"] = np.array_equal(
            result_1.state_pipeline_output["windows_scaled"], result_2.state_pipeline_output["windows_scaled"], equal_nan=True
        )
    if result_1.num_sequences > 0:
        checks["11_repeated_X_sequences_identical"] = np.array_equal(
            result_1.state_pipeline_output["X_sequences"], result_2.state_pipeline_output["X_sequences"], equal_nan=True
        )

    # ============================================================ 12. Feature L1 integration / 68D / 10-step
    checks["12_state_pipeline_output_produced"] = result_1.state_pipeline_output is not None
    checks["12_windows_scaled_is_68_dimensional"] = result_1.state_pipeline_output["windows_scaled"].shape[1] == 68
    checks["12_reached_68d_state_flag_true"] = result_1.reached_68d_state is True
    checks["12_reached_10step_sequences_flag_true"] = result_1.reached_10step_sequences is True
    checks["12_X_sequences_shape_is_(N,10,68)"] = result_1.state_pipeline_output["X_sequences"].shape[1:] == (10, 68)
    checks["12_seq_meta_target_label_is_none"] = (
        result_1.state_pipeline_output["seq_meta"]["target_window_label"].isna().all()
        if len(result_1.state_pipeline_output["seq_meta"]) else True
    )
    checks["12_no_label_column_anywhere_in_pcap_pipeline_input"] = "Label" not in flow_table.columns

    # ============================================================ 13. unsupported-feature / compatibility reporting
    compat = build_compatibility_report()
    checks["13_compatibility_status_is_complete"] = compat.status == STATUS_COMPLETE
    checks["13_features_computed_equals_65"] = compat.features_computed == 65
    checks["13_no_features_silently_marked_not_computed"] = compat.features_not_computed == []
    checks["13_category_d_features_explicitly_flagged_as_simplified"] = set(compat.simplified_features) == set(
        f for f, e in FEATURE_MAPPING.items() if e.category == "D"
    )
    checks["13_notes_disclaim_cicflowmeter_validation"] = any("CICFlowMeter" in n for n in compat.notes)
    checks["13_result_carries_same_compatibility_object"] = result_1.compatibility.status == STATUS_COMPLETE

    # ---- protected-file integrity ----
    print("Hashing protected files (post-run) ...")
    protected_after = hash_protected_state()
    unchanged = protected_before == protected_after
    checks["protected_files_unchanged"] = unchanged
    if not unchanged:
        changed = [p for p in protected_before if protected_before.get(p) != protected_after.get(p)]
        print(f"  CHANGED FILES: {changed}")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE L2 - PCAP PIPELINE TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")

    print(f"\nTotal frames in capture: {result_1.total_frames_in_capture}")
    print(f"Packets parsed: {result_1.packets_parsed}, malformed: {result_1.packets_malformed}")
    print(f"Flows reconstructed: {result_1.flows_reconstructed}")
    print(f"Windows: {result_1.num_windows}, Sequences: {result_1.num_sequences}")
    print(f"Compatibility status: {compat.status} ({compat.features_computed}/{compat.total_required_features} features computed)")

    if not all_pass:
        fail("One or more Feature L2 checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L2 PCAP PIPELINE CHECKS PASSED.")


if __name__ == "__main__":
    main()
