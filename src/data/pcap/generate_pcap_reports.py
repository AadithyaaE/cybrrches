"""
Feature L2 - generates the results/pcap/ output artifacts by running the
offline pipeline once against the synthetic fixture and writing reports.
Read-only w.r.t. every existing Feature 1-16 artifact; only ever writes
under results/pcap/.
"""

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap.feature_mapping import FEATURE_MAPPING, CATEGORY_COUNTS, as_report_rows, DEFAULT_ACTIVE_IDLE_THRESHOLD_US  # noqa: E402
from data.pcap.flow_reconstruction import DEFAULT_FLOW_TIMEOUT_US  # noqa: E402
from data.pcap.pcap_to_state import pcap_to_state  # noqa: E402

OUT_DIR = ROOT / "results/pcap"
FIXTURE = ROOT / "tests/fixtures/pcap/synthetic_benign.pcap"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---- tool_availability_report.json ----
    tool_report = {
        "environment_note": (
            "Two separate Python interpreters exist on this machine. 'python' (3.12.10) has scapy "
            "2.7.0 installed AND the full ML stack (pandas/numpy/sklearn/joblib/torch) used throughout "
            "Features 1-16 and Feature L1. 'python3' (3.14.3), used for the rest of this project's "
            "development, does NOT have scapy installed. Feature L2 uses the 'python' (3.12.10) "
            "interpreter for this reason - no new dependency was installed; scapy was already present."
        ),
        "tool_actually_used": {"name": "scapy", "version": "2.7.0", "purpose": "offline .pcap/.pcapng file reading (rdpcap) and synthetic fixture generation (wrpcap)"},
        "cli_tools_checked_and_not_found": ["tshark", "wireshark", "dumpcap", "tcpdump", "cicflowmeter"],
        "python_packages_checked": {
            "scapy": "2.7.0 (found, python 3.12.10 interpreter only)",
            "pyshark": "not found",
            "dpkt": "not found",
            "nfstream": "not found",
            "cicflowmeter": "not found (no PyPI package of this name checked; no CLI binary found either)",
        },
        "conclusion": "scapy is the only packet-parsing library available in this environment; it was used for all PCAP reading in Feature L2. No CICFlowMeter installation is available anywhere in this environment.",
    }
    (OUT_DIR / "tool_availability_report.json").write_text(json.dumps(tool_report, indent=2), encoding="utf-8")

    # ---- feature_mapping_report.json ----
    mapping_report = {
        "total_features": len(FEATURE_MAPPING),
        "category_counts": CATEGORY_COUNTS,
        "category_legend": {
            "A": "directly extractable from a single packet field or trivial per-packet aggregate",
            "B": "derivable from a reconstructed bidirectional flow (straightforward statistic)",
            "C": "derivable from packet timing/statistics (inter-arrival times, active/idle segmentation)",
            "D": "not currently reproducible with full confidence - documented simplification used instead",
        },
        "critical_note": "training_definition_validated is False for EVERY feature - no CICFlowMeter installation exists in this environment to empirically validate against. See each row's 'limitation' field.",
        "rows": as_report_rows(),
    }
    (OUT_DIR / "feature_mapping_report.json").write_text(json.dumps(mapping_report, indent=2), encoding="utf-8")

    # ---- run the pipeline on the fixture ----
    result = pcap_to_state(FIXTURE)

    # ---- pcap_compatibility_report.json ----
    compat = result.compatibility
    compat_report = {
        "status": compat.status,
        "total_required_features": compat.total_required_features,
        "features_computed": compat.features_computed,
        "features_not_computed": compat.features_not_computed,
        "category_counts": compat.category_counts,
        "high_confidence_features_A_B": compat.high_confidence_features,
        "algorithmic_features_C": compat.algorithmic_features,
        "simplified_features_D": compat.simplified_features,
        "notes": compat.notes,
        "explicit_disclaimer": (
            "PCAP_FEATURES_COMPLETE means every one of the 65 required numeric features is computed from "
            "real captured packet/flow data for every flow this pipeline produces - none are zero-filled, "
            "mean-filled, or otherwise fabricated. It does NOT mean this pipeline has been validated as "
            "'CICFlowMeter-compatible': no reference CICFlowMeter installation exists in this environment "
            "to empirically cross-check output against (see tool_availability_report.json)."
        ),
    }
    (OUT_DIR / "pcap_compatibility_report.json").write_text(json.dumps(compat_report, indent=2), encoding="utf-8")

    # ---- flow_summary.json ----
    flow_summary = {
        "source_file": result.source_file,
        "total_frames_in_capture": result.total_frames_in_capture,
        "packets_parsed": result.packets_parsed,
        "packets_malformed": result.packets_malformed,
        "malformed_reasons": result.malformed_reasons,
        "flows_reconstructed": result.flows_reconstructed,
        "packets_unassigned_to_a_flow": result.packets_unassigned_to_a_flow,
        "unassigned_reasons": result.unassigned_reasons,
        "flow_timeout_us": result.flow_timeout_us,
        "flow_timeout_us_default": DEFAULT_FLOW_TIMEOUT_US,
        "active_idle_threshold_us": result.active_idle_threshold_us,
        "active_idle_threshold_us_default": DEFAULT_ACTIVE_IDLE_THRESHOLD_US,
        "protocol_breakdown": {
            "tcp_flows": int((result.flow_feature_table["Protocol"] == 6).sum()),
            "udp_flows": int((result.flow_feature_table["Protocol"] == 17).sum()),
        },
    }
    (OUT_DIR / "flow_summary.json").write_text(json.dumps(flow_summary, indent=2), encoding="utf-8")

    # ---- extracted_feature_sample.csv ----
    sample = result.flow_feature_table.copy()
    sample["Timestamp"] = sample["Timestamp"].astype(str)
    sample.to_csv(OUT_DIR / "extracted_feature_sample.csv", index=False)

    # ---- state_summary.json ----
    state_output = result.state_pipeline_output
    state_summary = {
        "reached_68d_state": result.reached_68d_state,
        "reached_10step_sequences": result.reached_10step_sequences,
        "num_flows": result.flows_reconstructed,
        "num_windows": result.num_windows,
        "num_sequences": result.num_sequences,
        "windows_scaled_shape": list(state_output["windows_scaled"].shape) if state_output else None,
        "X_sequences_shape": list(state_output["X_sequences"].shape) if state_output else None,
        "feature_order_length": len(state_output["feature_order"]) if state_output else None,
        "label_available": state_output["prep_meta"]["label_available"] if state_output else None,
        "note": "Produced entirely via Feature L1's unmodified prepare_unlabeled_state_pipeline() - no Label was read, required, or fabricated at any point.",
    }
    (OUT_DIR / "state_summary.json").write_text(json.dumps(state_summary, indent=2), encoding="utf-8")

    # ---- configuration.json ----
    config = {
        "flow_timeout_us": DEFAULT_FLOW_TIMEOUT_US,
        "active_idle_threshold_us": DEFAULT_ACTIVE_IDLE_THRESHOLD_US,
        "flow_key": "canonical (order-independent) pair of (ip, port) endpoints + protocol",
        "direction_rule": "forward = direction of the first packet observed for a flow (the initiator)",
        "tcp_closure_rules": ["RST in either direction closes immediately", "FIN seen in BOTH directions closes immediately"],
        "udp_closure_rule": "timeout or end-of-capture only",
        "malformed_packet_handling": "reported with a reason, never silently dropped",
        "unassignable_packet_handling": "reported with a reason (e.g. non-TCP/UDP), never forced into an arbitrary flow",
        "pcap_source_file": str(FIXTURE.relative_to(ROOT)),
    }
    (OUT_DIR / "configuration.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    print(f"Wrote reports to {OUT_DIR}:")
    for p in sorted(OUT_DIR.glob("*")):
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
