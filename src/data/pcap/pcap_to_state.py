"""
Feature L2 - offline PCAP -> CyberChess network-state orchestrator.

    .pcap/.pcapng file
        -> pcap_reader.read_pcap()            (normalized packets)
        -> flow_reconstruction.reconstruct_flows()  (deterministic flows)
        -> flow_features.build_flow_feature_table() (65-feature "clean_df")
        -> prepare_unlabeled_state.prepare_unlabeled_state_pipeline()
           (Feature L1, imported UNMODIFIED)   (68D state / windows / 10-step sequences)

This module performs NO training, NO .fit()/.fit_transform(), NO live
capture, NO firewall/mitigation action, and NO connection to any network
(Sandbox Lab or otherwise) - it only ever reads a local file from disk.

The frozen preprocessing pipeline and all Feature 1-16 artifacts are
loaded read-only (via prepare_unlabeled_state.py -> prepare_external_dataset.
load_reference_artifacts(), unmodified) and are never written to.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prepare_unlabeled_state import prepare_unlabeled_state_pipeline  # noqa: E402 - Feature L1, reused unmodified

from .feature_mapping import FEATURE_MAPPING, CATEGORY_COUNTS, DEFAULT_ACTIVE_IDLE_THRESHOLD_US
from .flow_features import build_flow_feature_table
from .flow_reconstruction import DEFAULT_FLOW_TIMEOUT_US, reconstruct_flows
from .pcap_reader import read_pcap

STATUS_COMPLETE = "PCAP_FEATURES_COMPLETE"
STATUS_PARTIAL = "PCAP_FEATURES_PARTIAL"


@dataclass
class PcapCompatibilityReport:
    status: str
    total_required_features: int
    features_computed: int
    features_not_computed: list
    category_counts: dict
    high_confidence_features: list  # category A+B: direct field / straightforward flow statistic
    algorithmic_features: list  # category C: timing/threshold-based algorithm (e.g. active/idle segmentation)
    simplified_features: list  # category D: documented simplification, most likely to diverge from real CICFlowMeter
    notes: list = field(default_factory=list)


def build_compatibility_report() -> PcapCompatibilityReport:
    """
    Every one of the 65 required numeric features IS computed for every
    flow this pipeline produces - none are zero/mean-filled or left unset.
    Status is therefore PCAP_FEATURES_COMPLETE in that specific sense.

    This status does NOT mean CICFlowMeter-compatibility has been
    validated: FEATURE_MAPPING.training_definition_validated is False for
    EVERY feature (no reference CICFlowMeter installation is available in
    this environment to cross-check against - see
    results/pcap/tool_availability_report.json). Category C features
    depend on a configurable timing threshold; category D features
    (the 4 Subflow fields) use a documented single-subflow simplification
    that is most likely to diverge from real CICFlowMeter output for flows
    with long idle gaps.
    """
    high_confidence = sorted(f for f, e in FEATURE_MAPPING.items() if e.category in ("A", "B"))
    algorithmic = sorted(f for f, e in FEATURE_MAPPING.items() if e.category == "C")
    simplified = sorted(f for f, e in FEATURE_MAPPING.items() if e.category == "D")

    return PcapCompatibilityReport(
        status=STATUS_COMPLETE,
        total_required_features=len(FEATURE_MAPPING),
        features_computed=len(FEATURE_MAPPING),
        features_not_computed=[],
        category_counts=dict(CATEGORY_COUNTS),
        high_confidence_features=high_confidence,
        algorithmic_features=algorithmic,
        simplified_features=simplified,
        notes=[
            "All 65 required numeric features are computed from real packet/flow data for every "
            "flow produced by this pipeline; none are zero-filled, mean-filled, or otherwise fabricated.",
            "PCAP_FEATURES_COMPLETE describes computational coverage only. It does NOT mean "
            "'CICFlowMeter-compatible' - training_definition_validated is False for every feature "
            "because no reference CICFlowMeter installation exists in this environment to validate against.",
            f"{len(simplified)} feature(s) (category D: Subflow *Pkts/*Byts) use a documented "
            "single-subflow simplification, not a reproduction of CICFlowMeter's true subflow-splitting "
            "algorithm - see feature_mapping.py's _SUBFLOW_NOTE for the exact caveat.",
            f"{len(algorithmic)} feature(s) (category C) depend on the configurable "
            f"active_idle_threshold_us parameter (default {DEFAULT_ACTIVE_IDLE_THRESHOLD_US}us).",
            "This pipeline only ever produces Protocol 6 (TCP) or 17 (UDP) rows, since flow "
            "reconstruction requires a valid TCP/UDP port pair; Protocol_0 is never produced.",
        ],
    )


@dataclass
class PcapToStateResult:
    source_file: str
    total_frames_in_capture: int
    packets_parsed: int
    packets_malformed: int
    malformed_reasons: list
    flows_reconstructed: int
    packets_unassigned_to_a_flow: int
    unassigned_reasons: list
    flow_timeout_us: int
    active_idle_threshold_us: int
    flow_feature_table: pd.DataFrame
    compatibility: PcapCompatibilityReport
    state_pipeline_output: dict  # result of prepare_unlabeled_state_pipeline(), or None if 0 flows
    reached_68d_state: bool
    reached_10step_sequences: bool
    num_windows: int
    num_sequences: int


def pcap_to_state(
    pcap_path: str | Path,
    flow_timeout_us: int = DEFAULT_FLOW_TIMEOUT_US,
    active_idle_threshold_us: int = DEFAULT_ACTIVE_IDLE_THRESHOLD_US,
) -> PcapToStateResult:
    """
    Run the full offline PCAP -> 68D CyberChess state pipeline on one
    capture file. Read-only: only reads pcap_path from disk plus the
    existing frozen Feature 1-16 artifacts (via Feature L1, unmodified);
    writes nothing.
    """
    read_result = read_pcap(pcap_path)
    reconstruction = reconstruct_flows(read_result.packets, flow_timeout_us=flow_timeout_us)
    flow_table = build_flow_feature_table(reconstruction.flows, active_idle_threshold_us=active_idle_threshold_us)
    compatibility = build_compatibility_report()

    state_output = None
    num_windows = 0
    num_sequences = 0
    reached_68d = False
    reached_10step = False
    if len(flow_table) > 0:
        state_output = prepare_unlabeled_state_pipeline(flow_table)
        num_windows = len(state_output["windows"])
        num_sequences = int(state_output["X_sequences"].shape[0])
        reached_68d = state_output["windows_scaled"].shape[1] == 68 if num_windows > 0 else False
        reached_10step = state_output["X_sequences"].shape[1] == 10 if num_sequences > 0 else False

    return PcapToStateResult(
        source_file=str(pcap_path),
        total_frames_in_capture=read_result.total_frames_in_capture,
        packets_parsed=len(read_result.packets),
        packets_malformed=len(read_result.malformed),
        malformed_reasons=[f"packet {m.index}: {m.reason}" for m in read_result.malformed],
        flows_reconstructed=len(reconstruction.flows),
        packets_unassigned_to_a_flow=len(reconstruction.unassigned),
        unassigned_reasons=[f"packet {u.index}: {u.reason}" for u in reconstruction.unassigned],
        flow_timeout_us=flow_timeout_us,
        active_idle_threshold_us=active_idle_threshold_us,
        flow_feature_table=flow_table,
        compatibility=compatibility,
        state_pipeline_output=state_output,
        reached_68d_state=reached_68d,
        reached_10step_sequences=reached_10step,
        num_windows=num_windows,
        num_sequences=num_sequences,
    )
