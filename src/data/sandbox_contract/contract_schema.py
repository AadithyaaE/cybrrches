"""
Feature L3.1 - Sandbox/Lab Input Contract: machine-readable schema.

This module defines, but does NOT implement, the interface between a
future Sandbox/lab traffic source and CyberChess. It contains no model
inference, no training/fitting, no mitigation, and no live networking. It
only declares required fields, accepted input forms, the provenance
taxonomy, and rejection reasons - all derived by READING (never editing)
the existing frozen artifacts that already define the 65-feature
contract (results/model_feature_list.json, results/temporal_feature_order.json,
results/state_schema.json) and Feature L2's existing PCAP field contract
(src/data/pcap/pcap_reader.py's PacketRecord, feature_mapping.py).

See docs/sandbox_input_contract/SANDBOX_INPUT_CONTRACT.md for the full
human-readable specification this module implements the machine-readable
half of.
"""

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent

TIMESTAMP_COLUMN = "Timestamp"
PROTOCOL_COLUMN = "Protocol"
STATE_DIMENSIONS = 68
SEQUENCE_LENGTH = 10
WINDOW_SECONDS = 1


def _load_required_65_features() -> list:
    """The single source of truth for the 65 required numeric feature names,
    read directly from the existing frozen Feature 4 artifact - never
    hardcoded a second time."""
    with open(ROOT / "results/model_feature_list.json", encoding="utf-8") as f:
        selected = json.load(f)["selected_features"]  # 66, includes "Protocol"
    return [f for f in selected if f != PROTOCOL_COLUMN]


def _load_68d_state_order() -> list:
    """The single source of truth for the exact 68-dimensional state ordering
    (65 features, alphabetical, then Protocol_0/6/17), read directly from the
    existing frozen Feature 6 artifact."""
    with open(ROOT / "results/temporal_feature_order.json", encoding="utf-8") as f:
        return json.load(f)["feature_order"]


def _load_feature_dtypes() -> dict:
    with open(ROOT / "results/state_schema.json", encoding="utf-8") as f:
        return json.load(f)["feature_dtypes"]


REQUIRED_65_FEATURES = _load_required_65_features()
STATE_ORDER_68D = _load_68d_state_order()
FEATURE_DTYPES_68D = _load_feature_dtypes()
PROTOCOL_ONEHOT_COLUMNS = [c for c in STATE_ORDER_68D if c.startswith("Protocol_")]

assert len(REQUIRED_65_FEATURES) == 65, f"Expected 65 required features, got {len(REQUIRED_65_FEATURES)}"
assert len(STATE_ORDER_68D) == STATE_DIMENSIONS, f"Expected {STATE_DIMENSIONS}-dim state order, got {len(STATE_ORDER_68D)}"
assert PROTOCOL_ONEHOT_COLUMNS == ["Protocol_0", "Protocol_6", "Protocol_17"]


class DataProvenance(Enum):
    """
    Item 11's required explicit separation. Every artifact produced anywhere
    downstream of a Sandbox/lab input MUST be tagged with exactly one of
    these. A consumer (frontend, analyst, future automated system) must
    never be able to confuse one category for another - e.g. a FORECAST
    value must never be rendered or logged as if it were an OBSERVED value.
    """
    OBSERVED_LAB_TRAFFIC = "observed_lab_traffic"       # raw packets/flows exactly as captured, no computation applied
    DERIVED_FLOW_FEATURE = "derived_flow_feature"        # one of the 65 computed features, or the 68D state vector
    MODEL_STATE = "model_state"                          # the 68D vector(s) as consumed/produced inside the LSTM world model
    MODEL_FORECAST = "model_forecast"                     # a predicted FUTURE state (K-step forecast) - never an observation
    ATTACK_PROBABILITY = "attack_probability"              # classifier/probability output - a model judgment, not a fact
    MITRE_EVIDENCE = "mitre_evidence"                      # MITRE ATT&CK stage-mapping output - a research-derived annotation


class LabInputForm(Enum):
    """The ONLY two input forms this contract currently accepts. Any other
    input form (live interface capture, NetFlow/IPFIX export, a vendor
    SIEM export, etc.) is explicitly OUT OF SCOPE until a future feature
    extends this enum and defines its own field contract - it is REJECTED,
    never guessed at."""
    RAW_PCAP_FILE = "raw_pcap_file"                # offline .pcap/.pcapng, processed via Feature L2's existing adapter (unmodified)
    PRECOMPUTED_FLOW_TABLE = "precomputed_flow_table"  # a table already in the clean_df shape L1 expects (Timestamp, Protocol, 65 features)


# Required PacketRecord fields for LabInputForm.RAW_PCAP_FILE - mirrors
# src/data/pcap/pcap_reader.py's PacketRecord dataclass exactly (read-only
# citation, not a redefinition - see REQUIRED_PACKET_FIELDS's docstring-like
# comment below for why duplication here is intentional and safe).
REQUIRED_PACKET_FIELDS = (
    "timestamp_us", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "ip_total_len", "ip_header_len", "transport_header_len", "payload_len",
    "tcp_flags", "tcp_window",
)
# NOTE: this tuple is a CONTRACT DECLARATION (what the field names/roles
# are), not the implementation - the implementation is
# src/data/pcap/pcap_reader.py's PacketRecord, imported and used unmodified
# by anything that actually parses a PCAP. A test in
# tests/test_sandbox_input_contract.py asserts this tuple stays in sync
# with the real PacketRecord dataclass fields, so the two can never
# silently drift apart.

# Required columns for LabInputForm.PRECOMPUTED_FLOW_TABLE - the exact
# "clean_df" shape src/data/prepare_unlabeled_state.py's
# build_model_ready_table_unlabeled() already requires (Feature L1,
# unmodified, imported read-only wherever this contract is enforced).
REQUIRED_FLOW_TABLE_COLUMNS = (TIMESTAMP_COLUMN, PROTOCOL_COLUMN) + tuple(REQUIRED_65_FEATURES)


class RejectionReason(Enum):
    """
    Item 12's required failure conditions. Any one of these means
    inference MUST be rejected outright for the affected record(s) - never
    proceed with a fabricated, zero-filled, or substituted value.
    """
    MISSING_REQUIRED_COLUMN = "missing_required_column"
    MISSING_REQUIRED_PACKET_FIELD = "missing_required_packet_field"
    UNSUPPORTED_PROTOCOL_IPV6 = "unsupported_protocol_ipv6"
    UNSUPPORTED_PROTOCOL_OTHER = "unsupported_protocol_other"
    TIMESTAMP_MISSING_OR_UNPARSEABLE = "timestamp_missing_or_unparseable"
    TIMESTAMP_NOT_MONOTONIC_WITHIN_FLOW = "timestamp_not_monotonic_within_flow"
    AMBIGUOUS_FLOW_IDENTITY = "ambiguous_flow_identity"
    FEATURE_VALUE_TYPE_MISMATCH = "feature_value_type_mismatch"
    FEATURE_NOT_DERIVABLE_FROM_INPUT = "feature_not_derivable_from_input"
    PREPROCESSING_PIPELINE_NOT_FITTED = "preprocessing_pipeline_not_fitted"
    LABEL_COLUMN_PRESENT_AND_REQUIRED_ABSENT = "label_column_present_and_required_absent"
    UNSUPPORTED_INPUT_FORM = "unsupported_input_form"


@dataclass(frozen=True)
class ContractValidationResult:
    accepted: bool
    input_form: "LabInputForm | None"
    reasons: tuple  # tuple[RejectionReason, ...] - empty iff accepted
    detail: tuple  # tuple[str, ...] - human-readable detail per reason, same length as reasons
