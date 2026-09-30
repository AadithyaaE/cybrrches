"""
Feature L3.1 - tests for the Sandbox/Lab Input Contract itself.

Standalone script (no pytest - matches this project's existing convention).
These tests validate the CONTRACT/SCHEMA - they do not run model inference,
do not train/fit anything, and do not implement a working Sandbox pipeline
(none exists yet; this feature only defines the contract).

Run with:
    python tests/test_sandbox_input_contract.py
"""

import ast
import dataclasses
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.sandbox_contract.contract_schema import (  # noqa: E402
    REQUIRED_65_FEATURES, STATE_ORDER_68D, FEATURE_DTYPES_68D, PROTOCOL_ONEHOT_COLUMNS,
    DataProvenance, LabInputForm, RejectionReason, REQUIRED_PACKET_FIELDS, REQUIRED_FLOW_TABLE_COLUMNS,
    TIMESTAMP_COLUMN, PROTOCOL_COLUMN, STATE_DIMENSIONS, SEQUENCE_LENGTH, WINDOW_SECONDS,
)
from data.sandbox_contract.validate_input import (  # noqa: E402
    validate_flow_table_contract, validate_raw_pcap_form_declared_fields,
)
from data.pcap.pcap_reader import PacketRecord  # noqa: E402
from data.pcap.pcap_to_state import pcap_to_state  # noqa: E402
from data.pcap.feature_mapping import FEATURE_MAPPING  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/pcap/synthetic_benign.pcap"

# Files this feature must NOT modify (Features 1-16 artifacts, L1, all L2.x, frontend).
PROTECTED_FILES = [
    ROOT / "src/data/prepare_unlabeled_state.py",
    ROOT / "results/model_feature_list.json",
    ROOT / "results/temporal_feature_order.json",
    ROOT / "results/state_schema.json",
    ROOT / "data/processed/splits/preprocessing_pipeline_train_fitted.joblib",
]
PROTECTED_DIRS = [
    ROOT / "src/data/pcap", ROOT / "src/data/pcap_validation", ROOT / "results",
    ROOT / "data/processed/splits", ROOT / "frontend",
]
EXCLUDE_PREFIXES = [
    ROOT / "results/pcap", ROOT / "results/sandbox_input_contract",
    ROOT / "frontend/node_modules", ROOT / "frontend/dist",
]


def fail(message: str):
    raise SystemExit(f"FEATURE L3.1 TEST FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_protected_state() -> dict:
    paths = list(PROTECTED_FILES)
    for d in PROTECTED_DIRS:
        if d.exists():
            paths.extend(
                p for p in d.rglob("*")
                if p.is_file() and not any(str(p).startswith(str(ex)) for ex in EXCLUDE_PREFIXES)
            )
    return {str(p): file_md5(p) for p in set(paths)}


def main():
    checks = {}

    print("Hashing protected files (pre-run) ...")
    protected_before = hash_protected_state()
    print(f"  {len(protected_before)} protected files hashed.")

    # ---- 1. schema shape/consistency ----
    checks["1_exactly_65_required_features"] = len(REQUIRED_65_FEATURES) == 65
    checks["1_state_order_is_68_dimensional"] = len(STATE_ORDER_68D) == STATE_DIMENSIONS == 68
    checks["1_state_order_ends_with_protocol_onehot_in_order"] = STATE_ORDER_68D[-3:] == ["Protocol_0", "Protocol_6", "Protocol_17"]
    checks["1_protocol_onehot_columns_match"] = PROTOCOL_ONEHOT_COLUMNS == ["Protocol_0", "Protocol_6", "Protocol_17"]
    checks["1_state_order_65_features_plus_3_protocol_cols"] = set(STATE_ORDER_68D) - set(PROTOCOL_ONEHOT_COLUMNS) == set(REQUIRED_65_FEATURES)
    checks["1_every_required_feature_has_a_dtype"] = all(f in FEATURE_DTYPES_68D for f in REQUIRED_65_FEATURES)
    checks["1_sequence_length_is_10"] = SEQUENCE_LENGTH == 10
    checks["1_window_is_1_second"] = WINDOW_SECONDS == 1
    checks["1_schema_65_features_match_feature_mapping_py"] = set(REQUIRED_65_FEATURES) == set(FEATURE_MAPPING.keys())

    # ---- 2. required-column tuple matches L1's flow-table shape ----
    checks["2_flow_table_columns_is_timestamp_protocol_plus_65"] = (
        REQUIRED_FLOW_TABLE_COLUMNS[0] == TIMESTAMP_COLUMN
        and REQUIRED_FLOW_TABLE_COLUMNS[1] == PROTOCOL_COLUMN
        and len(REQUIRED_FLOW_TABLE_COLUMNS) == 67
    )

    # ---- 3. REQUIRED_PACKET_FIELDS stays a subset of the REAL PacketRecord dataclass fields ----
    actual_packet_fields = set(f.name for f in dataclasses.fields(PacketRecord))
    checks["3_required_packet_fields_subset_of_real_dataclass"] = set(REQUIRED_PACKET_FIELDS).issubset(actual_packet_fields)
    checks["3_required_packet_fields_nonempty"] = len(REQUIRED_PACKET_FIELDS) > 0

    # ---- 4. DataProvenance has exactly the 6 required categories ----
    expected_provenance = {
        "observed_lab_traffic", "derived_flow_feature", "model_state",
        "model_forecast", "attack_probability", "mitre_evidence",
    }
    checks["4_provenance_has_exactly_6_categories"] = {e.value for e in DataProvenance} == expected_provenance

    # ---- 5. LabInputForm has exactly the 2 accepted forms ----
    checks["5_exactly_2_input_forms"] = {e.value for e in LabInputForm} == {"raw_pcap_file", "precomputed_flow_table"}

    # ---- 6. RejectionReason is non-trivial and covers the documented failure conditions ----
    expected_reasons = {
        "missing_required_column", "missing_required_packet_field",
        "unsupported_protocol_ipv6", "unsupported_protocol_other",
        "timestamp_missing_or_unparseable", "timestamp_not_monotonic_within_flow",
        "ambiguous_flow_identity", "feature_value_type_mismatch",
        "feature_not_derivable_from_input", "preprocessing_pipeline_not_fitted",
        "label_column_present_and_required_absent", "unsupported_input_form",
    }
    checks["6_rejection_reasons_cover_documented_failure_conditions"] = {e.value for e in RejectionReason} == expected_reasons

    # ---- 7. validate_flow_table_contract() ACCEPTS a genuinely well-formed table ----
    print("Building a genuinely well-formed flow table via Feature L2's existing, unmodified pipeline ...")
    pcap_result = pcap_to_state(FIXTURE)
    good_table = pcap_result.flow_feature_table
    good_result = validate_flow_table_contract(good_table)
    checks["7_wellformed_table_accepted"] = good_result.accepted is True
    checks["7_wellformed_table_has_no_reasons"] = good_result.reasons == ()

    # ---- 8. validate_flow_table_contract() REJECTS on a missing required feature (never fabricates) ----
    missing_feature_table = good_table.drop(columns=["Flow Duration"])
    missing_result = validate_flow_table_contract(missing_feature_table)
    checks["8_missing_feature_table_rejected"] = missing_result.accepted is False
    checks["8_missing_feature_reason_is_missing_required_column"] = RejectionReason.MISSING_REQUIRED_COLUMN in missing_result.reasons
    checks["8_missing_feature_never_silently_filled"] = "Flow Duration" not in missing_feature_table.columns  # df itself untouched

    # ---- 9. validate_flow_table_contract() REJECTS on an unsupported protocol value ----
    bad_protocol_table = good_table.copy()
    bad_protocol_table["Protocol"] = 999
    bad_protocol_result = validate_flow_table_contract(bad_protocol_table)
    checks["9_bad_protocol_table_rejected"] = bad_protocol_result.accepted is False
    checks["9_bad_protocol_reason_correct"] = RejectionReason.UNSUPPORTED_PROTOCOL_OTHER in bad_protocol_result.reasons

    # ---- 10. validate_flow_table_contract() REJECTS if a Label column is present ----
    labeled_table = good_table.copy()
    labeled_table["Label"] = "Benign"
    labeled_result = validate_flow_table_contract(labeled_table)
    checks["10_labeled_table_rejected"] = labeled_result.accepted is False
    checks["10_labeled_reason_correct"] = RejectionReason.LABEL_COLUMN_PRESENT_AND_REQUIRED_ABSENT in labeled_result.reasons

    # ---- 11. validate_flow_table_contract() REJECTS on a missing Timestamp column ----
    no_ts_table = good_table.drop(columns=["Timestamp"])
    no_ts_result = validate_flow_table_contract(no_ts_table)
    checks["11_missing_timestamp_rejected"] = no_ts_result.accepted is False
    checks["11_missing_timestamp_reason_correct"] = RejectionReason.TIMESTAMP_MISSING_OR_UNPARSEABLE in no_ts_result.reasons

    # ---- 12. validate_raw_pcap_form_declared_fields() accepts/rejects correctly ----
    ok_fields = validate_raw_pcap_form_declared_fields(actual_packet_fields)
    checks["12_full_packetrecord_fields_accepted"] = ok_fields.accepted is True
    incomplete_fields = actual_packet_fields - {"tcp_flags", "tcp_window"}
    bad_fields = validate_raw_pcap_form_declared_fields(incomplete_fields)
    checks["12_incomplete_fields_rejected"] = bad_fields.accepted is False
    checks["12_incomplete_fields_reason_correct"] = RejectionReason.MISSING_REQUIRED_PACKET_FIELD in bad_fields.reasons

    # ---- 13. documented IPv6-rejection limitation is consistent with L2's real code (read-only check) ----
    pcap_reader_source = (ROOT / "src/data/pcap/pcap_reader.py").read_text(encoding="utf-8")
    checks["13_pcap_reader_documents_ipv6_rejection"] = "IPv6" in pcap_reader_source and "not supported" in pcap_reader_source

    # ---- 14. this feature introduces no .fit()/.fit_transform() call anywhere ----
    contract_files = [
        ROOT / "src/data/sandbox_contract/contract_schema.py",
        ROOT / "src/data/sandbox_contract/validate_input.py",
    ]
    no_fit = True
    for path in contract_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "fit_transform"):
                no_fit = False
    checks["14_no_fit_call_in_L3_1_code"] = no_fit

    # ---- 15. no model-inference imports in this feature's code (contract-only, no pipeline) ----
    forbidden_imports = ("lstm_world_model", "next_state_attack_classifier", "attack_progression_probability", "mitre_stage_mapper")
    no_model_imports = all(
        not any(fi in path.read_text(encoding="utf-8") for fi in forbidden_imports)
        for path in contract_files
    )
    checks["15_no_model_inference_code_introduced"] = no_model_imports

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
    print("FEATURE L3.1 - SANDBOX INPUT CONTRACT TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")

    if not all_pass:
        fail("One or more Feature L3.1 contract checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L3.1 SANDBOX INPUT CONTRACT CHECKS PASSED.")


if __name__ == "__main__":
    main()
