"""
Network State S(t) construction for CyberChess.

Builds a temporally-ordered state table from the Feature 4 model-ready
artifacts. Each row is a state:

    S(t) = [x1(t), ..., x68(t)]

made of the exact 68 Feature 4 feature columns, plus row_id/timestamp as
ordering metadata and target/label kept alongside (never inside the
68-dimensional vector) for later supervised learning.

This script does NOT engineer new features, build sequences, train a
model, or forecast anything. It only aligns, orders, and packages the
existing Feature 4 outputs into a state table with strict validation.

Fails loudly (no silent repair) if:
    - a required input file is missing
    - row_id sets don't match across features/target/timestamp
    - duplicate row_ids exist
    - the feature column count is not exactly 68
    - expected feature columns are missing or renamed
    - the target column ends up inside the feature vector
    - timestamp parsing fails

Usage:
    python src/data/build_states.py
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

MODEL_READY_DIR = Path("data/processed/model_ready")
FEATURE_REPORT_PATH = Path("results/model_preparation_report.json")
FEATURE_LIST_PATH = Path("results/model_feature_list.json")

EXPECTED_FEATURE_COUNT = 68
EXPECTED_PROTOCOL_ONEHOT_COLUMNS = 3
EXPECTED_LABEL_ENCODING = {"Benign": 0, "Infilteration": 1}
TARGET_COLUMN_ORIGINAL = "Label_encoded"
LABEL_COLUMN_ORIGINAL = "Label"


def fail(message: str):
    raise SystemExit(f"FEATURE 5 VALIDATION FAILURE: {message}")


def load_feature4_reference() -> dict:
    """Load the authoritative Feature 4 schema to validate against (no invented names)."""
    if not FEATURE_REPORT_PATH.exists():
        fail(f"Required Feature 4 report not found: {FEATURE_REPORT_PATH}")
    if not FEATURE_LIST_PATH.exists():
        fail(f"Required Feature 4 feature list not found: {FEATURE_LIST_PATH}")

    with open(FEATURE_REPORT_PATH, encoding="utf-8") as f:
        prep_report = json.load(f)
    with open(FEATURE_LIST_PATH, encoding="utf-8") as f:
        feature_list = json.load(f)

    expected_columns = prep_report["outputs"]["final_feature_matrix_columns"]
    label_mapping = prep_report["label_encoding"]["mapping"]
    protocol_columns = prep_report["protocol_encoding"]["resulting_columns"]

    return {
        "expected_feature_columns": expected_columns,
        "label_mapping": label_mapping,
        "protocol_onehot_columns": protocol_columns,
        "feature_list": feature_list,
    }


def validate_feature4_inputs(features_df, target_df, timestamp_df, reference: dict):
    """Step: validate Feature 4 assumptions before constructing states. Stop on mismatch."""
    expected_columns = reference["expected_feature_columns"]
    protocol_columns = reference["protocol_onehot_columns"]
    label_mapping = reference["label_mapping"]

    actual_feature_columns = [c for c in features_df.columns if c != "row_id"]

    if len(actual_feature_columns) != EXPECTED_FEATURE_COUNT:
        fail(
            f"features.csv has {len(actual_feature_columns)} feature columns, "
            f"expected exactly {EXPECTED_FEATURE_COUNT}."
        )

    if set(actual_feature_columns) != set(expected_columns):
        missing = set(expected_columns) - set(actual_feature_columns)
        extra = set(actual_feature_columns) - set(expected_columns)
        fail(
            "features.csv columns do not match the Feature 4 report's "
            f"final_feature_matrix_columns. Missing: {sorted(missing)}. Extra: {sorted(extra)}."
        )

    if len(protocol_columns) != EXPECTED_PROTOCOL_ONEHOT_COLUMNS:
        fail(
            f"Expected {EXPECTED_PROTOCOL_ONEHOT_COLUMNS} Protocol one-hot columns per the "
            f"Feature 4 report, found {len(protocol_columns)}: {protocol_columns}."
        )
    if not set(protocol_columns).issubset(set(actual_feature_columns)):
        fail(f"Protocol one-hot columns {protocol_columns} not all present in features.csv.")

    numeric_feature_cols = [c for c in actual_feature_columns if c not in protocol_columns]
    inf_mask = np.isinf(features_df[numeric_feature_cols].to_numpy())
    if inf_mask.any():
        fail(
            f"features.csv contains {int(inf_mask.sum())} Infinity values in numeric feature "
            "columns; Feature 4 was expected to have already converted these to NaN."
        )

    if TARGET_COLUMN_ORIGINAL not in target_df.columns:
        fail(f"target.csv missing expected column '{TARGET_COLUMN_ORIGINAL}'.")
    if LABEL_COLUMN_ORIGINAL not in target_df.columns:
        fail(f"target.csv missing expected column '{LABEL_COLUMN_ORIGINAL}'.")

    observed_mapping = (
        target_df[[LABEL_COLUMN_ORIGINAL, TARGET_COLUMN_ORIGINAL]]
        .drop_duplicates()
        .set_index(LABEL_COLUMN_ORIGINAL)[TARGET_COLUMN_ORIGINAL]
        .to_dict()
    )
    for label, code in EXPECTED_LABEL_ENCODING.items():
        if label not in observed_mapping:
            fail(f"Expected label '{label}' not found in target.csv.")
        if observed_mapping[label] != code:
            fail(
                f"Label encoding mismatch for '{label}': expected {code}, "
                f"found {observed_mapping[label]}."
            )
    if observed_mapping != {**label_mapping}:
        fail(f"target.csv label encoding {observed_mapping} does not match Feature 4 report {label_mapping}.")

    for name, df_ in [("features.csv", features_df), ("target.csv", target_df), ("timestamp.csv", timestamp_df)]:
        if "row_id" not in df_.columns:
            fail(f"{name} is missing required 'row_id' column.")

    return actual_feature_columns


def validate_alignment(features_df, target_df, timestamp_df) -> dict:
    """Explicit row_id alignment validation - never assumed from equal row counts alone."""
    results = {}

    features_ids = features_df["row_id"]
    target_ids = target_df["row_id"]
    timestamp_ids = timestamp_df["row_id"]

    results["features_row_id_unique"] = bool(features_ids.is_unique)
    results["target_row_id_unique"] = bool(target_ids.is_unique)
    results["timestamp_row_id_unique"] = bool(timestamp_ids.is_unique)

    if not (results["features_row_id_unique"] and results["target_row_id_unique"] and results["timestamp_row_id_unique"]):
        fail("Duplicate row_id values found within one or more Feature 4 input files.")

    features_set = set(features_ids)
    target_set = set(target_ids)
    timestamp_set = set(timestamp_ids)

    results["row_id_sets_identical"] = (features_set == target_set == timestamp_set)
    if not results["row_id_sets_identical"]:
        fail(
            "row_id sets differ across features.csv/target.csv/timestamp.csv. "
            f"features-only: {sorted(list(features_set - target_set - timestamp_set))[:10]}..."
        )

    results["same_row_count_all_files"] = (len(features_df) == len(target_df) == len(timestamp_df))
    results["features_row_count"] = len(features_df)
    results["target_row_count"] = len(target_df)
    results["timestamp_row_count"] = len(timestamp_df)

    merged = features_df.merge(target_df, on="row_id", how="inner", validate="one_to_one")
    merged = merged.merge(timestamp_df, on="row_id", how="inner", validate="one_to_one")

    results["merged_row_count"] = len(merged)
    results["no_row_lost_in_join"] = len(merged) == len(features_df) == len(target_df) == len(timestamp_df)
    results["no_duplicate_row_id_after_join"] = bool(merged["row_id"].is_unique)

    if not results["no_row_lost_in_join"]:
        fail(
            f"Row count changed after joining on row_id (features={len(features_df)}, "
            f"target={len(target_df)}, timestamp={len(timestamp_df)}, merged={len(merged)})."
        )
    if not results["no_duplicate_row_id_after_join"]:
        fail("Duplicate row_id introduced by the join.")

    return merged, results


def build_temporal_report(df: pd.DataFrame) -> dict:
    ts = df["timestamp"]
    is_monotonic = bool(ts.is_monotonic_increasing)
    counts_per_timestamp = ts.value_counts()
    duplicate_timestamp_count = int((counts_per_timestamp > 1).sum())
    rows_with_duplicated_timestamp = int((counts_per_timestamp[counts_per_timestamp > 1]).sum())

    return {
        "min_timestamp": str(ts.min()),
        "max_timestamp": str(ts.max()),
        "num_unique_timestamps": int(ts.nunique()),
        "timestamps_monotonically_non_decreasing": is_monotonic,
        "duplicate_timestamp_count": duplicate_timestamp_count,
        "rows_sharing_a_duplicated_timestamp": rows_with_duplicated_timestamp,
        "observations_per_timestamp_summary": {
            "min": int(counts_per_timestamp.min()),
            "max": int(counts_per_timestamp.max()),
            "mean": round(float(counts_per_timestamp.mean()), 4),
            "median": float(counts_per_timestamp.median()),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Construct network state S(t) from Feature 4 model-ready outputs.")
    parser.add_argument("--model-ready-dir", default=str(MODEL_READY_DIR), help="Directory with Feature 4 outputs.")
    parser.add_argument("--output-dir", default="data/processed/states", help="Directory for state outputs.")
    parser.add_argument("--report-dir", default="results", help="Directory for reports.")
    args = parser.parse_args()

    model_ready_dir = Path(args.model_ready_dir)
    output_dir = Path(args.output_dir)
    report_dir = Path(args.report_dir)

    features_path = model_ready_dir / "features.csv"
    target_path = model_ready_dir / "target.csv"
    timestamp_path = model_ready_dir / "timestamp.csv"
    pipeline_path = model_ready_dir / "preprocessing_pipeline.joblib"

    for p in [features_path, target_path, timestamp_path, pipeline_path]:
        if not p.exists():
            fail(f"Required Feature 4 file not found: {p}")

    print("Loading Feature 4 reference schema ...")
    reference = load_feature4_reference()

    print("Loading Feature 4 outputs ...")
    features_df = pd.read_csv(features_path)
    target_df = pd.read_csv(target_path)
    timestamp_df = pd.read_csv(timestamp_path)

    print("Validating Feature 4 assumptions ...")
    feature_columns = validate_feature4_inputs(features_df, target_df, timestamp_df, reference)
    print(f"  OK: {len(feature_columns)} feature columns match the Feature 4 report exactly.")

    # Parse timestamp explicitly (it was already validated/parsed in Feature 4; here we
    # just re-parse from the stored CSV string using the unambiguous ISO format it was
    # written in, and stop rather than guess if that fails).
    parsed_ts = pd.to_datetime(timestamp_df["Timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    n_failed = int(parsed_ts.isna().sum())
    if n_failed > 0:
        fail(f"{n_failed} timestamps in timestamp.csv failed to parse with format %Y-%m-%d %H:%M:%S.")
    timestamp_df = timestamp_df.copy()
    timestamp_df["timestamp"] = parsed_ts

    print("Validating row_id alignment across features/target/timestamp ...")
    merged, alignment_results = validate_alignment(features_df, target_df, timestamp_df)
    print(f"  OK: {alignment_results['merged_row_count']} rows aligned with no loss or duplication.")

    # --- assemble the state table ---
    print("Assembling state table S(t) ...")
    state_df = merged[["row_id", "timestamp"] + feature_columns + [TARGET_COLUMN_ORIGINAL, LABEL_COLUMN_ORIGINAL]].copy()
    state_df = state_df.rename(columns={TARGET_COLUMN_ORIGINAL: "target", LABEL_COLUMN_ORIGINAL: "label"})

    # Guard: target must never be part of the feature vector.
    if "target" in feature_columns or "label" in feature_columns:
        fail("Target/label column name collides with a feature column name.")
    if set(feature_columns) & {"target", "label", "row_id", "timestamp"}:
        fail("A feature column name collides with a reserved metadata/target column name.")

    # --- temporal ordering: timestamp ascending, row_id ascending (stable, no shuffle) ---
    print("Sorting by timestamp ascending, row_id ascending ...")
    state_df = state_df.sort_values(by=["timestamp", "row_id"], ascending=[True, True], kind="mergesort").reset_index(drop=True)

    if not state_df["timestamp"].is_monotonic_increasing:
        fail("Post-sort timestamps are not monotonically non-decreasing.")

    temporal_report = build_temporal_report(state_df)

    # --- missing / infinity check on final feature columns ---
    feature_matrix = state_df[feature_columns]
    missing_per_feature = {c: int(feature_matrix[c].isna().sum()) for c in feature_columns if feature_matrix[c].isna().sum() > 0}
    inf_per_feature = {c: int(np.isinf(feature_matrix[c]).sum()) for c in feature_columns if np.isinf(feature_matrix[c]).sum() > 0}

    label_distribution = {str(k): int(v) for k, v in state_df["label"].value_counts(dropna=False).items()}
    duplicate_row_id_count = int(state_df["row_id"].duplicated().sum())

    # --- final safety confirmations required by the spec ---
    confirmations = {
        "target_excluded_from_feature_vector": "target" not in feature_columns and "label" not in feature_columns,
        "timestamp_is_metadata_only": "timestamp" not in feature_columns,
        "dst_port_absent": "Dst Port" not in state_df.columns and "Dst Port" not in feature_columns,
        "row_id_is_metadata_only": "row_id" not in feature_columns,
        "no_additional_derived_features_created": set(feature_columns) == set(reference["expected_feature_columns"]),
        "feature_count_is_68": len(feature_columns) == EXPECTED_FEATURE_COUNT,
    }
    for key, ok in confirmations.items():
        if not ok:
            fail(f"Final safety confirmation failed: {key}")

    # --- write outputs ---
    output_dir.mkdir(parents=True, exist_ok=True)
    states_path = output_dir / "states.csv"
    state_df.to_csv(states_path, index=False)
    print(f"Wrote {states_path} ({len(state_df)} rows x {len(state_df.columns)} columns)")

    state_metadata = {
        "state_name": "S(t)",
        "row_count": len(state_df),
        "column_count": len(state_df.columns),
        "columns": list(state_df.columns),
        "dtypes": {c: str(state_df[c].dtype) for c in state_df.columns},
        "feature_count": len(feature_columns),
        "metadata_columns": ["row_id", "timestamp"],
        "target_columns": ["target", "label"],
        "sorted_by": ["timestamp ascending", "row_id ascending"],
        "source_files": {
            "features": str(features_path),
            "target": str(target_path),
            "timestamp": str(timestamp_path),
        },
    }
    metadata_path = output_dir / "state_metadata.json"
    metadata_path.write_text(json.dumps(state_metadata, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metadata_path}")

    # --- results/state_schema.json ---
    schema = {
        "state_name": "S(t)",
        "feature_count": len(feature_columns),
        "feature_column_names": feature_columns,
        "feature_dtypes": {c: str(state_df[c].dtype) for c in feature_columns},
        "metadata_columns": {
            "row_id": str(state_df["row_id"].dtype),
            "timestamp": str(state_df["timestamp"].dtype),
        },
        "target_columns": {
            "target": {"dtype": str(state_df["target"].dtype), "encoding": reference["label_mapping"]},
            "label": {"dtype": str(state_df["label"].dtype), "description": "Original human-readable label (Benign / Infilteration)."},
        },
        "ordering_rule": "Sorted by timestamp ascending, then row_id ascending as a deterministic tie-breaker for identical timestamps. Data is never shuffled.",
        "source_files": {
            "features_csv": str(features_path),
            "target_csv": str(target_path),
            "timestamp_csv": str(timestamp_path),
            "feature4_preparation_report": str(FEATURE_REPORT_PATH),
            "feature4_feature_list": str(FEATURE_LIST_PATH),
        },
        "leakage_exclusions": {
            "target_and_label_not_in_feature_vector": True,
            "timestamp_not_in_feature_vector": True,
            "row_id_not_in_feature_vector": True,
            "dst_port_not_present": True,
        },
        "notes": (
            "This is a per-observation state (one row per original flow record), not yet "
            "aggregated into fixed time windows or sequences. Feature column names are kept "
            "identical to the Feature 4 model-ready columns (not renamed to feature_1..feature_68) "
            "to preserve traceability to the Feature 3 audit reasoning."
        ),
    }
    schema_path = report_dir / "state_schema.json"
    report_dir.mkdir(parents=True, exist_ok=True)
    schema_path.write_text(json.dumps(schema, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {schema_path}")

    # --- results/state_construction_report.json / .txt ---
    report = {
        "inputs": {
            "features_csv": {"path": str(features_path), "row_count": len(features_df)},
            "target_csv": {"path": str(target_path), "row_count": len(target_df)},
            "timestamp_csv": {"path": str(timestamp_path), "row_count": len(timestamp_df)},
        },
        "alignment_validation": alignment_results,
        "final_state_row_count": len(state_df),
        "state_feature_count": len(feature_columns),
        "feature_names": feature_columns,
        "timestamp_range": {"min": temporal_report["min_timestamp"], "max": temporal_report["max_timestamp"]},
        "unique_timestamp_count": temporal_report["num_unique_timestamps"],
        "duplicate_timestamp_count": temporal_report["duplicate_timestamp_count"],
        "timestamps_monotonically_non_decreasing": temporal_report["timestamps_monotonically_non_decreasing"],
        "observations_per_timestamp_summary": temporal_report["observations_per_timestamp_summary"],
        "label_distribution": label_distribution,
        "missing_values_in_state_features": missing_per_feature,
        "infinite_values_in_state_features": inf_per_feature,
        "duplicate_row_id_count": duplicate_row_id_count,
        "confirmations": confirmations,
        "outputs": {
            "states_csv": str(states_path),
            "state_metadata_json": str(metadata_path),
            "state_schema_json": str(schema_path),
        },
    }
    report_json_path = report_dir / "state_construction_report.json"
    report_json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    report_txt_path = report_dir / "state_construction_report.txt"
    report_txt_path.write_text(format_text_report(report), encoding="utf-8")
    print(f"Wrote {report_json_path}, {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Files created: {states_path}, {metadata_path}, {schema_path}, {report_json_path}, {report_txt_path}")
    print("Command used: python src/data/build_states.py")
    print(f"Number of states created: {len(state_df)}")
    print(f"Number of state features: {len(feature_columns)}")
    print(f"Timestamp range: {temporal_report['min_timestamp']} -> {temporal_report['max_timestamp']}")
    print(f"Number of unique timestamps: {temporal_report['num_unique_timestamps']}")
    print(f"Temporal ordering valid: {temporal_report['timestamps_monotonically_non_decreasing']}")
    print(f"Row alignment passed: {alignment_results['no_row_lost_in_join'] and alignment_results['no_duplicate_row_id_after_join']}")
    print(f"Label distribution: {label_distribution}")
    print(f"Missing values remaining in features: {missing_per_feature}")
    print(f"Infinite values remaining in features: {inf_per_feature}")
    print(f"Target excluded from S(t) feature vector: {confirmations['target_excluded_from_feature_vector']}")
    print("Sequences/model/forecasting created: False (out of scope for Feature 5)")

    return report


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("NETWORK STATE S(t) CONSTRUCTION REPORT")
    lines.append("=" * 70)

    lines.append("")
    lines.append("-" * 70)
    lines.append("INPUTS")
    lines.append("-" * 70)
    for name, info in report["inputs"].items():
        lines.append(f"  {name}: {info['path']} ({info['row_count']} rows)")

    lines.append("")
    lines.append("-" * 70)
    lines.append("ALIGNMENT VALIDATION")
    lines.append("-" * 70)
    for k, v in report["alignment_validation"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STATE TABLE")
    lines.append("-" * 70)
    lines.append(f"  Final state row count: {report['final_state_row_count']}")
    lines.append(f"  State feature count: {report['state_feature_count']}")
    lines.append(f"  Feature names: {report['feature_names']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("TEMPORAL ORDERING")
    lines.append("-" * 70)
    lines.append(f"  Timestamp range: {report['timestamp_range']['min']} -> {report['timestamp_range']['max']}")
    lines.append(f"  Unique timestamp count: {report['unique_timestamp_count']}")
    lines.append(f"  Duplicate timestamp count: {report['duplicate_timestamp_count']}")
    lines.append(f"  Monotonically non-decreasing: {report['timestamps_monotonically_non_decreasing']}")
    lines.append(f"  Observations per timestamp summary: {report['observations_per_timestamp_summary']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("LABEL DISTRIBUTION")
    lines.append("-" * 70)
    for label, count in report["label_distribution"].items():
        lines.append(f"  {label}: {count}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("MISSING / INFINITE VALUES IN STATE FEATURES")
    lines.append("-" * 70)
    lines.append(f"  Missing values: {report['missing_values_in_state_features'] or 'None'}")
    lines.append(f"  Infinite values: {report['infinite_values_in_state_features'] or 'None'}")
    lines.append(f"  Duplicate row_id count: {report['duplicate_row_id_count']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("CONFIRMATIONS")
    lines.append("-" * 70)
    for k, v in report["confirmations"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("OUTPUTS")
    lines.append("-" * 70)
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
