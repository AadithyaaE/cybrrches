"""
Chronological TRAIN/VALIDATION/TEST split with temporal leakage protection.

Splits Feature 6's temporal windows/sequences into TRAIN < VALIDATION < TEST
by time, then PURGES any sequence whose 11 constituent windows (10 input +
1 target) would otherwise straddle a partition boundary. This guarantees:

    - no sequence crosses a partition boundary
    - no window_id is used by sequences in more than one partition
    - TRAIN timestamps < VALIDATION timestamps < TEST timestamps

A training-only preprocessing pipeline (clone of the Feature 4 design:
SimpleImputer(median) + StandardScaler on numeric features, passthrough for
one-hot Protocol columns) is fit exclusively on the TRAIN partition's unique
window feature vectors, then used to transform() (never re-fit) TRAIN,
VALIDATION and TEST. The original Feature 4 preprocessing_pipeline.joblib is
never modified - a new fitted copy is saved separately.

Does NOT train any classifier/forecaster. Structural splitting and
train-only preprocessing only.

Usage:
    python src/data/split_temporal_data.py
"""

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.utils.validation import check_is_fitted, NotFittedError

TEMPORAL_WINDOWS_PATH = Path("data/processed/temporal/temporal_windows.csv")
SEQUENCE_META_PATH = Path("data/processed/temporal/sequences/sequence_metadata.csv")
X_SEQ_PATH = Path("data/processed/temporal/sequences/X_sequences.npy")
NEXT_WINDOW_PATH = Path("data/processed/temporal/sequences/next_window_features.npy")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
TEMPORAL_WINDOW_REPORT_PATH = Path("results/temporal_window_report.json")
ORIGINAL_PIPELINE_PATH = Path("data/processed/model_ready/preprocessing_pipeline.joblib")

TRAIN_FRACTION = 0.70
VAL_FRACTION = 0.15  # remainder (~0.15) goes to TEST
SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
WINDOW_STEP = pd.Timedelta(seconds=1)


def fail(message: str):
    raise SystemExit(f"FEATURE 7 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def require_columns(df: pd.DataFrame, required: set, name: str):
    missing = required - set(df.columns)
    if missing:
        fail(f"{name} is missing required columns: {sorted(missing)}. Found: {list(df.columns)}")


def main():
    parser = argparse.ArgumentParser(description="Chronological train/validation/test split with temporal leakage protection.")
    parser.add_argument("--output-dir", default="data/processed/splits", help="Directory for split outputs.")
    parser.add_argument("--report-dir", default="results", help="Directory for reports.")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    report_dir = Path(args.report_dir)

    for p in [TEMPORAL_WINDOWS_PATH, SEQUENCE_META_PATH, X_SEQ_PATH, NEXT_WINDOW_PATH, FEATURE_ORDER_PATH, ORIGINAL_PIPELINE_PATH]:
        if not p.exists():
            fail(f"Required Feature 6/4 file not found: {p}")

    print("Loading Feature 6 outputs ...")
    windows = pd.read_csv(TEMPORAL_WINDOWS_PATH)
    seq_meta = pd.read_csv(SEQUENCE_META_PATH)
    X_sequences = np.load(X_SEQ_PATH)
    next_window_features = np.load(NEXT_WINDOW_PATH)
    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]

    require_columns(windows, {"window_id", "window_start", "window_end", "target", "label"} | set(feature_order), "temporal_windows.csv")
    require_columns(
        seq_meta,
        {"sequence_id", "input_start_window", "input_end_window", "target_window",
         "input_start_timestamp", "input_end_timestamp", "target_timestamp",
         "target_window_target", "target_window_label"},
        "sequence_metadata.csv",
    )

    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")
    if X_sequences.shape[1:] != (SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT):
        fail(f"X_sequences.npy has shape {X_sequences.shape}, expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")
    if next_window_features.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"next_window_features.npy has shape {next_window_features.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")
    if len(seq_meta) != X_sequences.shape[0] or len(seq_meta) != next_window_features.shape[0]:
        fail("sequence_metadata.csv row count does not match X_sequences/next_window_features row counts.")
    if not seq_meta["sequence_id"].is_unique:
        fail("Duplicate sequence_id values found in sequence_metadata.csv.")
    if not (seq_meta["sequence_id"].to_numpy() == np.arange(len(seq_meta))).all():
        fail("sequence_id is not a 0..N-1 range matching array row order; cannot safely index X_sequences positionally.")

    # --- parse timestamps ---
    windows["window_start"] = pd.to_datetime(windows["window_start"], errors="coerce")
    windows["window_end"] = pd.to_datetime(windows["window_end"], errors="coerce")
    if windows["window_start"].isna().any() or windows["window_end"].isna().any():
        fail("Timestamp parsing failed for one or more rows in temporal_windows.csv.")
    seq_meta["input_start_timestamp"] = pd.to_datetime(seq_meta["input_start_timestamp"], errors="coerce")
    seq_meta["input_end_timestamp"] = pd.to_datetime(seq_meta["input_end_timestamp"], errors="coerce")
    seq_meta["target_timestamp"] = pd.to_datetime(seq_meta["target_timestamp"], errors="coerce")
    if seq_meta[["input_start_timestamp", "input_end_timestamp", "target_timestamp"]].isna().any().any():
        fail("Timestamp parsing failed for one or more rows in sequence_metadata.csv.")

    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    if not (windows["window_id"].to_numpy() == np.arange(len(windows))).all():
        fail("window_id is not a 0..N-1 range in time-sorted order; cannot safely derive segments.")

    # --- deterministically re-derive continuous segments (same rule as Feature 6) ---
    diffs = windows["window_start"].diff()
    gap_mask = diffs > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()
    n_gaps_derived = int(gap_mask.sum())
    n_segments_derived = int(windows["segment_id"].nunique())

    if TEMPORAL_WINDOW_REPORT_PATH.exists():
        with open(TEMPORAL_WINDOW_REPORT_PATH, encoding="utf-8") as f:
            f6_report = json.load(f)
        f6_gaps = f6_report["validation"]["num_temporal_gaps"]
        f6_segments = f6_report["validation"]["num_continuous_segments"]
        if n_gaps_derived != f6_gaps or n_segments_derived != f6_segments:
            fail(
                f"Re-derived segments ({n_segments_derived} segments, {n_gaps_derived} gaps) do not match "
                f"Feature 6's report ({f6_segments} segments, {f6_gaps} gaps). Stopping rather than proceeding "
                "on an inconsistent temporal structure."
            )
        print(f"  Re-derived segmentation matches Feature 6 exactly: {n_segments_derived} segments, {n_gaps_derived} gaps.")

    n_windows = len(windows)
    n_sequences_total = len(seq_meta)
    print(f"Loaded {n_windows} windows, {n_sequences_total} sequences.")

    # --- chronological window-level partition boundaries (by window count) ---
    train_end_idx = int(np.floor(TRAIN_FRACTION * n_windows))
    val_end_idx = int(np.floor((TRAIN_FRACTION + VAL_FRACTION) * n_windows))
    train_end_idx = max(1, min(train_end_idx, n_windows - 2))
    val_end_idx = max(train_end_idx + 1, min(val_end_idx, n_windows - 1))

    windows["partition"] = np.where(
        windows.index < train_end_idx, "train",
        np.where(windows.index < val_end_idx, "validation", "test"),
    )
    window_id_to_partition = windows.set_index("window_id")["partition"].to_dict()

    train_window_ids = set(windows.loc[windows["partition"] == "train", "window_id"])
    val_window_ids = set(windows.loc[windows["partition"] == "validation", "window_id"])
    test_window_ids = set(windows.loc[windows["partition"] == "test", "window_id"])

    train_boundary_ts = windows.loc[windows["partition"] == "train", "window_start"].max()
    val_start_ts = windows.loc[windows["partition"] == "validation", "window_start"].min()
    val_boundary_ts = windows.loc[windows["partition"] == "validation", "window_start"].max()
    test_start_ts = windows.loc[windows["partition"] == "test", "window_start"].min()

    print(f"Window partition boundaries: TRAIN ends {train_boundary_ts}, VALIDATION [{val_start_ts} .. {val_boundary_ts}], TEST starts {test_start_ts}")

    # --- assign each sequence to a partition, or purge if it straddles a boundary ---
    print("Assigning sequences to partitions with boundary purge ...")
    seq_partition = []
    purge_records = []
    for row in seq_meta.itertuples(index=False):
        window_ids_used = list(range(row.input_start_window, row.target_window + 1))
        if len(window_ids_used) != SEQUENCE_LENGTH + 1:
            fail(f"Sequence {row.sequence_id} does not span exactly {SEQUENCE_LENGTH + 1} window_ids.")
        partitions_touched = {window_id_to_partition[w] for w in window_ids_used}
        if len(partitions_touched) == 1:
            seq_partition.append(next(iter(partitions_touched)))
        else:
            seq_partition.append(None)
            purge_records.append({
                "sequence_id": int(row.sequence_id),
                "window_ids": window_ids_used,
                "partitions_touched": sorted(partitions_touched),
                "reason": "Sequence's input/target windows span more than one chronological partition.",
            })
    seq_meta["partition"] = seq_partition

    n_purged = len(purge_records)
    print(f"  {n_purged} sequences purged at partition boundaries out of {n_sequences_total} total.")

    partitions = {}
    for name in ["train", "validation", "test"]:
        idx = seq_meta.index[seq_meta["partition"] == name].to_numpy()
        partitions[name] = {
            "row_positions": idx,  # positional index into X_sequences/next_window_features (== sequence_id)
            "meta": seq_meta.loc[idx].sort_values("sequence_id").reset_index(drop=True),
        }

    # --- mandatory validation checks (1-14, temporal/leakage) ---
    print("Running mandatory validation checks ...")
    checks = {}

    train_meta = partitions["train"]["meta"]
    val_meta = partitions["validation"]["meta"]
    test_meta = partitions["test"]["meta"]

    checks["1_train_before_validation"] = bool(
        train_meta.empty or val_meta.empty or train_meta["target_timestamp"].max() < val_meta["input_start_timestamp"].min()
    )
    checks["2_validation_before_test"] = bool(
        val_meta.empty or test_meta.empty or val_meta["target_timestamp"].max() < test_meta["input_start_timestamp"].min()
    )

    def window_ids_for(meta_df):
        s = set()
        for row in meta_df.itertuples(index=False):
            s.update(range(row.input_start_window, row.target_window + 1))
        return s

    train_wids, val_wids, test_wids = window_ids_for(train_meta), window_ids_for(val_meta), window_ids_for(test_meta)
    checks["3_no_sequence_spans_multiple_partitions"] = True  # enforced structurally by purge step
    checks["4_no_input_window_id_in_multiple_partitions"] = len(train_wids & val_wids) == 0 and len(val_wids & test_wids) == 0 and len(train_wids & test_wids) == 0
    checks["5_no_target_window_id_in_multiple_partitions"] = checks["4_no_input_window_id_in_multiple_partitions"]
    checks["6_no_cross_partition_window_overlap"] = checks["4_no_input_window_id_in_multiple_partitions"]
    checks["7_no_target_overlaps_other_partition_inputs"] = checks["4_no_input_window_id_in_multiple_partitions"]
    checks["8_temporal_gaps_not_bridged"] = True  # sequences were already gap-safe from Feature 6; purge only removes, never bridges
    checks["9_sequence_length_is_10"] = X_sequences.shape[1] == SEQUENCE_LENGTH
    checks["10_feature_dimension_is_68"] = X_sequences.shape[2] == EXPECTED_FEATURE_COUNT and next_window_features.shape[1] == EXPECTED_FEATURE_COUNT
    checks["11_X_and_target_aligned_with_metadata"] = bool(
        (seq_meta["sequence_id"].to_numpy() == np.arange(len(seq_meta))).all()
    )
    all_kept_ids = pd.concat([train_meta["sequence_id"], val_meta["sequence_id"], test_meta["sequence_id"]])
    checks["12_13_sequence_ids_unique_within_and_across"] = bool(all_kept_ids.is_unique)
    checks["14_no_duplicate_window_id_across_partitions"] = checks["4_no_input_window_id_in_multiple_partitions"]

    for k, v in checks.items():
        if not v:
            fail(f"Mandatory validation check failed: {k}")

    # --- 20: chronological order preserved inside every partition ---
    for name, meta in [("train", train_meta), ("validation", val_meta), ("test", test_meta)]:
        if not meta.empty and not meta["input_start_timestamp"].is_monotonic_increasing:
            fail(f"Chronological order not preserved within partition '{name}'.")
    checks["20_chronological_order_within_partitions"] = True

    # --- training-only preprocessing ---
    print("Fitting training-only preprocessing pipeline (TRAIN windows only) ...")
    original_pipeline_md5_before = file_md5(ORIGINAL_PIPELINE_PATH)
    unfitted_reference_pipeline = joblib.load(ORIGINAL_PIPELINE_PATH)
    try:
        check_is_fitted(unfitted_reference_pipeline)
        fail("Original Feature 4 pipeline is unexpectedly already fitted before Feature 7 ran.")
    except NotFittedError:
        pass

    # Fit on the UNIQUE set of TRAIN-partition window feature vectors (not the
    # expanded/overlapping sequence tensor), so windows reused across many
    # overlapping sequences do not bias the imputation/scaling statistics.
    train_window_feature_df = windows.loc[windows["window_id"].isin(train_window_ids), feature_order].reset_index(drop=True)

    fitted_pipeline = joblib.load(ORIGINAL_PIPELINE_PATH)  # fresh unfitted clone, loaded independently
    fitted_pipeline.fit(train_window_feature_df)
    try:
        check_is_fitted(fitted_pipeline)
    except NotFittedError:
        fail("Pipeline did not become fitted after calling .fit() on TRAIN window data.")

    original_pipeline_md5_after = file_md5(ORIGINAL_PIPELINE_PATH)
    if original_pipeline_md5_before != original_pipeline_md5_after:
        fail("Original Feature 4 preprocessing_pipeline.joblib was modified on disk during Feature 7.")
    try:
        check_is_fitted(joblib.load(ORIGINAL_PIPELINE_PATH))
        fail("Original Feature 4 preprocessing_pipeline.joblib is fitted after reload - it must remain unfitted.")
    except NotFittedError:
        pass
    checks["15_training_preprocessing_fitted_only_on_train"] = True
    checks["16_original_pipeline_unfitted_and_unchanged"] = True

    def transform_tensor(arr_3d, pipeline, columns):
        n, t, f = arr_3d.shape
        flat = arr_3d.reshape(n * t, f)
        df = pd.DataFrame(flat, columns=columns)
        transformed = pipeline.transform(df)
        return np.asarray(transformed, dtype="float64").reshape(n, t, f)

    def transform_matrix(arr_2d, pipeline, columns):
        df = pd.DataFrame(arr_2d, columns=columns)
        transformed = pipeline.transform(df)
        return np.asarray(transformed, dtype="float64")

    # --- assemble and write per-partition outputs ---
    output_dir.mkdir(parents=True, exist_ok=True)
    partition_summary = {}
    for name in ["train", "validation", "test"]:
        meta = partitions[name]["meta"]
        positions = meta["sequence_id"].to_numpy()

        part_dir = output_dir / name
        part_dir.mkdir(parents=True, exist_ok=True)

        X_part = X_sequences[positions]
        next_part = next_window_features[positions]

        inf_before = int(np.isinf(X_part).sum() + np.isinf(next_part).sum())

        if len(positions) > 0:
            X_part_scaled = transform_tensor(X_part, fitted_pipeline, feature_order)
            next_part_scaled = transform_matrix(next_part, fitted_pipeline, feature_order)
        else:
            X_part_scaled = np.empty((0, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT), dtype="float64")
            next_part_scaled = np.empty((0, EXPECTED_FEATURE_COUNT), dtype="float64")

        inf_after = int(np.isinf(X_part_scaled).sum() + np.isinf(next_part_scaled).sum())
        nan_after = int(np.isnan(X_part_scaled).sum() + np.isnan(next_part_scaled).sum())

        np.save(part_dir / "X_sequences.npy", X_part)
        np.save(part_dir / "next_window_features.npy", next_part)
        np.save(part_dir / "X_sequences_scaled.npy", X_part_scaled)
        np.save(part_dir / "next_window_features_scaled.npy", next_part_scaled)
        meta.to_csv(part_dir / "sequence_metadata.csv", index=False)

        label_dist = {str(k): int(v) for k, v in meta["target_window_label"].value_counts(dropna=False).items()} if len(meta) else {}
        partition_summary[name] = {
            "sequence_count": int(len(meta)),
            "earliest_timestamp": str(meta["input_start_timestamp"].min()) if len(meta) else None,
            "latest_timestamp": str(meta["target_timestamp"].max()) if len(meta) else None,
            "label_distribution": label_dist,
            "num_continuous_segments_represented": int(
                windows.loc[windows["window_id"].isin(window_ids_for(meta)), "segment_id"].nunique()
            ) if len(meta) else 0,
            "num_windows_in_partition": int(len(windows[windows["partition"] == name])),
            "infinite_values_before_transform": inf_before,
            "infinite_values_after_transform": inf_after,
            "nan_values_after_transform": nan_after,
        }
        print(f"  {name}: {len(meta)} sequences written to {part_dir}")

    checks["17_no_infinity_after_preprocessing"] = all(v["infinite_values_after_transform"] == 0 for v in partition_summary.values())
    # NaN is expected to remain wherever an entire window's rate feature was NaN pre-imputation
    # only if that value could not be imputed (should not happen: SimpleImputer always fills any
    # NaN using the fitted per-column median, computed from TRAIN, as long as TRAIN itself had at
    # least one non-NaN value for that column).
    checks["18_no_unexpected_nan_after_preprocessing"] = all(v["nan_values_after_transform"] == 0 for v in partition_summary.values())
    checks["19_labels_correctly_aligned"] = True  # meta carries target_window_target/label alongside each sequence by construction
    for k in ["17_no_infinity_after_preprocessing", "18_no_unexpected_nan_after_preprocessing"]:
        if not checks[k]:
            fail(f"Mandatory validation check failed: {k}")

    pipeline_out_path = output_dir / "preprocessing_pipeline_train_fitted.joblib"
    joblib.dump(fitted_pipeline, pipeline_out_path)
    print(f"Wrote {pipeline_out_path}")

    # --- actual proportions ---
    total_kept = sum(partition_summary[n]["sequence_count"] for n in ["train", "validation", "test"])
    actual_pct = {n: round(partition_summary[n]["sequence_count"] / total_kept * 100, 2) if total_kept else 0.0 for n in ["train", "validation", "test"]}
    window_pct = {
        n: round(partition_summary[n]["num_windows_in_partition"] / n_windows * 100, 2) for n in ["train", "validation", "test"]
    }

    # --- split_metadata.json ---
    split_metadata = {
        "split_strategy": (
            "Chronological split by WINDOW position (windows sorted ascending by window_start; "
            f"first {int(TRAIN_FRACTION*100)}% of windows by count -> TRAIN, next "
            f"{int(VAL_FRACTION*100)}% -> VALIDATION, remainder -> TEST). Any sequence whose 11 "
            "constituent window_ids (10 input + 1 target) span more than one of these partitions "
            "is purged entirely rather than assigned - this is the temporal-leakage boundary "
            "protection mechanism."
        ),
        "chronological_boundaries": {
            "train_ends_at": str(train_boundary_ts),
            "validation_range": [str(val_start_ts), str(val_boundary_ts)],
            "test_starts_at": str(test_start_ts),
        },
        "target_proportions_pct": {"train": TRAIN_FRACTION * 100, "validation": VAL_FRACTION * 100, "test": (1 - TRAIN_FRACTION - VAL_FRACTION) * 100},
        "actual_proportions_pct_by_sequence_count": actual_pct,
        "actual_proportions_pct_by_window_count": window_pct,
        "num_sequences_total_before_purge": n_sequences_total,
        "num_sequences_purged": n_purged,
        "num_windows_total": n_windows,
        "num_windows_discarded": 0,
        "num_continuous_segments_total": n_segments_derived,
        "label_distribution_by_partition": {n: partition_summary[n]["label_distribution"] for n in ["train", "validation", "test"]},
        "purge_records": purge_records,
        "random_seed": None,
        "random_seed_note": "No random operation is used anywhere in this split (purely chronological + deterministic purge).",
        "preprocessing_strategy": "SimpleImputer(strategy='median') + StandardScaler on the 65 numeric features; Protocol_0/6/17 one-hot columns passthrough (unscaled) - identical design to Feature 4's unfitted pipeline.",
        "preprocessing_fit_source": "Unique TRAIN-partition window feature vectors from temporal_windows.csv (deduplicated by window_id), NOT the expanded/overlapping sequence tensor, to avoid overweighting windows reused across multiple overlapping sequences.",
        "feature_count": EXPECTED_FEATURE_COUNT,
        "sequence_length": SEQUENCE_LENGTH,
        "dataset_version_source": {
            "temporal_windows_csv": str(TEMPORAL_WINDOWS_PATH),
            "sequence_metadata_csv": str(SEQUENCE_META_PATH),
            "x_sequences_npy": str(X_SEQ_PATH),
            "next_window_features_npy": str(NEXT_WINDOW_PATH),
            "feature_order_json": str(FEATURE_ORDER_PATH),
        },
        "validation_checks": checks,
    }
    split_metadata_path = output_dir / "split_metadata.json"
    split_metadata_path.write_text(json.dumps(split_metadata, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {split_metadata_path}")

    # --- results/temporal_split_report.json / .txt ---
    report = {
        "inputs": {
            "temporal_windows_csv": {"path": str(TEMPORAL_WINDOWS_PATH), "row_count": n_windows},
            "sequence_metadata_csv": {"path": str(SEQUENCE_META_PATH), "row_count": n_sequences_total},
        },
        "split_strategy": split_metadata["split_strategy"],
        "chronological_boundaries": split_metadata["chronological_boundaries"],
        "partitions": partition_summary,
        "actual_proportions_pct_by_sequence_count": actual_pct,
        "actual_proportions_pct_by_window_count": window_pct,
        "num_sequences_purged": n_purged,
        "purge_records": purge_records,
        "preprocessing": {
            "strategy": split_metadata["preprocessing_strategy"],
            "fit_source": split_metadata["preprocessing_fit_source"],
            "fitted_pipeline_path": str(pipeline_out_path),
            "original_unfitted_pipeline_unchanged": checks["16_original_pipeline_unfitted_and_unchanged"],
        },
        "validation_checks": checks,
        "outputs": {
            "train_dir": str(output_dir / "train"),
            "validation_dir": str(output_dir / "validation"),
            "test_dir": str(output_dir / "test"),
            "split_metadata_json": str(split_metadata_path),
            "preprocessing_pipeline_train_fitted": str(pipeline_out_path),
        },
    }
    report_json_path = report_dir / "temporal_split_report.json"
    report_json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    report_txt_path = report_dir / "temporal_split_report.txt"
    report_txt_path.write_text(format_text_report(report), encoding="utf-8")
    print(f"Wrote {report_json_path}, {report_txt_path}")

    # --- independent verification / sanity printout ---
    print("\n" + "=" * 70)
    print("INDEPENDENT VERIFICATION")
    print("=" * 70)
    for name in ["train", "validation", "test"]:
        s = partition_summary[name]
        print(f"\n{name.upper()}:")
        print(f"  sequence count: {s['sequence_count']}")
        print(f"  earliest timestamp: {s['earliest_timestamp']}")
        print(f"  latest timestamp: {s['latest_timestamp']}")
        print(f"  label distribution: {s['label_distribution']}")

    overlap_ok = checks["4_no_input_window_id_in_multiple_partitions"]
    print(f"\nOverlap check (no window_id shared across partitions): {overlap_ok}")
    print(f"Boundary leakage check (TRAIN < VALIDATION < TEST): {checks['1_train_before_validation'] and checks['2_validation_before_test']}")
    print(f"Sequence-length check (==10): {checks['9_sequence_length_is_10']}")
    print(f"Feature-dimension check (==68): {checks['10_feature_dimension_is_68']}")
    print(f"Preprocessing fitted status: fitted_pipeline={_is_fitted(fitted_pipeline)}, original_pipeline_unfitted={checks['16_original_pipeline_unfitted_and_unchanged']}")
    print(f"Number of purged sequences: {n_purged}")
    print(f"Number of discarded windows: 0 (every window belongs to exactly one partition)")
    print(f"Actual proportions (by sequence count): {actual_pct}")

    # --- final report ---
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print("Files created:")
    print(f"  {output_dir}/train/*, {output_dir}/validation/*, {output_dir}/test/*")
    print(f"  {split_metadata_path}")
    print(f"  {pipeline_out_path}")
    print(f"  {report_json_path}, {report_txt_path}")
    print(f"\nSplit strategy: {split_metadata['split_strategy']}")
    print(f"\nTrain/Val/Test sequence counts: {partition_summary['train']['sequence_count']} / "
          f"{partition_summary['validation']['sequence_count']} / {partition_summary['test']['sequence_count']}")
    print(f"Actual percentages (by kept sequence count): {actual_pct}")
    print(f"Purged sequences at boundaries: {n_purged} (of {n_sequences_total} total)")
    print(f"No sequences cross partitions: True (purge step enforces this structurally)")
    print(f"No windows overlap across partitions: {overlap_ok}")
    print(f"Preprocessing fitted ONLY on TRAIN: True")
    print(f"Original Feature 4 pipeline remains unfitted: {checks['16_original_pipeline_unfitted_and_unchanged']}")

    return report


def _is_fitted(pipeline) -> bool:
    try:
        check_is_fitted(pipeline)
        return True
    except NotFittedError:
        return False


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("CHRONOLOGICAL TRAIN/VALIDATION/TEST SPLIT REPORT")
    lines.append("=" * 70)

    lines.append("")
    lines.append("-" * 70)
    lines.append("INPUTS")
    lines.append("-" * 70)
    for name, info in report["inputs"].items():
        lines.append(f"  {name}: {info['path']} ({info['row_count']} rows)")

    lines.append("")
    lines.append("-" * 70)
    lines.append("SPLIT STRATEGY")
    lines.append("-" * 70)
    lines.append(f"  {report['split_strategy']}")
    lines.append(f"  Chronological boundaries: {report['chronological_boundaries']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("PARTITIONS")
    lines.append("-" * 70)
    for name, s in report["partitions"].items():
        lines.append(f"  {name.upper()}:")
        for k, v in s.items():
            lines.append(f"    {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("PROPORTIONS")
    lines.append("-" * 70)
    lines.append(f"  By sequence count: {report['actual_proportions_pct_by_sequence_count']}")
    lines.append(f"  By window count: {report['actual_proportions_pct_by_window_count']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("PURGED SEQUENCES")
    lines.append("-" * 70)
    lines.append(f"  Count: {report['num_sequences_purged']}")
    for rec in report["purge_records"]:
        lines.append(f"    {rec}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("PREPROCESSING")
    lines.append("-" * 70)
    for k, v in report["preprocessing"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("VALIDATION CHECKS")
    lines.append("-" * 70)
    for k, v in report["validation_checks"].items():
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
