"""
Feature L1 - Label-Independent Network-State Preparation.

Sandbox Lab integration, step 1 of 5 (per the reviewed architecture):

    Sandbox/PCAP -> flow features -> [THIS: label-free network state]
        -> 68D CyberChess state -> existing frozen LSTM/classifiers

This module makes the existing state-preparation path usable when
ground-truth labels are unavailable. It does NOT implement PCAP parsing,
flow reconstruction, a backend/API, or any model training - those remain
future work. It assumes its input is already a "clean_df"-shaped
DataFrame: real dtypes, a parsed Timestamp column, a Protocol column, and
the 65 numeric feature columns present - the same shape
src/data/clean_dataset.py's clean_dataset() produces today, or that a
future flow-reconstruction stage would need to produce.

WHY RAW-CSV CLEANING IS OUT OF SCOPE HERE
--------------------------------------------
clean_dataset()'s duplicate-removal rule only removes rows identical
across ALL 80 columns, INCLUDING Label - two rows that are feature-
identical but carry different labels are deliberately kept (see
clean_dataset.py's own "removal_decision" text). Silently applying an
equivalent feature-only duplicate rule to unlabeled data could discard a
DIFFERENT set of rows than the labeled path would for the same raw data,
which would not be an honest "identical minus metadata" result. Feature
L1 therefore starts one step later than raw-CSV cleaning, from an
ALREADY-CLEANED/well-typed table, and leaves raw-capture cleaning to
whatever future flow-reconstruction stage produces the input.

WHAT IS PRESERVED EXACTLY (same as the labeled path)
-------------------------------------------------------
    - the 65 numeric feature names and their order
    - the Protocol_0/6/17 one-hot encoding (identical reindex-to-training-
      columns-fill-zero convention)
    - the 68-dimensional feature_order used throughout Features 1-16
    - the 1-second window/timestamp-flooring convention
    - the SUM/MEAN aggregation policy (build_aggregation_policy, reused
      unmodified)
    - the 10-step, gap/segment-safe sequence construction rule
    - the frozen, train-fitted preprocessing pipeline, applied via
      .transform() ONLY (never .fit()/.fit_transform())

WHAT IS DIFFERENT (label-dependent metadata only, never fabricated)
-----------------------------------------------------------------------
    - no target_df / no binary_target / no training_compatible_target
    - windows carry no benign_count / attack_count / attack_ratio /
      dominant_label
    - sequence metadata's target_window_binary_target and
      target_window_label are explicitly None (genuinely unknown - never
      guessed, never defaulted to "Benign"/0)

REUSED, UNMODIFIED (imported, never edited)
-----------------------------------------------
    - build_temporal_windows.py :: build_aggregation_policy()  (already
      label-independent)
    - prepare_external_dataset.py :: load_reference_artifacts()  (loads
      results/temporal_feature_order.json, results/model_feature_list.json,
      and the frozen data/processed/splits/preprocessing_pipeline_train_fitted.joblib
      - read-only)

This module is a pure, side-effect-free library: it never writes to disk
and is never imported by, nor imports from, anything under
data/processed/splits/ or results/ in a way that could modify them.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.utils.validation import check_is_fitted, NotFittedError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_temporal_windows import build_aggregation_policy  # noqa: E402 - reused unmodified
from prepare_external_dataset import load_reference_artifacts  # noqa: E402 - reused unmodified

TIMESTAMP_COLUMN = "Timestamp"
PROTOCOL_COLUMN = "Protocol"
EXPECTED_FEATURE_COUNT = 68
SEQUENCE_LENGTH = 10
WINDOW_STEP = pd.Timedelta(seconds=1)


def fail(message: str):
    raise SystemExit(f"FEATURE L1 VALIDATION FAILURE: {message}")


def build_model_ready_table_unlabeled(clean_df: pd.DataFrame, numeric_features: list, onehot_protocol_columns: list) -> tuple:
    """
    Label-free equivalent of prepare_external_dataset.build_model_ready_table().

    Never reads, requires, infers, or fabricates a Label/target column.
    Returns (model_ready, timestamp_df, prep_meta) - no target_df.
    """
    missing = set(numeric_features) - set(clean_df.columns)
    if missing:
        fail(f"Unlabeled input is missing expected numeric features: {sorted(missing)}")
    if PROTOCOL_COLUMN not in clean_df.columns:
        fail(f"Unlabeled input is missing the required '{PROTOCOL_COLUMN}' column.")
    if TIMESTAMP_COLUMN not in clean_df.columns:
        fail(f"Unlabeled input is missing the required '{TIMESTAMP_COLUMN}' column.")

    X_numeric = clean_df[numeric_features].replace([np.inf, -np.inf], np.nan).copy()
    infinity_counts = {
        col: int(np.isinf(clean_df[col]).sum()) for col in numeric_features if np.isinf(clean_df[col]).sum() > 0
    }

    protocol_values = clean_df[PROTOCOL_COLUMN]
    expected_protocol_categories = {c.replace("Protocol_", "") for c in onehot_protocol_columns}
    observed_protocol_categories = {str(v) for v in protocol_values.unique()}
    unexpected_protocols = sorted(observed_protocol_categories - expected_protocol_categories)

    dummies = pd.get_dummies(protocol_values.astype(str), prefix="Protocol").astype(int)
    # Reindex to the EXACT training-time one-hot columns, identical to the labeled path.
    dummies = dummies.reindex(columns=onehot_protocol_columns, fill_value=0)

    model_ready = pd.concat([X_numeric.reset_index(drop=True), dummies.reset_index(drop=True)], axis=1)
    model_ready.insert(0, "row_id", range(len(clean_df)))

    timestamp_df = pd.DataFrame({
        "row_id": model_ready["row_id"],
        "timestamp": clean_df[TIMESTAMP_COLUMN].reset_index(drop=True),
    })

    prep_meta = {
        "infinity_counts": infinity_counts,
        "unexpected_protocol_values": unexpected_protocols,
        "label_available": False,
        "label_note": "No Label column was read, required, or fabricated at this stage.",
    }
    return model_ready, timestamp_df, prep_meta


def build_states_unlabeled(model_ready: pd.DataFrame, timestamp_df: pd.DataFrame, feature_order: list) -> pd.DataFrame:
    """
    Label-free equivalent of prepare_external_dataset.build_states().

    Same sort order (timestamp, then row_id) and the same feature columns
    as the labeled path; no target_df is merged, so no label/target column
    appears in the output at all.
    """
    merged = model_ready.merge(timestamp_df, on="row_id")
    merged = merged.sort_values(by=["timestamp", "row_id"], ascending=[True, True], kind="mergesort").reset_index(drop=True)
    missing = set(feature_order) - set(merged.columns)
    if missing:
        fail(f"Unlabeled state table missing expected feature columns: {sorted(missing)}")
    return merged[["row_id", "timestamp"] + feature_order]


def build_windows_unlabeled(states: pd.DataFrame, feature_order: list) -> pd.DataFrame:
    """
    Label-free equivalent of prepare_external_dataset.build_windows().

    Produces the SAME window_id assignment, window_start/window_end,
    observation_count, segment_id, and per-feature SUM/MEAN aggregation as
    the labeled path (same build_aggregation_policy). Does NOT compute
    benign_count/attack_count/attack_ratio/binary_target/label/
    dominant_label - there is no label to derive them from, and none is
    fabricated; these columns are simply absent.
    """
    policy = build_aggregation_policy(feature_order)
    sum_cols = [f for f in feature_order if policy[f]["aggregation"] == "sum"]
    mean_cols = [f for f in feature_order if policy[f]["aggregation"] == "mean"]

    df = states.copy()
    df["window_start"] = df["timestamp"].dt.floor("1s")
    df = df.sort_values(by=["window_start", "row_id"], ascending=[True, True], kind="mergesort")

    grouped = df.groupby("window_start", sort=True)
    mean_part = grouped[mean_cols].mean()
    sum_part = grouped[sum_cols].sum(min_count=1)
    observation_count = grouped.size().rename("observation_count")

    windows = pd.concat([observation_count, mean_part, sum_part], axis=1).reset_index()
    if not windows["window_start"].is_unique:
        fail("Duplicate window_start after aggregation.")

    windows["window_end"] = windows["window_start"] + pd.Timedelta(seconds=1)
    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    windows.insert(0, "window_id", range(len(windows)))

    gap_mask = windows["window_start"].diff() > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()

    ordered = ["window_id", "window_start", "window_end", "observation_count", "segment_id"] + feature_order
    return windows[ordered]


def build_sequences_unlabeled(windows: pd.DataFrame, feature_order: list) -> tuple:
    """
    Label-free equivalent of prepare_external_dataset.build_sequences().

    Produces IDENTICAL X_sequences/next_window_features arrays and
    IDENTICAL sequence_id/input_start_window/input_end_window/
    target_window/timestamp metadata to the labeled path for the same
    window table. target_window_label and target_window_binary_target are
    explicitly None - genuinely unknown, never guessed or defaulted.
    """
    feature_values = windows[feature_order].to_numpy(dtype="float64")
    window_ids = windows["window_id"].to_numpy()
    segment_ids = windows["segment_id"].to_numpy()

    seq_len_total = SEQUENCE_LENGTH + 1
    X_list, next_list = [], []
    seq_rows = []
    sequence_id = 0
    for seg_id in np.unique(segment_ids):
        idx = np.where(segment_ids == seg_id)[0]
        if len(idx) < seq_len_total:
            continue
        for start in range(0, len(idx) - seq_len_total + 1):
            window_idx = idx[start: start + seq_len_total]
            input_idx = window_idx[:SEQUENCE_LENGTH]
            target_idx = window_idx[SEQUENCE_LENGTH]
            X_list.append(feature_values[input_idx])
            next_list.append(feature_values[target_idx])
            seq_rows.append({
                "sequence_id": sequence_id,
                "input_start_window": int(window_ids[input_idx[0]]),
                "input_end_window": int(window_ids[input_idx[-1]]),
                "target_window": int(window_ids[target_idx]),
                "input_start_timestamp": str(windows["window_start"].iloc[input_idx[0]]),
                "input_end_timestamp": str(windows["window_start"].iloc[input_idx[-1]]),
                "target_timestamp": str(windows["window_start"].iloc[target_idx]),
                "target_window_binary_target": None,
                "target_window_label": None,
            })
            sequence_id += 1

    if sequence_id > 0:
        X = np.stack(X_list, axis=0).astype("float32")
        nxt = np.stack(next_list, axis=0).astype("float32")
    else:
        X = np.empty((0, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT), dtype="float32")
        nxt = np.empty((0, EXPECTED_FEATURE_COUNT), dtype="float32")

    return X, nxt, pd.DataFrame(seq_rows)


def transform_unlabeled_windows(windows: pd.DataFrame, feature_order: list, fitted_pipeline) -> np.ndarray:
    """
    Apply the EXISTING frozen, train-fitted preprocessing pipeline via
    .transform() ONLY. Never calls .fit()/.fit_transform(). `fitted_pipeline`
    must already be fitted - load it via
    prepare_external_dataset.load_reference_artifacts(), which reads
    data/processed/splits/preprocessing_pipeline_train_fitted.joblib
    read-only.
    """
    try:
        check_is_fitted(fitted_pipeline)
    except NotFittedError:
        fail("Provided preprocessing pipeline is not fitted. Feature L1 never fits a pipeline itself.")
    df = windows[feature_order]
    return np.asarray(fitted_pipeline.transform(df), dtype="float64")


def prepare_unlabeled_state_pipeline(clean_df: pd.DataFrame) -> dict:
    """
    Convenience orchestrator chaining all four label-free steps plus the
    frozen-pipeline transform. Pure function: reads nothing from disk
    except (indirectly, via load_reference_artifacts()) the existing
    frozen artifacts, and writes nothing to disk anywhere.
    """
    feature_order, numeric_features, onehot_protocol_columns, fitted_pipeline = load_reference_artifacts()

    model_ready, timestamp_df, prep_meta = build_model_ready_table_unlabeled(clean_df, numeric_features, onehot_protocol_columns)
    states = build_states_unlabeled(model_ready, timestamp_df, feature_order)
    windows = build_windows_unlabeled(states, feature_order)
    windows_scaled = transform_unlabeled_windows(windows, feature_order, fitted_pipeline)
    X_sequences, next_window_features, seq_meta = build_sequences_unlabeled(windows, feature_order)

    return {
        "feature_order": feature_order,
        "model_ready": model_ready,
        "timestamp_df": timestamp_df,
        "prep_meta": prep_meta,
        "states": states,
        "windows": windows,
        "windows_scaled": windows_scaled,
        "X_sequences": X_sequences,
        "next_window_features": next_window_features,
        "seq_meta": seq_meta,
    }
