"""
Feature 16 - external dataset preparation for frozen-model generalization evaluation.

Takes one raw external CSE-CIC-IDS2018 capture-day CSV through the SAME
conceptual pipeline as Features 2/5/6 (clean -> per-observation state ->
1-second temporal windows -> 10-step sequences), then applies the EXISTING
Feature 7 train-fitted preprocessing pipeline via .transform() ONLY.

Reused, unmodified, from the existing codebase:
    - src/data/clean_dataset.py :: clean_dataset()  (Feature 2 cleaning -
      deterministic, no fitting, safe to reuse as-is on any CICFlowMeter
      CSV with the same 80-column schema)
    - src/data/build_temporal_windows.py :: build_aggregation_policy()
      (Feature 6's SUM/MEAN policy - depends only on feature names, not
      on labels, so it is identical for external data)
    - data/processed/splits/preprocessing_pipeline_train_fitted.joblib
      (Feature 7's scaler, applied via .transform() only - NEVER refit)

NOT reused as-is: Feature 4's prepare_features.py and Feature 5/6's
label-handling hard-code the binary Benign/Infilteration encoding and
would raise on the external multi-class labels (FTP-BruteForce,
SSH-Bruteforce, DDOS attack-HOIC, DDOS attack-LOIC-UDP). This script
reimplements the same STRUCTURAL logic (feature selection, Infinity
handling, Protocol one-hot, temporal windowing, sequence construction)
with GENERALIZED label handling:
    - the original label string is always preserved exactly
    - a binary_target (0=Benign, 1=non-Benign) is derived generically
    - a training_compatible_target (Feature 7's exact 0/1 encoding) is
      only populated where the external label is literally "Benign" or
      "Infilteration" (NaN/None otherwise) - see the module docstring in
      evaluate_frozen_generalization.py for how these two views are used.

No preprocessing is fit. No model is trained. The current development
dataset, Feature 1-15 artifacts, and the fitted pipeline are never
modified - this script only ever calls fitted_pipeline.transform().
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clean_dataset import clean_dataset  # noqa: E402 - Feature 2, reused unmodified
from build_temporal_windows import build_aggregation_policy  # noqa: E402 - Feature 6, reused unmodified

FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
MODEL_FEATURE_LIST_PATH = Path("results/model_feature_list.json")
FITTED_PIPELINE_PATH = Path("data/processed/splits/preprocessing_pipeline_train_fitted.joblib")

TIMESTAMP_COLUMN = "Timestamp"
LABEL_COLUMN = "Label"
PROTOCOL_COLUMN = "Protocol"
EXPECTED_FEATURE_COUNT = 68
SEQUENCE_LENGTH = 10
K_MAX = 5
WINDOW_STEP = pd.Timedelta(seconds=1)
TRAINING_COMPATIBLE_ENCODING = {"Benign": 0, "Infilteration": 1}


def fail(message: str):
    raise SystemExit(f"FEATURE 16 PREPARATION FAILURE: {message}")


def load_reference_artifacts():
    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    with open(MODEL_FEATURE_LIST_PATH, encoding="utf-8") as f:
        model_feature_list = json.load(f)
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")
    selected_features = model_feature_list["selected_features"]  # 66, includes "Protocol"
    numeric_features = [f for f in selected_features if f != PROTOCOL_COLUMN]  # 65
    onehot_protocol_columns = [c for c in feature_order if c.startswith("Protocol_")]
    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)
    return feature_order, numeric_features, onehot_protocol_columns, fitted_pipeline


def build_model_ready_table(clean_df: pd.DataFrame, numeric_features: list, onehot_protocol_columns: list) -> tuple:
    """Structural prep equivalent to Feature 4, generalized for multi-class labels."""
    missing = set(numeric_features) - set(clean_df.columns)
    if missing:
        fail(f"Cleaned external data is missing expected numeric features: {sorted(missing)}")

    X_numeric = clean_df[numeric_features].replace([np.inf, -np.inf], np.nan).copy()
    infinity_counts = {
        col: int(np.isinf(clean_df[col]).sum()) for col in numeric_features if np.isinf(clean_df[col]).sum() > 0
    }

    protocol_values = clean_df[PROTOCOL_COLUMN]
    expected_protocol_categories = {c.replace("Protocol_", "") for c in onehot_protocol_columns}
    observed_protocol_categories = {str(v) for v in protocol_values.unique()}
    unexpected_protocols = sorted(observed_protocol_categories - expected_protocol_categories)

    dummies = pd.get_dummies(protocol_values.astype(str), prefix="Protocol").astype(int)
    # Reindex to the EXACT training-time one-hot columns; any unseen protocol value gets all-zero
    # columns (reported via unexpected_protocols) rather than silently expanding the schema.
    dummies = dummies.reindex(columns=onehot_protocol_columns, fill_value=0)

    model_ready = pd.concat([X_numeric.reset_index(drop=True), dummies.reset_index(drop=True)], axis=1)
    model_ready.insert(0, "row_id", range(len(clean_df)))

    original_label = clean_df[LABEL_COLUMN].reset_index(drop=True)
    binary_target = (original_label != "Benign").astype(int)
    training_compatible_target = original_label.map(TRAINING_COMPATIBLE_ENCODING)  # NaN where not Benign/Infilteration

    target_df = pd.DataFrame({
        "row_id": model_ready["row_id"],
        "label": original_label,
        "binary_target": binary_target,
        "training_compatible_target": training_compatible_target,
    })
    timestamp_df = pd.DataFrame({"row_id": model_ready["row_id"], "timestamp": clean_df[TIMESTAMP_COLUMN].reset_index(drop=True)})

    prep_meta = {"infinity_counts": infinity_counts, "unexpected_protocol_values": unexpected_protocols}
    return model_ready, target_df, timestamp_df, prep_meta


def build_states(model_ready: pd.DataFrame, target_df: pd.DataFrame, timestamp_df: pd.DataFrame, feature_order: list) -> pd.DataFrame:
    """Per-observation state S(t), Feature 5 equivalent."""
    merged = model_ready.merge(target_df, on="row_id").merge(timestamp_df, on="row_id")
    merged = merged.sort_values(by=["timestamp", "row_id"], ascending=[True, True], kind="mergesort").reset_index(drop=True)
    feature_cols = [c for c in feature_order]
    missing = set(feature_cols) - set(merged.columns)
    if missing:
        fail(f"State table missing expected feature columns: {sorted(missing)}")
    return merged[["row_id", "timestamp"] + feature_cols + ["binary_target", "training_compatible_target", "label"]]


def build_windows(states: pd.DataFrame, feature_order: list) -> pd.DataFrame:
    """1-second temporal windows, Feature 6 equivalent, generalized label aggregation."""
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

    df["_is_benign"] = (df["label"] == "Benign").astype(int)
    df["_is_attack"] = (df["label"] != "Benign").astype(int)
    benign_count = grouped["_is_benign"].sum().rename("benign_count")
    attack_count = grouped["_is_attack"].sum().rename("attack_count")

    # dominant non-benign label per window (most frequent attack label in that window, if any)
    def dominant_label(s):
        non_benign = s[s != "Benign"]
        return non_benign.mode().iloc[0] if len(non_benign) > 0 else "Benign"
    dominant = grouped["label"].apply(dominant_label).rename("dominant_label")

    windows = pd.concat([observation_count, benign_count, attack_count, mean_part, sum_part, dominant], axis=1).reset_index()
    if not windows["window_start"].is_unique:
        fail("Duplicate window_start after aggregation.")

    windows["window_end"] = windows["window_start"] + pd.Timedelta(seconds=1)
    windows["attack_ratio"] = windows["attack_count"] / windows["observation_count"]
    windows["binary_target"] = (windows["attack_count"] > 0).astype(int)
    windows["label"] = np.where(windows["binary_target"] == 1, windows["dominant_label"], "Benign")

    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    windows.insert(0, "window_id", range(len(windows)))

    gap_mask = windows["window_start"].diff() > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()

    ordered = (
        ["window_id", "window_start", "window_end", "observation_count", "benign_count", "attack_count",
         "attack_ratio", "binary_target", "label", "dominant_label", "segment_id"]
        + feature_order
    )
    return windows[ordered]


def build_sequences(windows: pd.DataFrame, feature_order: list) -> tuple:
    """10-history sequences with up to K_MAX=5 future targets available, gap/segment-safe (Feature 6/12 equivalent)."""
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
                "target_window_binary_target": int(windows["binary_target"].iloc[target_idx]),
                "target_window_label": str(windows["label"].iloc[target_idx]),
            })
            sequence_id += 1

    if sequence_id > 0:
        X = np.stack(X_list, axis=0).astype("float32")
        nxt = np.stack(next_list, axis=0).astype("float32")
    else:
        X = np.empty((0, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT), dtype="float32")
        nxt = np.empty((0, EXPECTED_FEATURE_COUNT), dtype="float32")

    return X, nxt, pd.DataFrame(seq_rows)


def main():
    parser = argparse.ArgumentParser(description="Feature 16: prepare one external capture day for frozen-model evaluation.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--day-label", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[{args.day_label}] Cleaning raw CSV via Feature 2's clean_dataset() (reused, unmodified) ...")
    clean_df, clean_report = clean_dataset(input_path)
    print(f"[{args.day_label}]   raw_rows={clean_report['raw_data']['raw_row_count']} "
          f"embedded_headers_removed={clean_report['embedded_headers']['rows_removed']} "
          f"exact_duplicates_removed={clean_report['duplicates']['removal_decision']}")
    print(f"[{args.day_label}]   final cleaned rows: {clean_report['final_dataset']['final_row_count']}")

    feature_order, numeric_features, onehot_protocol_columns, fitted_pipeline = load_reference_artifacts()

    print(f"[{args.day_label}] Building model-ready table (66 features + generalized label handling) ...")
    model_ready, target_df, timestamp_df, prep_meta = build_model_ready_table(clean_df, numeric_features, onehot_protocol_columns)
    if prep_meta["unexpected_protocol_values"]:
        print(f"[{args.day_label}]   WARNING: unexpected Protocol values not seen in training: {prep_meta['unexpected_protocol_values']}")

    print(f"[{args.day_label}] Building per-observation states ...")
    states = build_states(model_ready, target_df, timestamp_df, feature_order)

    print(f"[{args.day_label}] Building 1-second temporal windows ...")
    windows = build_windows(states, feature_order)
    n_gaps = int((windows["segment_id"].diff().fillna(0) > 0).sum())
    n_segments = int(windows["segment_id"].nunique())
    print(f"[{args.day_label}]   {len(windows)} windows, {n_segments} continuous segments, {n_gaps} gaps.")

    print(f"[{args.day_label}] Building 10-step sequences (gap-safe) ...")
    X_raw, next_raw, seq_meta = build_sequences(windows, feature_order)
    print(f"[{args.day_label}]   {len(seq_meta)} valid sequences constructed.")

    if len(seq_meta) > 0:
        print(f"[{args.day_label}] Applying EXISTING train-fitted preprocessing pipeline (.transform() only, never refit) ...")
        n, t, f_ = X_raw.shape
        flat_df = pd.DataFrame(X_raw.reshape(n * t, f_), columns=feature_order)
        X_scaled = np.asarray(fitted_pipeline.transform(flat_df), dtype="float32").reshape(n, t, f_)
        next_scaled = np.asarray(fitted_pipeline.transform(pd.DataFrame(next_raw, columns=feature_order)), dtype="float32")
    else:
        X_scaled = np.empty((0, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT), dtype="float32")
        next_scaled = np.empty((0, EXPECTED_FEATURE_COUNT), dtype="float32")

    windows.to_csv(output_dir / "temporal_windows.csv", index=False)
    seq_meta.to_csv(output_dir / "sequence_metadata.csv", index=False)
    np.save(output_dir / "X_sequences_raw.npy", X_raw)
    np.save(output_dir / "X_sequences_scaled.npy", X_scaled)
    np.save(output_dir / "next_window_features_raw.npy", next_raw)
    np.save(output_dir / "next_window_features_scaled.npy", next_scaled)

    label_dist_raw = {str(k): int(v) for k, v in clean_df[LABEL_COLUMN].value_counts(dropna=False).items()}
    label_dist_windows = {str(k): int(v) for k, v in windows["label"].value_counts(dropna=False).items()}

    prep_report = {
        "day_label": args.day_label,
        "input_file": str(input_path),
        "cleaning_report_summary": {
            "raw_row_count": clean_report["raw_data"]["raw_row_count"],
            "embedded_header_rows_removed": clean_report["embedded_headers"]["rows_removed"],
            "exact_duplicate_rows_removed": clean_report["duplicates"]["duplicate_count_after_header_removal"],
            "final_row_count": clean_report["final_dataset"]["final_row_count"],
            "label_distribution_raw_rows": label_dist_raw,
            "timestamp_min": clean_report["validation"]["final_min_timestamp"],
            "timestamp_max": clean_report["validation"]["final_max_timestamp"],
        },
        "unexpected_protocol_values": prep_meta["unexpected_protocol_values"],
        "infinity_counts_pre_conversion": prep_meta["infinity_counts"],
        "window_summary": {
            "num_windows": len(windows),
            "num_continuous_segments": n_segments,
            "num_gaps": n_gaps,
            "label_distribution_windows": label_dist_windows,
            "observation_count_stats": {
                "min": int(windows["observation_count"].min()), "max": int(windows["observation_count"].max()),
                "mean": round(float(windows["observation_count"].mean()), 3),
            },
        },
        "sequence_summary": {
            "num_valid_sequences": len(seq_meta),
            "sequence_length": SEQUENCE_LENGTH,
            "feature_count": EXPECTED_FEATURE_COUNT,
        },
        "preprocessing": {
            "pipeline_path": str(FITTED_PIPELINE_PATH),
            "fit_source": "Feature 7 TRAIN partition of the ORIGINAL Thursday-01-03-2018 dataset - NOT refit on this external data.",
        },
    }
    (output_dir / "prep_report.json").write_text(json.dumps(prep_report, indent=2, default=str), encoding="utf-8")
    print(f"[{args.day_label}] Wrote outputs to {output_dir}")

    return prep_report


if __name__ == "__main__":
    main()
