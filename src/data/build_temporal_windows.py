"""
Temporal windows and sequence construction for CyberChess.

Converts Feature 5's per-observation states (data/processed/states/states.csv)
into fixed 1-second temporal network windows, then into fixed-length
(10 -> 1) sequences for later World Model work.

This script performs STRUCTURAL temporal aggregation only:
    - no imputer/scaler is fitted
    - no global normalization statistics are calculated
    - no model is trained or evaluated
    - future windows are never used to modify current windows (aggregation
      is per-window only; sequence construction only reads windows that
      already exist, it never back-fills or interpolates)

Design choices made explicit and documented (not silently assumed):
    - window size: 1 second, exact, not tuned (see WINDOW_SIZE_SECONDS)
    - per-feature aggregation policy: SUM vs MEAN, justified per feature
      (see AGGREGATION_POLICY / build_aggregation_policy())
    - sequence length: 10 input windows + 1 target window (see
      SEQUENCE_LENGTH)
    - sequence stride: 1 (overlapping sliding window), chosen to maximize
      the number of training examples from a single day of traffic;
      documented here since the spec did not fix a stride

Fails loudly (no silent repair) on: unexpected feature count/names,
timestamp parse failure, missing required columns, duplicate window_start
after aggregation, or an aggregation policy that cannot be determined.

Usage:
    python src/data/build_temporal_windows.py
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

STATES_PATH = Path("data/processed/states/states.csv")
STATE_SCHEMA_PATH = Path("results/state_schema.json")

WINDOW_SIZE_SECONDS = 1
SEQUENCE_LENGTH = 10  # input windows
SEQUENCE_STRIDE = 1  # overlapping sliding window over each continuous segment
EXPECTED_FEATURE_COUNT = 68

TIMESTAMP_FORMAT_CANDIDATES = ["%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"]


def fail(message: str):
    raise SystemExit(f"FEATURE 6 VALIDATION FAILURE: {message}")


# ----------------------------------------------------------------------
# Aggregation policy
# ----------------------------------------------------------------------
def build_aggregation_policy(feature_order: list) -> dict:
    """
    Explicit per-feature aggregation policy for the 68 Feature-4/5 features.

    Categories, per the Feature 6 specification:
        COUNT-LIKE / EVENT-LIKE (packet/byte/flag counts)      -> SUM
        RATE features (X/s)                                    -> MEAN
        DURATION features                                      -> MEAN
        SIZE / packet-length / segment-size features            -> MEAN
        DISTRIBUTION / statistical features (IAT, active/idle)  -> MEAN
        BINARY / one-hot Protocol features                      -> MEAN (proportion)

    Features that do not fall cleanly into a listed example are resolved
    here with an explicit, documented, non-guessed decision (flagged with
    "needs_documentation": True).
    """
    # Explicit SUM set: cumulative packet/byte/flag counts observed in the
    # window. Summing these across the flows that occurred within the same
    # 1-second window gives the total volume/event count for that window,
    # which is the natural aggregate network-behaviour quantity.
    sum_features = {
        "ACK Flag Cnt": "Flag count - number of ACK-flagged packets; summing gives total ACK activity in the window.",
        "ECE Flag Cnt": "Flag count.",
        "Fwd PSH Flags": "Flag count (forward direction).",
        "PSH Flag Cnt": "Flag count.",
        "RST Flag Cnt": "Flag count.",
        "SYN Flag Cnt": "Flag count.",
        "URG Flag Cnt": "Flag count.",
        "Fwd Act Data Pkts": "Packet count (forward data packets).",
        "Subflow Fwd Pkts": "Packet count.",
        "Subflow Bwd Pkts": "Packet count.",
        "Subflow Fwd Byts": "Byte count.",
        "Subflow Bwd Byts": "Byte count.",
        "Tot Fwd Pkts": "Packet count.",
        "Tot Bwd Pkts": "Packet count.",
        "TotLen Fwd Pkts": "Byte count (total length of forward packets).",
        "TotLen Bwd Pkts": "Byte count (total length of backward packets).",
        "Fwd Header Len": (
            "NEEDS_DOCUMENTATION: not explicitly listed in the spec's SUM examples, but "
            "represents cumulative header bytes for a flow (a byte-volume quantity, same "
            "family as TotLen Fwd/Bwd Pkts), so it is summed to represent total header "
            "byte volume observed across all flows in the window."
        ),
        "Bwd Header Len": (
            "NEEDS_DOCUMENTATION: same reasoning as Fwd Header Len - cumulative header "
            "byte volume, summed for total window volume."
        ),
    }

    # Explicit MEAN set: rates, durations, size/length statistics,
    # distribution statistics (IAT, active/idle), and one-hot proportions.
    mean_features = {
        "Flow Byts/s": "Rate feature (explicit spec example).",
        "Flow Pkts/s": "Rate feature (explicit spec example).",
        "Fwd Pkts/s": "Rate feature (explicit spec example).",
        "Bwd Pkts/s": "Rate feature (explicit spec example).",
        "Flow Duration": "Duration feature (explicit spec example).",
        "Pkt Len Mean": "Packet-length statistic (explicit spec example).",
        "Pkt Len Std": "Packet-length statistic (explicit spec example).",
        "Pkt Len Var": "Packet-length statistic (explicit spec example: Packet Length Variance).",
        "Pkt Len Max": "Packet-length statistic; same family as Pkt Len Mean/Std, extended consistently.",
        "Pkt Len Min": "Packet-length statistic; same family as Pkt Len Mean/Std, extended consistently.",
        "Pkt Size Avg": "Average packet size (explicit spec example: Average Packet Size).",
        "Fwd Seg Size Avg": "Segment-size statistic (explicit spec example: Avg Fwd Segment Size).",
        "Bwd Seg Size Avg": "Segment-size statistic (explicit spec example: Avg Bwd Segment Size).",
        "Fwd Pkt Len Max": "Packet-length statistic, same family as Pkt Len Max/Min/Mean/Std.",
        "Fwd Pkt Len Min": "Packet-length statistic, same family.",
        "Fwd Pkt Len Mean": "Packet-length statistic, same family.",
        "Fwd Pkt Len Std": "Packet-length statistic, same family.",
        "Bwd Pkt Len Max": "Packet-length statistic, same family.",
        "Bwd Pkt Len Min": "Packet-length statistic, same family.",
        "Bwd Pkt Len Mean": "Packet-length statistic, same family.",
        "Bwd Pkt Len Std": "Packet-length statistic, same family.",
        "Flow IAT Mean": "Distribution/statistical feature (explicit spec example: IAT Mean).",
        "Flow IAT Std": "Distribution/statistical feature (explicit spec example: IAT Std).",
        "Flow IAT Max": "Distribution/statistical feature (explicit spec example: IAT Max).",
        "Flow IAT Min": "Distribution/statistical feature (explicit spec example: IAT Min).",
        "Fwd IAT Mean": "Distribution/statistical feature, same family (forward direction).",
        "Fwd IAT Std": "Distribution/statistical feature, same family.",
        "Fwd IAT Max": "Distribution/statistical feature, same family.",
        "Fwd IAT Min": "Distribution/statistical feature, same family.",
        "Bwd IAT Mean": "Distribution/statistical feature, same family (backward direction).",
        "Bwd IAT Std": "Distribution/statistical feature, same family.",
        "Bwd IAT Max": "Distribution/statistical feature, same family.",
        "Bwd IAT Min": "Distribution/statistical feature, same family.",
        "Active Mean": "Active/idle statistic (explicit spec example).",
        "Active Std": "Active/idle statistic (explicit spec example).",
        "Active Max": "Active/idle statistic (explicit spec example).",
        "Active Min": "Active/idle statistic (explicit spec example).",
        "Idle Mean": "Active/idle statistic (explicit spec example).",
        "Idle Std": "Active/idle statistic (explicit spec example).",
        "Idle Max": "Active/idle statistic (explicit spec example).",
        "Idle Min": "Active/idle statistic (explicit spec example).",
        "Protocol_0": "One-hot Protocol indicator; mean = proportion of window's observations using this protocol (explicit spec example).",
        "Protocol_6": "One-hot Protocol indicator; mean = proportion (explicit spec example).",
        "Protocol_17": "One-hot Protocol indicator; mean = proportion (explicit spec example).",
        "Fwd IAT Tot": (
            "NEEDS_DOCUMENTATION: not explicitly listed. 'IAT Tot' is the total inter-arrival "
            "time accumulated within a single flow (a per-flow duration-like total, closely "
            "related to that flow's own duration), not a literal event/packet count. Summing "
            "durations across unrelated concurrent flows has no clean physical meaning, so it "
            "is treated like Flow Duration and averaged (MEAN) across the window's flows."
        ),
        "Bwd IAT Tot": (
            "NEEDS_DOCUMENTATION: same reasoning as Fwd IAT Tot."
        ),
        "Down/Up Ratio": (
            "NEEDS_DOCUMENTATION: a per-flow ratio (down/up packet ratio), not a count. "
            "Ratios are distribution-like descriptive statistics, so MEAN (average ratio "
            "across the window's flows) is the defensible choice, consistent with how other "
            "per-flow ratios/statistics in this feature set are handled."
        ),
        "Fwd Seg Size Min": (
            "NEEDS_DOCUMENTATION: not explicitly listed, but is a segment-size statistic in "
            "the same family as Fwd/Bwd Seg Size Avg (explicit MEAN examples), so extended "
            "consistently as MEAN."
        ),
        "Init Fwd Win Byts": (
            "NEEDS_DOCUMENTATION: the initial TCP window size negotiated for a flow - a "
            "per-connection size/characteristic value, not a cumulative volume. Treated like "
            "other size statistics (MEAN) rather than summed, since summing window sizes "
            "across unrelated flows has no meaningful 'total' interpretation."
        ),
        "Init Bwd Win Byts": (
            "NEEDS_DOCUMENTATION: same reasoning as Init Fwd Win Byts."
        ),
    }

    policy = {}
    for feat in feature_order:
        if feat in sum_features:
            policy[feat] = {
                "aggregation": "sum",
                "category": "count_or_event_like",
                "reason": sum_features[feat],
                "needs_documentation": "NEEDS_DOCUMENTATION" in sum_features[feat],
            }
        elif feat in mean_features:
            policy[feat] = {
                "aggregation": "mean",
                "category": "rate_duration_size_or_distribution",
                "reason": mean_features[feat],
                "needs_documentation": "NEEDS_DOCUMENTATION" in mean_features[feat],
            }
        else:
            fail(f"No aggregation policy could be determined for feature '{feat}'. Stopping rather than guessing.")

    if set(policy.keys()) != set(feature_order):
        fail("Aggregation policy does not cover exactly the 68 expected features.")

    return policy


def parse_timestamp_explicit(series: pd.Series, format_candidates: list) -> tuple:
    for fmt in format_candidates:
        parsed = pd.to_datetime(series, format=fmt, errors="coerce")
        if int(parsed.isna().sum()) == 0:
            return parsed, fmt
    fail(f"Timestamp column could not be parsed with any candidate format {format_candidates}.")


def main():
    parser = argparse.ArgumentParser(description="Build 1-second temporal windows and sequences from Feature 5 states.")
    parser.add_argument("--states", default=str(STATES_PATH), help="Path to Feature 5 states.csv.")
    parser.add_argument("--schema", default=str(STATE_SCHEMA_PATH), help="Path to Feature 5 state_schema.json.")
    parser.add_argument("--output-dir", default="data/processed/temporal", help="Directory for window outputs.")
    parser.add_argument("--sequence-dir", default="data/processed/temporal/sequences", help="Directory for sequence outputs.")
    parser.add_argument("--report-dir", default="results", help="Directory for reports.")
    args = parser.parse_args()

    states_path = Path(args.states)
    schema_path = Path(args.schema)
    output_dir = Path(args.output_dir)
    sequence_dir = Path(args.sequence_dir)
    report_dir = Path(args.report_dir)

    if not states_path.exists():
        fail(f"Required input not found: {states_path}")
    if not schema_path.exists():
        fail(f"Required input not found: {schema_path}")

    print(f"Loading state schema from {schema_path} ...")
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    feature_order = schema["feature_column_names"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"state_schema.json reports {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print(f"Loading states from {states_path} ...")
    df = pd.read_csv(states_path)

    required_cols = {"row_id", "timestamp", "target", "label"} | set(feature_order)
    missing_cols = required_cols - set(df.columns)
    if missing_cols:
        fail(f"states.csv is missing required columns: {sorted(missing_cols)}")

    actual_feature_cols = [c for c in df.columns if c not in ("row_id", "timestamp", "target", "label")]
    if len(actual_feature_cols) != EXPECTED_FEATURE_COUNT or set(actual_feature_cols) != set(feature_order):
        fail(
            f"states.csv feature columns do not match state_schema.json exactly. "
            f"Expected {len(feature_order)}, found {len(actual_feature_cols)}."
        )

    input_row_count = len(df)
    input_unique_timestamps = df["timestamp"].nunique()

    print("Parsing timestamp explicitly ...")
    parsed_ts, ts_format_used = parse_timestamp_explicit(df["timestamp"], TIMESTAMP_FORMAT_CANDIDATES)
    df["timestamp"] = parsed_ts
    print(f"  Timestamp format used: {ts_format_used}")

    # --- window_start = timestamp floored to 1 second ---
    df["window_start"] = df["timestamp"].dt.floor(f"{WINDOW_SIZE_SECONDS}s")
    n_floor_changed = int((df["window_start"] != df["timestamp"]).sum())
    if n_floor_changed > 0:
        print(
            f"NOTE: {n_floor_changed} timestamps had sub-second precision collapsed by flooring "
            "to 1 second (unexpected for this dataset - reported, not hidden)."
        )

    # --- sort: window_start ascending, row_id ascending. No shuffling. ---
    df = df.sort_values(by=["window_start", "row_id"], ascending=[True, True], kind="mergesort").reset_index(drop=True)

    # --- aggregation policy ---
    print("Building aggregation policy ...")
    policy = build_aggregation_policy(feature_order)
    sum_cols = [f for f in feature_order if policy[f]["aggregation"] == "sum"]
    mean_cols = [f for f in feature_order if policy[f]["aggregation"] == "mean"]
    print(f"  {len(sum_cols)} SUM features, {len(mean_cols)} MEAN features.")

    # --- target indicators for vectorized window-level counting ---
    df["_is_benign"] = (df["label"] == "Benign").astype(int)
    df["_is_infiltration"] = (df["label"] == "Infilteration").astype(int)
    unexpected_labels = set(df["label"].unique()) - {"Benign", "Infilteration"}
    if unexpected_labels:
        fail(f"Unexpected label values found: {unexpected_labels}")

    # --- window-level aggregation (vectorized, NaN-safe) ---
    print("Aggregating into 1-second windows ...")
    grouped = df.groupby("window_start", sort=True)

    mean_part = grouped[mean_cols].mean()  # pandas mean(): skips NaN, all-NaN group -> NaN
    sum_part = grouped[sum_cols].sum(min_count=1)  # min_count=1: all-NaN group -> NaN, not 0

    observation_count = grouped.size().rename("observation_count")
    benign_count = grouped["_is_benign"].sum().rename("benign_count")
    infiltration_count = grouped["_is_infiltration"].sum().rename("infiltration_count")

    windows = pd.concat([observation_count, benign_count, infiltration_count, mean_part, sum_part], axis=1)
    windows = windows.reset_index().rename(columns={"window_start": "window_start"})

    if not windows["window_start"].is_unique:
        fail("Duplicate window_start values remained after aggregation - grouping did not fully collapse observations.")

    windows["window_end"] = windows["window_start"] + pd.Timedelta(seconds=WINDOW_SIZE_SECONDS)
    windows["infiltration_ratio"] = windows["infiltration_count"] / windows["observation_count"]
    windows["target"] = (windows["infiltration_count"] > 0).astype(int)
    windows["label"] = windows["target"].map({0: "Benign", 1: "Infilteration"})

    windows = windows.sort_values(by="window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    windows.insert(0, "window_id", range(len(windows)))

    ordered_cols = (
        ["window_id", "window_start", "window_end", "observation_count", "benign_count",
         "infiltration_count", "infiltration_ratio", "target", "label"]
        + feature_order
    )
    windows = windows[ordered_cols]

    n_windows = len(windows)
    print(f"  {n_windows} temporal windows created from {input_row_count} observations.")

    # --- gap detection ---
    print("Detecting temporal gaps ...")
    diffs = windows["window_start"].diff()
    expected_step = pd.Timedelta(seconds=WINDOW_SIZE_SECONDS)
    gap_mask = diffs > expected_step
    n_gaps = int(gap_mask.sum())
    largest_gap = diffs.max()
    windows["segment_id"] = gap_mask.cumsum()
    n_segments = int(windows["segment_id"].nunique())
    print(f"  {n_gaps} gaps found, largest gap = {largest_gap}, {n_segments} continuous segments.")

    # --- missing / infinity in aggregated features ---
    feature_matrix = windows[feature_order]
    missing_in_windows = {c: int(feature_matrix[c].isna().sum()) for c in feature_order if feature_matrix[c].isna().sum() > 0}
    inf_in_windows = {c: int(np.isinf(feature_matrix[c]).sum()) for c in feature_order if np.isinf(feature_matrix[c]).sum() > 0}

    # --- write window-level outputs ---
    output_dir.mkdir(parents=True, exist_ok=True)
    windows_out_path = output_dir / "temporal_windows.csv"
    windows_to_save = windows.drop(columns=["segment_id"])
    windows_to_save.to_csv(windows_out_path, index=False)
    print(f"Wrote {windows_out_path}")

    window_metadata = {
        "window_size_seconds": WINDOW_SIZE_SECONDS,
        "window_start_convention": "timestamp floored to the start of its 1-second interval (dt.floor('1s'))",
        "window_end_convention": "window_start + 1 second (half-open interval [window_start, window_end))",
        "sort_order": ["window_start ascending"],
        "row_count": n_windows,
        "columns": list(windows_to_save.columns),
        "dtypes": {c: str(windows_to_save[c].dtype) for c in windows_to_save.columns},
        "target_definition": (
            "target=1 (label='Infilteration') if infiltration_count > 0 in the window, else "
            "target=0 (label='Benign'). This is an 'attack presence in window' definition: it "
            "means at least one Infilteration flow occurred in that window, NOT that every "
            "flow in the window is malicious."
        ),
        "source_files": {"states_csv": str(states_path), "state_schema_json": str(schema_path)},
    }
    metadata_path = output_dir / "temporal_window_metadata.json"
    metadata_path.write_text(json.dumps(window_metadata, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metadata_path}")

    policy_summary = {
        "window_size_seconds": WINDOW_SIZE_SECONDS,
        "policy_by_feature": policy,
        "sum_feature_count": len(sum_cols),
        "mean_feature_count": len(mean_cols),
        "sum_features": sum_cols,
        "mean_features": mean_cols,
        "features_needing_documented_decision": [f for f in feature_order if policy[f]["needs_documentation"]],
        "nan_handling": (
            "SUM columns use groupby.sum(min_count=1): NaN values are ignored when summing, "
            "and the result is NaN (not 0) only if every value in the window is NaN. MEAN "
            "columns use groupby.mean(), which skips NaN and returns NaN only if every value "
            "in the window is NaN. No missing values were filled; no global statistics were "
            "computed; no future-window information was used."
        ),
    }
    policy_path = output_dir / "temporal_aggregation_policy.json"
    policy_path.write_text(json.dumps(policy_summary, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {policy_path}")

    # --- results/temporal_feature_order.json ---
    report_dir.mkdir(parents=True, exist_ok=True)
    feature_order_payload = {
        "feature_count": len(feature_order),
        "feature_order": feature_order,
        "source": "results/state_schema.json (feature_column_names), originally from Feature 4's final_feature_matrix_columns.",
        "note": "This exact order is used for every row of X_sequences and next_window_features.",
    }
    feature_order_path = report_dir / "temporal_feature_order.json"
    feature_order_path.write_text(json.dumps(feature_order_payload, indent=2), encoding="utf-8")
    print(f"Wrote {feature_order_path}")

    # --- sequence construction ---
    print("Constructing fixed-length sequences ...")
    sequence_dir.mkdir(parents=True, exist_ok=True)

    X_list = []
    next_list = []
    seq_rows = []

    feature_values = windows[feature_order].to_numpy(dtype="float64")
    window_starts = windows["window_start"].to_numpy()
    window_ids = windows["window_id"].to_numpy()
    targets = windows["target"].to_numpy()
    labels = windows["label"].to_numpy()
    segment_ids = windows["segment_id"].to_numpy()

    seq_len_total = SEQUENCE_LENGTH + 1
    sequence_id = 0
    for seg_id in np.unique(segment_ids):
        idx = np.where(segment_ids == seg_id)[0]
        seg_len = len(idx)
        if seg_len < seq_len_total:
            continue
        for start in range(0, seg_len - seq_len_total + 1, SEQUENCE_STRIDE):
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
                "input_start_timestamp": str(window_starts[input_idx[0]]),
                "input_end_timestamp": str(window_starts[input_idx[-1]]),
                "target_timestamp": str(window_starts[target_idx]),
                "target_window_target": int(targets[target_idx]),
                "target_window_label": str(labels[target_idx]),
            })
            sequence_id += 1

    n_sequences = len(seq_rows)
    if n_sequences > 0:
        X_sequences = np.stack(X_list, axis=0).astype("float64")
        next_window_features = np.stack(next_list, axis=0).astype("float64")
    else:
        X_sequences = np.empty((0, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT), dtype="float64")
        next_window_features = np.empty((0, EXPECTED_FEATURE_COUNT), dtype="float64")

    if X_sequences.shape[1] != SEQUENCE_LENGTH or X_sequences.shape[2] != EXPECTED_FEATURE_COUNT:
        fail(f"X_sequences has unexpected shape {X_sequences.shape}, expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")
    if next_window_features.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"next_window_features has unexpected shape {next_window_features.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")

    x_path = sequence_dir / "X_sequences.npy"
    next_path = sequence_dir / "next_window_features.npy"
    np.save(x_path, X_sequences)
    np.save(next_path, next_window_features)
    print(f"Wrote {x_path} shape={X_sequences.shape}")
    print(f"Wrote {next_path} shape={next_window_features.shape}")

    seq_meta_df = pd.DataFrame(seq_rows)
    seq_meta_csv_path = sequence_dir / "sequence_metadata.csv"
    seq_meta_json_path = sequence_dir / "sequence_metadata.json"
    seq_meta_df.to_csv(seq_meta_csv_path, index=False)
    seq_meta_json_payload = {
        "sequence_length_input_windows": SEQUENCE_LENGTH,
        "sequence_stride": SEQUENCE_STRIDE,
        "stride_note": (
            "Stride was not fixed by the Feature 6 spec; stride=1 (overlapping sliding window) "
            "was chosen to maximize the number of training sequences from this single-day "
            "capture. This is a documented design choice, evaluable later."
        ),
        "num_sequences": n_sequences,
        "num_continuous_segments": n_segments,
        "num_temporal_gaps": n_gaps,
        "largest_temporal_gap": str(largest_gap),
        "X_sequences_shape": list(X_sequences.shape),
        "next_window_features_shape": list(next_window_features.shape),
        "feature_order_reference": str(feature_order_path),
        "sequences": seq_rows,
    }
    seq_meta_json_path.write_text(json.dumps(seq_meta_json_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {seq_meta_csv_path}, {seq_meta_json_path}")

    # --- sanity check prints ---
    print("\n" + "=" * 70)
    print("SANITY CHECK")
    print("=" * 70)
    print("First window:")
    print(windows_to_save.iloc[0][["window_id", "window_start", "window_end", "observation_count", "target", "label", "infiltration_ratio"]])
    print("\nLast window:")
    print(windows_to_save.iloc[-1][["window_id", "window_start", "window_end", "observation_count", "target", "label", "infiltration_ratio"]])

    if n_sequences > 0:
        print("\nFirst sequence:")
        print(seq_meta_df.iloc[0])
        print("\nLast sequence:")
        print(seq_meta_df.iloc[-1])

        print("\nExample sequences:")
        example_idx = [0, n_sequences // 2, n_sequences - 1] if n_sequences >= 3 else list(range(n_sequences))
        for i in example_idx:
            row = seq_meta_df.iloc[i]
            print(
                f"  sequence_id={row['sequence_id']} "
                f"input=[{row['input_start_timestamp']} .. {row['input_end_timestamp']}] "
                f"target_timestamp={row['target_timestamp']} "
                f"target_label={row['target_window_label']} "
                f"(window target={row['target_window_target']})"
            )
    else:
        print("\nNo valid sequences were constructed (no continuous segment reached length 11).")

    # --- validation report ---
    label_dist = {str(k): int(v) for k, v in windows["label"].value_counts().items()}
    n_benign_windows = int((windows["target"] == 0).sum())
    n_infiltration_windows = int((windows["target"] == 1).sum())

    validation = {
        "input_state_row_count": input_row_count,
        "input_unique_timestamp_count": input_unique_timestamps,
        "num_temporal_windows": n_windows,
        "window_duration_seconds": WINDOW_SIZE_SECONDS,
        "windows_sorted_ascending": bool(windows_to_save["window_start"].is_monotonic_increasing),
        "feature_count_is_68": len(feature_order) == EXPECTED_FEATURE_COUNT,
        "feature_order_matches_state_schema": feature_order == schema["feature_column_names"],
        "num_temporal_gaps": n_gaps,
        "largest_temporal_gap": str(largest_gap),
        "num_continuous_segments": n_segments,
        "num_valid_sequences": n_sequences,
        "X_sequences_shape": list(X_sequences.shape),
        "next_window_features_shape": list(next_window_features.shape),
        "target_or_label_inside_X_sequences": False,
        "label_distribution_window_level": label_dist,
        "num_benign_windows": n_benign_windows,
        "num_infiltration_windows": n_infiltration_windows,
        "observation_count_per_window": {
            "min": int(windows["observation_count"].min()),
            "max": int(windows["observation_count"].max()),
            "mean": round(float(windows["observation_count"].mean()), 4),
            "median": float(windows["observation_count"].median()),
        },
        "missing_values_in_aggregated_features": missing_in_windows,
        "infinite_values_in_aggregated_features": inf_in_windows,
        "no_data_shuffling": True,
        "no_preprocessing_fitted": True,
        "source_files_modified": False,
        "x_sequences_shape_check_10": X_sequences.shape[1] == SEQUENCE_LENGTH,
        "x_sequences_shape_check_68": X_sequences.shape[2] == EXPECTED_FEATURE_COUNT,
        "next_window_features_shape_check_68": next_window_features.shape[1] == EXPECTED_FEATURE_COUNT,
    }

    report = {
        "inputs": {"states_csv": str(states_path), "state_schema_json": str(schema_path)},
        "window_size_seconds": WINDOW_SIZE_SECONDS,
        "sequence_length": SEQUENCE_LENGTH,
        "sequence_stride": SEQUENCE_STRIDE,
        "validation": validation,
        "aggregation_policy_summary": {
            "sum_feature_count": len(sum_cols),
            "mean_feature_count": len(mean_cols),
            "features_needing_documented_decision": policy_summary["features_needing_documented_decision"],
        },
        "outputs": {
            "temporal_windows_csv": str(windows_out_path),
            "temporal_window_metadata_json": str(metadata_path),
            "temporal_aggregation_policy_json": str(policy_path),
            "temporal_feature_order_json": str(feature_order_path),
            "x_sequences_npy": str(x_path),
            "next_window_features_npy": str(next_path),
            "sequence_metadata_csv": str(seq_meta_csv_path),
            "sequence_metadata_json": str(seq_meta_json_path),
        },
    }

    report_json_path = report_dir / "temporal_window_report.json"
    report_json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    report_txt_path = report_dir / "temporal_window_report.txt"
    report_txt_path.write_text(format_text_report(report), encoding="utf-8")
    print(f"\nWrote {report_json_path}, {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Files created: temporal_windows.csv, temporal_window_metadata.json, temporal_aggregation_policy.json, "
          f"X_sequences.npy, next_window_features.npy, sequence_metadata.csv/json, "
          f"temporal_feature_order.json, temporal_window_report.txt/json")
    print(f"Number of 1-second windows: {n_windows}")
    print(f"Number of continuous temporal segments: {n_segments}")
    print(f"Number of temporal gaps: {n_gaps}")
    print(f"Largest temporal gap: {largest_gap}")
    print(f"Number of valid sequences: {n_sequences}")
    print(f"X_sequences shape: {X_sequences.shape}")
    print(f"next_window_features shape: {next_window_features.shape}")
    print(f"Window-level label distribution: {label_dist}")
    print(f"Aggregation policy: {len(sum_cols)} SUM features, {len(mean_cols)} MEAN features "
          f"({len(policy_summary['features_needing_documented_decision'])} required documented judgment calls)")
    print(f"Missing values in aggregated features: {missing_in_windows or 'None'}")
    print(f"Infinite values in aggregated features: {inf_in_windows or 'None'}")
    print("Preprocessing (imputer/scaler) fitted: False")
    print("Target/label inside X_sequences: False")
    print(f"Feature order deterministic (from {feature_order_path}): True")
    print("Model/forecasting created: False")

    return report


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("TEMPORAL WINDOW AND SEQUENCE CONSTRUCTION REPORT")
    lines.append("=" * 70)

    lines.append(f"States input: {report['inputs']['states_csv']}")
    lines.append(f"Schema input: {report['inputs']['state_schema_json']}")
    lines.append(f"Window size: {report['window_size_seconds']} second(s)")
    lines.append(f"Sequence length: {report['sequence_length']} input windows, stride {report['sequence_stride']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("VALIDATION")
    lines.append("-" * 70)
    for k, v in report["validation"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("AGGREGATION POLICY SUMMARY")
    lines.append("-" * 70)
    aps = report["aggregation_policy_summary"]
    lines.append(f"  SUM features: {aps['sum_feature_count']}")
    lines.append(f"  MEAN features: {aps['mean_feature_count']}")
    lines.append(f"  Features needing documented judgment calls: {aps['features_needing_documented_decision']}")

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
