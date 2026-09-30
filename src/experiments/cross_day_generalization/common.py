"""
Feature 17 - shared utilities for cross-day generalization experiments.

Reuses, never modifies: src/data/clean_dataset.py, src/data/prepare_external_dataset.py,
src/data/build_temporal_windows.py, src/models/evaluate_frozen_generalization.py,
src/models/lstm_world_model.py, src/models/k_step_forecaster.py,
src/models/attack_progression_probability.py.
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src/data"))
sys.path.insert(0, str(ROOT / "src/models"))

from clean_dataset import clean_dataset  # noqa: E402 - Feature 2, unmodified
import prepare_external_dataset as pext  # noqa: E402 - Feature 16, unmodified

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
HORIZONS = [1, 2, 3, 5]
RANDOM_SEED = 42

# Every day this feature is permitted to use, with its raw file, and its EXPLICIT,
# preserved data-quality caveat (never hidden, never silently dropped).
DAY_REGISTRY = {
    "Thursday-01-03-2018": {
        "raw_path": ROOT / "data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        "role": "original CyberChess training/dev day (Features 1-16)",
        "caveat": "None beyond what Features 1-16 already documented (embedded header rows, exact duplicates - handled by clean_dataset()).",
    },
    "Wednesday-28-02-2018": {
        "raw_path": ROOT / "data/raw/external_evaluation/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
        "role": "external evaluation day - same attack type (Infilteration) as Thursday",
        "caveat": "None known beyond standard cleaning artifacts.",
    },
    "Wednesday-14-02-2018": {
        "raw_path": ROOT / "data/raw/external_evaluation/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "role": "external evaluation day - FTP-BruteForce/SSH-Bruteforce (different attack family)",
        "caveat": (
            "TRUNCATION/DUPLICATE CAVEAT: raw file has exactly 1,048,575 rows - one less than Excel's "
            "1,048,576 row limit, strongly indicating the file was truncated by a spreadsheet tool at some "
            "point in its provenance. 225,628 of those rows (21.5%) are exact duplicates removed by "
            "clean_dataset(). A corrupted/bogus timestamp (1970-01-05) is also present in the raw data. "
            "EXCLUDED from Experiment B's training combinations in this feature due to this caveat (see "
            "cross_day_report.txt for the exact exclusion rationale); still used, unchanged, in Experiment A "
            "as a frozen-baseline evaluation day (reusing Feature 16's existing results)."
        ),
    },
    "Wednesday-21-02-2018": {
        "raw_path": ROOT / "data/raw/external_evaluation/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        "role": "external evaluation day - DDOS-HOIC/DDOS-LOIC-UDP (different attack family, volumetric)",
        "caveat": (
            "TRUNCATION/EARLY-ENDING CAVEAT: raw file also has exactly 1,048,575 rows (same Excel-row-limit "
            "truncation signature as Wednesday-14-02-2018). The file's timestamp range ends at 10:43:21 "
            "(covers only ~8h47m, not a full day) and traffic is extremely bursty (mean 316.7 flows per "
            "1-second window, max 811) - consistent with a volumetric DDoS flood compressing enormous row "
            "counts into very few distinct 1-second windows (3,256 windows from 1,031,018 cleaned rows)."
        ),
    },
}

TUESDAY_20_02_EXCLUSION_NOTE = (
    "Tuesday-20-02-2018 is explicitly EXCLUDED from this feature, per instruction: its raw schema has 84 "
    "columns (vs. the standard 80: extra Flow ID/Src IP/Src Port/Dst IP columns) and has not been mapped or "
    "validated against the 65-feature contract. It is schema-incompatible and was never downloaded/prepared "
    "for use anywhere in this project."
)


def prepare_day_windows_and_sequences(day_label: str, feature_order: list, numeric_features: list, onehot_protocol_columns: list) -> dict:
    """
    Runs a day's raw CSV through clean_dataset() (Feature 2, unmodified) and
    prepare_external_dataset's build_model_ready_table/build_states/build_windows/
    build_sequences (Feature 16, unmodified) - producing windows (with the
    GENERIC binary_target: 0=Benign, 1=any-attack) and RAW (unscaled) sequences.
    Does NOT apply any preprocessing transform - that is the caller's
    responsibility (either the frozen Feature 7 pipeline for Experiment A, or a
    newly-fit-on-training-days-only pipeline for Experiment B).
    """
    raw_path = DAY_REGISTRY[day_label]["raw_path"]
    if not raw_path.exists():
        raise FileNotFoundError(f"Raw file for {day_label} not found: {raw_path}")

    clean_df, clean_report = clean_dataset(raw_path)  # Feature 2, unmodified - takes a path, parses Timestamp itself

    model_ready, target_df, timestamp_df, prep_meta = pext.build_model_ready_table(clean_df, numeric_features, onehot_protocol_columns)
    states = pext.build_states(model_ready, target_df, timestamp_df, feature_order)
    windows = pext.build_windows(states, feature_order)
    X_raw, next_raw, seq_meta = pext.build_sequences(windows, feature_order)

    return {
        "day_label": day_label,
        "clean_row_count": len(clean_df),
        "clean_report": clean_report,
        "windows": windows,
        "X_raw": X_raw,
        "next_raw": next_raw,
        "seq_meta": seq_meta,
        "timestamp_min": str(clean_df[pext.TIMESTAMP_COLUMN].min()),
        "timestamp_max": str(clean_df[pext.TIMESTAMP_COLUMN].max()),
    }


def chronological_train_val_split(seq_meta: pd.DataFrame, val_fraction: float = 0.1):
    """
    Splits sequence indices chronologically (last val_fraction, by
    input_start_window order, as validation) WITHOUT shuffling - used only to
    pick an LSTM early-stopping validation set from the COMBINED TRAINING
    days (the held-out day is never involved). Never mixes days: caller must
    call this PER DAY and concatenate the resulting index arrays, since a day
    boundary is not itself a valid split point within a day's own chronology.
    """
    order = np.argsort(seq_meta["input_start_window"].to_numpy(), kind="mergesort")
    n = len(order)
    n_val = max(1, int(round(n * val_fraction))) if n > 1 else 0
    train_idx = order[: n - n_val]
    val_idx = order[n - n_val:]
    return train_idx, val_idx


def extended_regression_stats(pred: np.ndarray, actual: np.ndarray, feature_order: list) -> dict:
    """Extends Feature 16's regression_metrics() with median/p95 absolute error and
    an explicit outlier-dominated-dimension flag - frozen-model INFERENCE only, no fitting."""
    ab = np.abs(pred - actual)
    sq = (pred - actual) ** 2
    per_sample_ab = np.mean(ab, axis=1)
    per_feature_mae = np.mean(ab, axis=0)
    per_feature_mse = np.mean(sq, axis=0)
    per_feature_p95 = np.percentile(ab, 95, axis=0)
    per_feature_max = np.max(ab, axis=0)

    overall_p95 = float(np.percentile(per_sample_ab, 95))
    # Outlier-dominated uses MAX/MAE (not P95/MAE): a sparse outlier affecting <5% of rows
    # can still leave the 95th percentile in the "normal" range, but always shows up in max().
    outlier_dominated = [
        feature_order[i] for i in range(len(feature_order))
        if per_feature_max[i] > 0 and (per_feature_max[i] / max(per_feature_mae[i], 1e-12)) > 10
    ]

    return {
        "n": int(len(pred)),
        "mse": float(np.mean(sq)),
        "rmse": float(np.sqrt(np.mean(sq))),
        "mae": float(np.mean(ab)),
        "median_abs_error": float(np.median(per_sample_ab)),
        "p95_abs_error": overall_p95,
        "per_feature_mae": {feature_order[i]: float(per_feature_mae[i]) for i in range(len(feature_order))},
        "per_feature_p95_abs_error": {feature_order[i]: float(per_feature_p95[i]) for i in range(len(feature_order))},
        "per_feature_max_abs_error": {feature_order[i]: float(per_feature_max[i]) for i in range(len(feature_order))},
        "outlier_dominated_dimensions": outlier_dominated,
        "outlier_dominated_note": (
            "A dimension is flagged 'outlier-dominated' if its per-feature MAXIMUM absolute error is >10x "
            "its own mean absolute error (MAX, not P95, so a sparse outlier affecting even <5% of rows is "
            "still caught) - i.e. a small number of samples dominate that feature's error budget. This is a "
            "diagnostic flag, not a claim about severity relative to other features."
        ),
    }


def brier_score(y_true: np.ndarray, y_proba: np.ndarray) -> float:
    return float(np.mean((np.asarray(y_proba, dtype=float) - np.asarray(y_true, dtype=float)) ** 2))


def degenerate_prediction_check(y_pred: np.ndarray) -> dict:
    """Flags a classifier that predicts (almost) all-one-class - required explicit check."""
    y_pred = np.asarray(y_pred)
    n = len(y_pred)
    pos_frac = float((y_pred == 1).sum()) / n if n else float("nan")
    degenerate = pos_frac >= 0.99 or pos_frac <= 0.01
    return {"positive_prediction_fraction": pos_frac, "degenerate": bool(degenerate)}
