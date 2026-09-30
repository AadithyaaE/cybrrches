"""
Feature 17, Experiment A - frozen-baseline reproduction on every already-
prepared external day, extended with the additional statistics Feature 17
requires (Brier score, degenerate-prediction flag, median/p95 absolute
error, per-feature forecasting error, outlier-dominated dimensions) that
Feature 16's original run did not compute.

This is INFERENCE ONLY: every model is loaded frozen and used via
.transform()/.predict()/.predict_proba() exclusively. No .fit() call
appears anywhere in this file. The already-prepared external-day arrays
under data/processed/frozen_generalization/<day>/ (Feature 16's own
output, unmodified) are read, never rewritten.

The numbers this script produces for accuracy/precision/recall/f1/roc_auc/
pr_auc/fpr/confusion_matrix are mathematically IDENTICAL to Feature 16's
original results/frozen_generalization/binary_attack_metrics.csv (same
frozen models, same prepared data, same generic binary_target,
deterministic inference) - re-run here (not merely copied) so the NEW
statistics can be computed from the same underlying arrays in one
consistent pass, and so this feature's own determinism/reproducibility
claims are independently verifiable rather than inherited by citation.
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, accuracy_score,
)

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src/models"))

from lstm_world_model import LSTMWorldModel  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402
from attack_progression_probability import load_frozen_classifier, infiltration_probability, threshold_predict, DEFAULT_THRESHOLD  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HORIZONS, EXPECTED_FEATURE_COUNT, SEQUENCE_LENGTH, extended_regression_stats, brier_score, degenerate_prediction_check  # noqa: E402

EXTERNAL_DAYS = ["Wednesday-28-02-2018", "Wednesday-14-02-2018", "Wednesday-21-02-2018"]
EXTERNAL_DIR = ROOT / "data/processed/frozen_generalization"
FEATURE_ORDER_PATH = ROOT / "results/temporal_feature_order.json"
LOGREG_PATH = ROOT / "results/baseline/logistic_regression_model.joblib"
RF_PATH = ROOT / "results/baseline/random_forest_model.joblib"
LSTM_CHECKPOINT_PATH = ROOT / "results/lstm/lstm_world_model.pt"
CLASSIFIER_PATH = ROOT / "results/next_state/next_state_attack_classifier.joblib"
OUT_DIR = ROOT / "results/cross_day_generalization"


def load_lstm_checkpoint(device):
    checkpoint = torch.load(LSTM_CHECKPOINT_PATH, map_location=device, weights_only=True)
    cfg = checkpoint["configuration"]
    model = LSTMWorldModel(input_size=cfg.get("input_size", EXPECTED_FEATURE_COUNT), hidden_size=cfg["hidden_size"],
                            num_layers=cfg["num_layers"], dropout=cfg["dropout"]).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model, checkpoint


def compute_classification_metrics(y_true, y_pred, y_proba_pos, threshold=DEFAULT_THRESHOLD) -> dict:
    n_pos, n_neg = int((y_true == 1).sum()), int((y_true == 0).sum())
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    result = {
        "n": int(len(y_true)), "n_positive": n_pos, "n_negative": n_neg,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": threshold,
        "brier_score": brier_score(y_true, y_proba_pos),
        "degenerate_prediction_check": degenerate_prediction_check(y_pred),
    }
    if n_pos > 0 and n_neg > 0:
        result["roc_auc"] = float(roc_auc_score(y_true, y_proba_pos))
        result["pr_auc"] = float(average_precision_score(y_true, y_proba_pos))
    else:
        reason = f"Only one class present in y_true (n_positive={n_pos}, n_negative={n_neg})."
        result["roc_auc_undefined_reason"] = reason
        result["pr_auc_undefined_reason"] = reason
    return result


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]

    print("Loading frozen models (inference only, never fit here) ...")
    logreg_model = joblib.load(LOGREG_PATH)
    rf_model = joblib.load(RF_PATH)
    lstm_model, _ = load_lstm_checkpoint(device)
    classifier = load_frozen_classifier(CLASSIFIER_PATH)

    all_results = {}
    for day in EXTERNAL_DAYS:
        print(f"\n{'='*70}\nExperiment A - Frozen baseline on: {day}\n{'='*70}")
        day_dir = EXTERNAL_DIR / day
        windows = pd.read_csv(day_dir / "temporal_windows.csv")
        seq_meta = pd.read_csv(day_dir / "sequence_metadata.csv")
        X_scaled = np.load(day_dir / "X_sequences_scaled.npy")
        next_scaled = np.load(day_dir / "next_window_features_scaled.npy")
        with open(day_dir / "prep_report.json", encoding="utf-8") as f:
            prep_report = json.load(f)
        n_seq = len(seq_meta)
        print(f"  {n_seq} sequences, {len(windows)} windows.")

        result = {
            "day": day, "n_sequences": n_seq, "n_windows": len(windows),
            "row_count_raw": prep_report["cleaning_report_summary"]["raw_row_count"],
            "row_count_final": prep_report["cleaning_report_summary"]["final_row_count"],
            "timestamp_range": [prep_report["cleaning_report_summary"]["timestamp_min"], prep_report["cleaning_report_summary"]["timestamp_max"]],
            "num_continuous_segments": prep_report["window_summary"]["num_continuous_segments"],
            "num_gaps": prep_report["window_summary"]["num_gaps"],
            "label_distribution_windows": prep_report["window_summary"]["label_distribution_windows"],
        }
        if n_seq == 0:
            all_results[day] = result
            continue

        y_true = seq_meta["target_window_binary_target"].to_numpy().astype(int)

        X_flat = X_scaled.reshape(n_seq, SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT)
        logreg_pred = logreg_model.predict(X_flat)
        logreg_proba = logreg_model.predict_proba(X_flat)[:, list(logreg_model.classes_).index(1)]
        rf_pred = rf_model.predict(X_flat)
        rf_proba = rf_model.predict_proba(X_flat)[:, list(rf_model.classes_).index(1)]
        result["logistic_regression_binary"] = compute_classification_metrics(y_true, logreg_pred, logreg_proba)
        result["random_forest_binary"] = compute_classification_metrics(y_true, rf_pred, rf_proba)

        rollout_full = batched_recursive_rollout(lstm_model, torch.from_numpy(X_scaled), max(HORIZONS), device).numpy()
        lstm_k1_pred = rollout_full[:, 0, :]
        result["lstm_one_step_regression"] = extended_regression_stats(lstm_k1_pred, next_scaled, feature_order)

        oracle_proba = infiltration_probability(classifier, next_scaled)
        oracle_pred = threshold_predict(oracle_proba)
        pipeline_proba = infiltration_probability(classifier, lstm_k1_pred)
        pipeline_pred = threshold_predict(pipeline_proba)
        result["next_state_classifier_oracle_binary"] = compute_classification_metrics(y_true, oracle_pred, oracle_proba)
        result["next_state_classifier_full_pipeline_binary"] = compute_classification_metrics(y_true, pipeline_pred, pipeline_proba)

        horizon_results = {}
        for h in HORIZONS:
            end_wid = seq_meta["input_end_window"].to_numpy()
            seg = windows.set_index("window_id")["segment_id"]
            target_wid = end_wid + h
            in_range = target_wid <= (len(windows) - 1)
            clipped = np.where(in_range, target_wid, 0)
            end_seg = seg.reindex(end_wid).to_numpy()
            target_seg = seg.reindex(clipped).to_numpy()
            valid = in_range & (target_seg == end_seg)
            n_valid = int(valid.sum())
            if n_valid == 0:
                horizon_results[h] = {"n": 0, "note": "No valid sequences at this horizon."}
                continue
            pred_h = rollout_full[valid, h - 1, :]
            windows_idx = windows.set_index("window_id")
            actual_raw = windows_idx.loc[clipped[valid], feature_order]
            # transform actual raw window features via the SAME frozen Feature 7 pipeline used to prepare X_scaled
            fitted_pipeline = joblib.load(ROOT / "data/processed/splits/preprocessing_pipeline_train_fitted.joblib")
            actual_scaled = np.asarray(fitted_pipeline.transform(actual_raw), dtype="float32")
            y_h = windows_idx.loc[clipped[valid], "binary_target"].to_numpy().astype(int)
            reg_h = extended_regression_stats(pred_h, actual_scaled, feature_order)
            proba_h = infiltration_probability(classifier, pred_h)
            pred_label_h = threshold_predict(proba_h)
            cls_h = compute_classification_metrics(y_h, pred_label_h, proba_h)
            horizon_results[h] = {"regression": reg_h, "attack_progression": cls_h}
        result["horizons"] = horizon_results

        all_results[day] = result
        print(f"  Done: {day}")

    (OUT_DIR / "experiment_a_frozen_baseline.json").write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {OUT_DIR / 'experiment_a_frozen_baseline.json'}")
    return all_results


if __name__ == "__main__":
    main()
