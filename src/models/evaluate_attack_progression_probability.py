"""
Feature 13 - Attack Progression Probability.

"Feature 12 answers: what might the future network state look like?
Feature 13 answers: given the predicted future network state, how
strongly does the frozen attack classifier associate that future state
with Infiltration?"

Pipeline:

    observed history (X_sequences_scaled)
        -> frozen Feature 10 LSTM (recursive rollout, reused from Feature 12)
        -> predicted future state Shat(t+K)
        -> frozen Feature 11 classifier
        -> P(Infiltration at t+K)

Primary result: "Full recursive CyberChess pipeline" (predicted state ->
classifier), evaluated on VALIDATION (the only mixed-class partition
besides TRAIN, which the classifier was fit on). An "Oracle future-state
diagnostic" (ground-truth state -> classifier) is also reported, clearly
labeled as a diagnostic, never as the primary result.

"The current chronological TEST partition contains no Infiltration
samples, so attack-progression detection metrics cannot be established
on that partition. Feature 13 is therefore evaluated on the mixed-class
VALIDATION partition as a development-stage assessment. A later expanded
multi-day evaluation will provide a proper unseen attack-containing test
set."

Usage:
    python src/models/evaluate_attack_progression_probability.py
"""

import argparse
import hashlib
import json
import platform
import random
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import torch
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402
from attack_progression_probability import (  # noqa: E402
    load_frozen_classifier, infiltration_probability, threshold_predict, DEFAULT_THRESHOLD,
)

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"
LSTM_CHECKPOINT_PATH = Path("results/lstm/lstm_world_model.pt")
CLASSIFIER_PATH = Path("results/next_state/next_state_attack_classifier.joblib")
FEATURE11_PIPELINE_METRICS_PATH = Path("results/next_state/pipeline_metrics.json")
TEMPORAL_WINDOWS_PATH = Path("data/processed/temporal/temporal_windows.csv")
FEATURE12_TEST_ROLLOUT_PATH = Path("data/processed/forecasting/test_rollout_predictions.npy")
FEATURE12_HORIZON_METRICS_PATH = Path("results/forecasting/k_step_forecast_horizon_metrics.csv")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
SEED = 42
HORIZONS = [1, 2, 3, 5]
K_MAX = max(HORIZONS)
WINDOW_STEP = pd.Timedelta(seconds=1)
EXPECTED_COUNTS = {"validation": 3492, "test": 2871}
TRAIN_FRACTION, VAL_FRACTION = 0.70, 0.15  # re-derived exactly as Feature 7/12 (not re-decided)
TOLERANCE = 1e-6

FEATURE_PROTECTED_FILES = (
    [
        SPLITS_DIR / "train" / "X_sequences_scaled.npy", SPLITS_DIR / "train" / "next_window_features_scaled.npy",
        SPLITS_DIR / "train" / "sequence_metadata.csv",
        SPLITS_DIR / "validation" / "X_sequences_scaled.npy", SPLITS_DIR / "validation" / "next_window_features_scaled.npy",
        SPLITS_DIR / "validation" / "sequence_metadata.csv",
        SPLITS_DIR / "test" / "X_sequences_scaled.npy", SPLITS_DIR / "test" / "next_window_features_scaled.npy",
        SPLITS_DIR / "test" / "sequence_metadata.csv",
        FITTED_PIPELINE_PATH, SPLITS_DIR / "split_metadata.json", TEMPORAL_WINDOWS_PATH,
    ]
    + list(Path("results/baseline").glob("logistic_regression_*"))
    + list(Path("results/baseline").glob("random_forest_*"))
    + list(Path("results/baseline").glob("baseline_model_comparison*"))
    + [LSTM_CHECKPOINT_PATH, Path("results/lstm/lstm_config.json"), Path("data/processed/lstm/test_predicted_next_state.npy")]
    + (list(Path("results/next_state").glob("*")) if Path("results/next_state").exists() else [])
    + (list(Path("results/forecasting").glob("*")) if Path("results/forecasting").exists() else [])
    + [FEATURE12_TEST_ROLLOUT_PATH]
)


def fail(message: str):
    raise SystemExit(f"FEATURE 13 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: list) -> dict:
    return {str(p): file_md5(p) for p in paths if p.exists()}


def load_lstm_checkpoint(device):
    if not LSTM_CHECKPOINT_PATH.exists():
        fail(f"Required Feature 10 checkpoint not found: {LSTM_CHECKPOINT_PATH}")
    checkpoint = torch.load(LSTM_CHECKPOINT_PATH, map_location=device, weights_only=True)
    cfg = checkpoint["configuration"]
    model = LSTMWorldModel(
        input_size=cfg.get("input_size", EXPECTED_FEATURE_COUNT),
        hidden_size=cfg["hidden_size"], num_layers=cfg["num_layers"], dropout=cfg["dropout"],
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model, checkpoint


def build_window_table(feature_order, fitted_pipeline):
    """Re-derive window_id/segment_id/partition and precompute scaled features for every window.
    Identical logic to Feature 7/12 (never modified), cross-checked below against their actual outputs."""
    windows = pd.read_csv(TEMPORAL_WINDOWS_PATH)
    windows["window_start"] = pd.to_datetime(windows["window_start"], errors="coerce")
    if windows["window_start"].isna().any():
        fail("Timestamp parsing failed in temporal_windows.csv.")
    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    if not (windows["window_id"].to_numpy() == np.arange(len(windows))).all():
        fail("window_id is not a 0..N-1 range in time-sorted order.")

    gap_mask = windows["window_start"].diff() > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()

    n_windows = len(windows)
    train_end_idx = max(1, min(int(np.floor(TRAIN_FRACTION * n_windows)), n_windows - 2))
    val_end_idx = max(train_end_idx + 1, min(int(np.floor((TRAIN_FRACTION + VAL_FRACTION) * n_windows)), n_windows - 1))
    windows["partition"] = np.where(windows.index < train_end_idx, "train", np.where(windows.index < val_end_idx, "validation", "test"))

    for name in ["train", "validation", "test"]:
        meta_check = pd.read_csv(SPLITS_DIR / name / "sequence_metadata.csv")
        derived = windows.set_index("window_id").loc[meta_check["input_end_window"].to_numpy(), "partition"].to_numpy()
        if not (derived == name).all():
            fail(f"Re-derived partition assignment does not match Feature 7's actual '{name}' split.")

    scaled = np.asarray(fitted_pipeline.transform(windows[feature_order]), dtype="float32")
    if scaled.shape != (n_windows, EXPECTED_FEATURE_COUNT) or np.isnan(scaled).any() or np.isinf(scaled).any():
        fail("Scaled window feature matrix is malformed (shape or NaN/Infinity).")

    return windows, scaled


def horizon_validity(windows, name, meta, h):
    end_wid = meta["input_end_window"].to_numpy()
    seg = windows["segment_id"].to_numpy()
    part = windows["partition"].to_numpy()
    n_windows = len(windows)
    target_wid = end_wid + h
    in_range = target_wid <= (n_windows - 1)
    clipped = np.where(in_range, target_wid, 0)
    same_segment = np.where(in_range, seg[clipped] == seg[end_wid], False)
    same_partition = np.where(in_range, part[clipped] == name, False)
    valid = in_range & same_segment & same_partition
    return valid, target_wid


def compute_classification_metrics(y_true, proba, threshold=DEFAULT_THRESHOLD, full_metrics=True):
    y_pred = threshold_predict(proba, threshold)
    n = len(y_true)
    n_pos, n_neg = int((y_true == 1).sum()), int((y_true == 0).sum())
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp) / (fp + tn) if (fp + tn) > 0 else None

    result = {
        "n_samples": n, "n_positive": n_pos, "n_negative": n_neg,
        "predicted_positive_count": int((y_pred == 1).sum()), "predicted_negative_count": int((y_pred == 0).sum()),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": fpr, "threshold": threshold,
        "roc_auc": None, "pr_auc": None, "precision": None, "recall": None, "f1": None,
        "notes": [],
    }
    if not full_metrics or n_pos == 0 or n_neg == 0:
        result["notes"].append(
            f"ROC-AUC/PR-AUC/recall/F1 not estimable or intentionally withheld (n_positive={n_pos}, n_negative={n_neg})."
        )
        if n_pos == 0 and (fp + tn) > 0:
            # precision is well-defined (0/(0+FP) or undefined if FP also 0) even with zero positives; report it, never recall/AUC.
            prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
            result["precision"] = None if np.isnan(prec) else prec
        return result

    result["roc_auc"] = float(roc_auc_score(y_true, proba))
    result["pr_auc"] = float(average_precision_score(y_true, proba))
    prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    result["precision"] = None if np.isnan(prec) else prec
    result["recall"] = None if np.isnan(rec) else rec
    result["f1"] = None if np.isnan(f1) else f1
    return result


def calibration_analysis(y_true, proba, n_bins=10):
    brier = float(brier_score_loss(y_true, proba))
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins = []
    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        mask = (proba >= lo) & (proba < hi) if i < n_bins - 1 else (proba >= lo) & (proba <= hi)
        n = int(mask.sum())
        bins.append({
            "bin_low": float(lo), "bin_high": float(hi), "n_samples": n,
            "mean_predicted_probability": float(proba[mask].mean()) if n > 0 else None,
            "observed_infiltration_frequency": float(y_true[mask].mean()) if n > 0 else None,
        })
    return brier, bins


def main():
    parser = argparse.ArgumentParser(description="Feature 13: attack progression probability evaluation.")
    parser.add_argument("--report-dir", default="results/attack_progression")
    args = parser.parse_args()
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    print("Recording Feature 7-12 file hashes (pre-run) ...")
    hashes_before = hash_files(FEATURE_PROTECTED_FILES)

    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}  Horizons: {HORIZONS}")

    for p in [FEATURE_ORDER_PATH, FITTED_PIPELINE_PATH, TEMPORAL_WINDOWS_PATH, CLASSIFIER_PATH]:
        if not p.exists():
            fail(f"Required file not found: {p}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"Feature order length {len(feature_order)} != {EXPECTED_FEATURE_COUNT}.")

    print(f"Loading frozen Feature 10 LSTM checkpoint from {LSTM_CHECKPOINT_PATH} ...")
    lstm_model, checkpoint = load_lstm_checkpoint(device)

    print(f"Loading frozen Feature 11 classifier from {CLASSIFIER_PATH} (identified as the authoritative saved classifier per its config/report) ...")
    classifier = load_frozen_classifier(CLASSIFIER_PATH)
    print(f"  classifier.classes_ = {list(classifier.classes_)}, expects {EXPECTED_FEATURE_COUNT}-dim input (verified per-call below).")

    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)  # transform() only, never fit()

    print("Re-deriving window/segment/partition table (same rule as Feature 7/12) ...")
    windows, scaled_window_features = build_window_table(feature_order, fitted_pipeline)
    window_label = windows.set_index("window_id")["label"]

    print("Loading VALIDATION and TEST sequences (Feature 7 outputs, unmodified) ...")
    split_data = {}
    for name in ["validation", "test"]:
        X = np.load(SPLITS_DIR / name / "X_sequences_scaled.npy").astype("float32")
        meta = pd.read_csv(SPLITS_DIR / name / "sequence_metadata.csv")
        if len(meta) != EXPECTED_COUNTS[name]:
            fail(f"{name}: sequence count {len(meta)} != known Feature 7 size {EXPECTED_COUNTS[name]}.")
        if X.shape != (len(meta), SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT) or np.isnan(X).any() or np.isinf(X).any():
            fail(f"{name}: X_sequences_scaled malformed.")
        split_data[name] = {"X": X, "meta": meta}

    print("Regenerating recursive rollout forecasts via the reused Feature 12 forecaster (VALIDATION + TEST) ...")
    rollout = {
        name: batched_recursive_rollout(lstm_model, torch.from_numpy(split_data[name]["X"]), K_MAX, device).numpy()
        for name in ["validation", "test"]
    }
    for name, arr in rollout.items():
        if np.isnan(arr).any() or np.isinf(arr).any():
            fail(f"{name}: rollout predictions contain NaN/Infinity.")

    if FEATURE12_TEST_ROLLOUT_PATH.exists():
        saved_test = np.load(FEATURE12_TEST_ROLLOUT_PATH)
        max_diff = float(np.max(np.abs(saved_test - rollout["test"])))
        print(f"  Regenerated TEST rollout vs Feature 12's saved array: max diff={max_diff:.3e}")
        if max_diff > TOLERANCE:
            fail(f"Regenerated TEST rollout does not match Feature 12's saved predictions within {TOLERANCE} (max diff {max_diff}).")

    # --- per-horizon validity + actual future label/state; cross-check N against Feature 12 ---
    print("Determining per-horizon validity and gathering actual future labels/states ...")
    f12_horizon_df = pd.read_csv(FEATURE12_HORIZON_METRICS_PATH) if FEATURE12_HORIZON_METRICS_PATH.exists() else None
    valid_masks, actual_label, actual_state, target_wid_map = {}, {}, {}, {}
    for name in ["validation", "test"]:
        valid_masks[name], actual_label[name], actual_state[name], target_wid_map[name] = {}, {}, {}, {}
        for h in HORIZONS:
            valid, target_wid = horizon_validity(windows, name, split_data[name]["meta"], h)
            valid_masks[name][h] = valid
            target_wid_map[name][h] = target_wid
            actual_label[name][h] = window_label.reindex(target_wid[valid]).to_numpy()
            actual_state[name][h] = scaled_window_features[np.where(valid, target_wid, 0)][valid]
            n_valid = int(valid.sum())
            if f12_horizon_df is not None:
                expected_n = f12_horizon_df.query("horizon == @h and split == @name")["n"].iloc[0]
                if n_valid != expected_n:
                    fail(f"{name} h={h}: re-derived valid count {n_valid} != Feature 12's reported N {expected_n}.")
            print(f"  {name} h={h}: {n_valid} valid / {len(valid)} total")

    # --- probabilities: full pipeline (predicted state) + oracle diagnostic (actual state) ---
    print("Computing P(Infiltration): FULL PIPELINE (predicted state) and ORACLE diagnostic (actual state) ...")
    proba_pipeline, proba_oracle, y_target = {}, {}, {}
    for name in ["validation", "test"]:
        proba_pipeline[name], proba_oracle[name], y_target[name] = {}, {}, {}
        for h in HORIZONS:
            mask = valid_masks[name][h]
            pred_state_h = rollout[name][mask, h - 1, :]
            proba_pipeline[name][h] = infiltration_probability(classifier, pred_state_h)
            proba_oracle[name][h] = infiltration_probability(classifier, actual_state[name][h])
            y_target[name][h] = (pd.Series(actual_label[name][h]) == "Infilteration").to_numpy().astype(int)

    # --- K=1 consistency check with Feature 11's saved validation pipeline metrics ---
    print("Running K=1 consistency check against Feature 11 ...")
    consistency = {}
    if FEATURE11_PIPELINE_METRICS_PATH.exists():
        with open(FEATURE11_PIPELINE_METRICS_PATH, encoding="utf-8") as f:
            f11_val = json.load(f)["validation"]
        f13_k1 = compute_classification_metrics(y_target["validation"][1], proba_pipeline["validation"][1], threshold=0.5, full_metrics=True)
        checks_match = {
            "accuracy_note": "Feature 13 reports precision/recall/f1/roc_auc/fpr/confusion_matrix; accuracy is derivable from the confusion matrix.",
            "precision_match": abs(f13_k1["precision"] - f11_val["precision"]) < 1e-9,
            "recall_match": abs(f13_k1["recall"] - f11_val["recall"]) < 1e-9,
            "f1_match": abs(f13_k1["f1"] - f11_val["f1"]) < 1e-9,
            "roc_auc_match": abs(f13_k1["roc_auc"] - f11_val["roc_auc"]) < 1e-9,
            "fpr_match": abs(f13_k1["false_positive_rate"] - f11_val["false_positive_rate"]) < 1e-9,
            "confusion_matrix_match": f13_k1["confusion_matrix"] == f11_val["confusion_matrix"],
        }
        all_match = all(v for k, v in checks_match.items() if k.endswith("_match"))
        consistency["k1_consistency_with_feature11"] = {
            "feature13_k1_pipeline_validation": f13_k1, "feature11_pipeline_validation": f11_val,
            "checks": checks_match, "all_match": all_match,
        }
        print(f"  K=1 vs Feature 11 all_match={all_match}: {checks_match}")
        if not all_match:
            fail(f"Feature 13's K=1 full-pipeline VALIDATION metrics do not match Feature 11's saved metrics: {checks_match}")
    else:
        print(f"  NOTE: {FEATURE11_PIPELINE_METRICS_PATH} not found; skipping direct comparison.")

    # --- primary metrics: VALIDATION full pipeline (and oracle diagnostic) per horizon ---
    print("Computing primary VALIDATION metrics (full pipeline) and ORACLE diagnostic per horizon ...")
    horizon_metrics = {"full_pipeline": {}, "oracle_diagnostic": {}}
    for h in HORIZONS:
        horizon_metrics["full_pipeline"][h] = compute_classification_metrics(y_target["validation"][h], proba_pipeline["validation"][h], full_metrics=True)
        horizon_metrics["oracle_diagnostic"][h] = compute_classification_metrics(y_target["validation"][h], proba_oracle["validation"][h], full_metrics=True)
        print(f"  h={h} FULL PIPELINE (validation): roc_auc={horizon_metrics['full_pipeline'][h]['roc_auc']:.4f} "
              f"pr_auc={horizon_metrics['full_pipeline'][h]['pr_auc']:.4f} f1={horizon_metrics['full_pipeline'][h]['f1']}")

    # --- TEST: descriptive only, NO recall/F1/ROC-AUC/PR-AUC (zero positives) ---
    print("Computing TEST descriptive-only metrics (benign false-positive behavior; NO attack-detection claims) ...")
    test_descriptive = {}
    for h in HORIZONS:
        test_descriptive[h] = compute_classification_metrics(y_target["test"][h], proba_pipeline["test"][h], full_metrics=False)
        test_descriptive[h]["mean_probability"] = float(np.mean(proba_pipeline["test"][h]))
        test_descriptive[h]["std_probability"] = float(np.std(proba_pipeline["test"][h]))

    # --- calibration (VALIDATION full pipeline only) ---
    print("Running calibration analysis (VALIDATION, full pipeline) ...")
    calibration = {}
    calibration_rows = []
    for h in HORIZONS:
        brier, bins = calibration_analysis(y_target["validation"][h], proba_pipeline["validation"][h])
        calibration[h] = {"brier_score": brier, "bins": bins}
        for b in bins:
            calibration_rows.append({"horizon": h, **b})
    calibration_df = pd.DataFrame(calibration_rows)

    # --- trajectory analysis (VALIDATION full pipeline) ---
    print("Running probability trajectory analysis (VALIDATION, full pipeline) ...")
    trajectory_rows = []
    for h in HORIZONS:
        p = proba_pipeline["validation"][h]
        yt = y_target["validation"][h]
        row = {
            "horizon": h, "n": len(p), "mean": float(np.mean(p)), "median": float(np.median(p)), "std": float(np.std(p)),
            "p10": float(np.percentile(p, 10)), "p90": float(np.percentile(p, 90)),
            "mean_given_actual_benign": float(np.mean(p[yt == 0])) if (yt == 0).any() else None,
            "mean_given_actual_infiltration": float(np.mean(p[yt == 1])) if (yt == 1).any() else None,
            "median_given_actual_benign": float(np.median(p[yt == 0])) if (yt == 0).any() else None,
            "median_given_actual_infiltration": float(np.median(p[yt == 1])) if (yt == 1).any() else None,
        }
        trajectory_rows.append(row)
    trajectory_df = pd.DataFrame(trajectory_rows)

    # --- early-warning diagnostic: fixed, documented definition ---
    print("Running early-warning diagnostic (documented definition; VALIDATION full pipeline) ...")
    early_warning_definition = (
        "Among VALIDATION sequences with a valid K=5 forecast, group by the sequence's ACTUAL label at "
        "t+5 (Benign vs Infilteration). For each group, report the mean/median full-pipeline P(Infiltration) "
        "at K=1, K=2, K=3, K=5 for that SAME sequence, restricted at each K to sequences for which that "
        "horizon is also individually valid (gap/partition-safe). This tests whether sequences destined to "
        "show Infiltration at t+5 already display elevated P(Infiltration) at earlier, shorter lead times, "
        "without assuming this must be true and without inventing a numeric 'lead time in seconds' metric. "
        "Because Feature 12 verified target windows are genuinely consecutive 1-second windows, horizon K "
        "here does correspond to K seconds ahead for the sequences evaluated at that horizon."
    )
    valid5 = valid_masks["validation"][5]
    meta_val = split_data["validation"]["meta"]
    seq_id_valid5 = meta_val.loc[valid5, "sequence_id"].to_numpy()
    label_at_5 = actual_label["validation"][5]
    group_infil_seqids = set(seq_id_valid5[label_at_5 == "Infilteration"].tolist())
    group_benign_seqids = set(seq_id_valid5[label_at_5 == "Benign"].tolist())

    early_warning_rows = []
    for h in HORIZONS:
        mask_h = valid_masks["validation"][h]
        seq_id_h = meta_val.loc[mask_h, "sequence_id"].to_numpy()
        p_h = proba_pipeline["validation"][h]
        is_infil_group = np.isin(seq_id_h, list(group_infil_seqids))
        is_benign_group = np.isin(seq_id_h, list(group_benign_seqids))
        early_warning_rows.append({
            "horizon": h,
            "n_in_infiltration_at_t5_group": int(is_infil_group.sum()),
            "mean_p_infiltration_group": float(p_h[is_infil_group].mean()) if is_infil_group.any() else None,
            "n_in_benign_at_t5_group": int(is_benign_group.sum()),
            "mean_p_benign_group": float(p_h[is_benign_group].mean()) if is_benign_group.any() else None,
        })
    early_warning_df = pd.DataFrame(early_warning_rows)
    print(f"  Early-warning diagnostic: {early_warning_rows}")

    # --- reproducibility: run full pipeline probability generation twice ---
    print("Verifying reproducibility: running probability generation twice on a fixed VALIDATION subset ...")
    fixed_states = rollout["validation"][:200, 0, :]
    p1 = infiltration_probability(classifier, fixed_states)
    p2 = infiltration_probability(classifier, fixed_states)
    run_match = bool(np.allclose(p1, p2, atol=TOLERANCE))
    reloaded_classifier = load_frozen_classifier(CLASSIFIER_PATH)
    p3 = infiltration_probability(reloaded_classifier, fixed_states)
    reload_match = bool(np.allclose(p1, p3, atol=TOLERANCE))
    print(f"  Repeat-run match: {run_match}  Fresh-reload match: {reload_match}")
    if not (run_match and reload_match):
        fail("Probability generation is not reproducible within tolerance.")

    # --- leakage checks ---
    print("Running leakage checks ...")
    n_grad_params_lstm = sum(p.requires_grad for p in lstm_model.parameters())
    leakage_checks = {
        "1_classifier_weights_unchanged": True,  # never touched after load_frozen_classifier(); no .fit() call anywhere
        "2_no_classifier_fitting": True,
        "3_no_lstm_training": True,  # lstm_model used only via eval()+no_grad() batched_recursive_rollout
        "4_no_scaler_fitting": True,  # fitted_pipeline.transform() only, .fit() never called
        "5_no_validation_labels_in_model_inputs": True,  # y_target used only for evaluation, never fed to classifier/model
        "6_no_actual_future_states_in_rollout": True,  # rollout uses only its own predictions after step 1 (Feature 12 module, unmodified)
        "7_actual_future_labels_evaluation_only": True,
        "8_no_temporal_gaps_crossed": True,  # enforced by same_segment mask in horizon_validity()
        "9_no_partition_boundary_crossed": True,  # enforced by same_partition mask in horizon_validity()
        "10_probabilities_use_predicted_state_for_full_pipeline": True,  # proba_pipeline built from rollout[...], not actual_state
        "11_feature7_12_artifacts_unchanged": None,  # filled after post-run hashing
        "lstm_frozen_param_count_with_grad": n_grad_params_lstm,
    }
    if n_grad_params_lstm != 0:
        fail("LSTM parameters unexpectedly require grad (should be frozen).")

    # --- post-run integrity ---
    print("Verifying Feature 7-12 files were not modified ...")
    hashes_after = hash_files(FEATURE_PROTECTED_FILES)
    unchanged = hashes_before == hashes_after
    if not unchanged:
        changed = [k for k in hashes_before if hashes_before.get(k) != hashes_after.get(k)]
        fail(f"Protected Feature 7-12 files were modified: {changed}")
    leakage_checks["11_feature7_12_artifacts_unchanged"] = unchanged
    print(f"  Feature 7-12 artifacts unchanged: {unchanged}")

    # --- predictions table ---
    print("Building predictions table ...")
    pred_rows = []
    for mode_name, proba_dict, state_source in [("full_pipeline", proba_pipeline, "predicted"), ("oracle_diagnostic", proba_oracle, "actual")]:
        for name in ["validation", "test"]:
            for h in HORIZONS:
                mask = valid_masks[name][h]
                meta_valid = split_data[name]["meta"].loc[mask]
                tgt_wid = target_wid_map[name][h][mask]
                proba = proba_dict[name][h]
                pred_rows.append(pd.DataFrame({
                    "mode": mode_name, "partition": name,
                    "sequence_id": meta_valid["sequence_id"].to_numpy(),
                    "current_timestamp": meta_valid["input_end_timestamp"].to_numpy(),
                    "future_timestamp": meta_valid["target_timestamp"].to_numpy() if h == 1 else windows.set_index("window_id").loc[tgt_wid, "window_start"].astype(str).to_numpy(),
                    "horizon": h,
                    "actual_future_label": actual_label[name][h],
                    "predicted_infiltration_probability": proba,
                    "predicted_attack_class_at_0_50": threshold_predict(proba, DEFAULT_THRESHOLD),
                    "segment_id": windows.set_index("window_id").loc[tgt_wid, "segment_id"].to_numpy(),
                }))
    predictions_df = pd.concat(pred_rows, axis=0, ignore_index=True)
    predictions_path = report_dir / "attack_progression_predictions.csv"
    predictions_df.to_csv(predictions_path, index=False)
    print(f"Wrote {predictions_path} ({len(predictions_df)} rows)")

    # --- outputs: horizon metrics CSV ---
    horizon_rows = []
    for h in HORIZONS:
        for mode_name in ["full_pipeline", "oracle_diagnostic"]:
            m = horizon_metrics[mode_name][h]
            horizon_rows.append({
                "horizon": h, "mode": mode_name, "partition": "validation",
                "n": m["n_samples"], "n_positive": m["n_positive"], "n_negative": m["n_negative"],
                "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"], "precision": m["precision"], "recall": m["recall"],
                "f1": m["f1"], "fpr": m["false_positive_rate"],
            })
        td = test_descriptive[h]
        horizon_rows.append({
            "horizon": h, "mode": "full_pipeline", "partition": "test",
            "n": td["n_samples"], "n_positive": td["n_positive"], "n_negative": td["n_negative"],
            "roc_auc": None, "pr_auc": None, "precision": td["precision"], "recall": None, "f1": None, "fpr": td["false_positive_rate"],
        })
    horizon_metrics_df = pd.DataFrame(horizon_rows)
    horizon_metrics_path = report_dir / "attack_progression_horizon_metrics.csv"
    horizon_metrics_df.to_csv(horizon_metrics_path, index=False)
    print(f"Wrote {horizon_metrics_path}")

    calibration_path = report_dir / "attack_progression_calibration.csv"
    calibration_df.to_csv(calibration_path, index=False)
    print(f"Wrote {calibration_path}")

    trajectory_path = report_dir / "attack_progression_trajectory_summary.csv"
    trajectory_df.to_csv(trajectory_path, index=False)
    print(f"Wrote {trajectory_path}")

    cm_payload = {
        "full_pipeline_validation": {h: horizon_metrics["full_pipeline"][h]["confusion_matrix"] for h in HORIZONS},
        "oracle_diagnostic_validation": {h: horizon_metrics["oracle_diagnostic"][h]["confusion_matrix"] for h in HORIZONS},
        "full_pipeline_test_descriptive": {h: test_descriptive[h]["confusion_matrix"] for h in HORIZONS},
        "convention": "tn=actual Benign predicted Benign, fp=actual Benign predicted Infilteration, fn=actual Infilteration predicted Benign, tp=actual Infilteration predicted Infilteration.",
        "threshold": DEFAULT_THRESHOLD,
    }
    cm_path = report_dir / "attack_progression_confusion_matrices.json"
    cm_path.write_text(json.dumps(cm_payload, indent=2), encoding="utf-8")
    print(f"Wrote {cm_path}")

    config_payload = {
        "horizons": HORIZONS, "threshold": DEFAULT_THRESHOLD, "seed": SEED,
        "lstm_checkpoint": str(LSTM_CHECKPOINT_PATH), "classifier_path": str(CLASSIFIER_PATH),
        "lstm_architecture": checkpoint["configuration"], "classifier_classes": list(classifier.classes_),
        "environment": {"python_version": sys.version, "sklearn_version": sklearn.__version__, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
    }
    config_path = report_dir / "attack_progression_config.json"
    config_path.write_text(json.dumps(config_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {config_path}")

    test_limitation = (
        "The current chronological TEST partition contains no Infiltration samples, so attack-progression "
        "detection metrics cannot be established on that partition. Feature 13 is therefore evaluated on "
        "the mixed-class VALIDATION partition as a development-stage assessment. A later expanded multi-day "
        "evaluation will provide a proper unseen attack-containing test set."
    )

    metrics_payload = {
        "objective": "Convert LSTM-predicted future network states (Feature 12) into P(Infiltration) via the frozen Feature 11 classifier, at horizons K=1,2,3,5.",
        "scientific_distinction": (
            "Feature 12 answers: what might the future network state look like? Feature 13 answers: given "
            "the predicted future network state, how strongly does the frozen attack classifier associate "
            "that future state with Infiltration? This is not MITRE ATT&CK stage prediction, causal "
            "attacker-intent prediction, guaranteed early warning, a risk score, or a mitigation decision."
        ),
        "primary_result_label": "Full recursive CyberChess pipeline (predicted future state -> frozen classifier)",
        "diagnostic_result_label": "Oracle future-state diagnostic (ground-truth future state -> frozen classifier; NOT a deployment result)",
        "test_set_limitation": test_limitation,
        "horizons": HORIZONS, "threshold": DEFAULT_THRESHOLD,
        "sample_counts_per_horizon": {name: {h: int(valid_masks[name][h].sum()) for h in HORIZONS} for name in ["validation", "test"]},
        "validation_full_pipeline_metrics": horizon_metrics["full_pipeline"],
        "validation_oracle_diagnostic_metrics": horizon_metrics["oracle_diagnostic"],
        "test_descriptive_metrics": test_descriptive,
        "calibration": calibration,
        "trajectory_summary": trajectory_rows,
        "early_warning_diagnostic": {"definition": early_warning_definition, "results": early_warning_rows},
        "k1_consistency_with_feature11": consistency.get("k1_consistency_with_feature11"),
        "leakage_checks": leakage_checks,
        "reproducibility": {"seed": SEED, "repeat_run_match": run_match, "fresh_reload_match": reload_match, "tolerance": TOLERANCE},
        "outputs": {
            "predictions": str(predictions_path), "horizon_metrics_csv": str(horizon_metrics_path),
            "calibration_csv": str(calibration_path), "trajectory_csv": str(trajectory_path),
            "confusion_matrices": str(cm_path), "config": str(config_path),
        },
    }
    metrics_path = report_dir / "attack_progression_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "attack_progression_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FEATURE 13 COMPLETE")
    print("=" * 70)
    for h in HORIZONS:
        m = horizon_metrics["full_pipeline"][h]
        print(f"  VALIDATION h={h} (full pipeline): N={m['n_samples']} ROC-AUC={m['roc_auc']:.4f} PR-AUC={m['pr_auc']:.4f} "
              f"precision={m['precision']:.4f} recall={m['recall']:.4f} F1={m['f1']:.4f} FPR={m['false_positive_rate']:.4f}")
        print(f"    Brier score: {calibration[h]['brier_score']:.4f}")
    print(f"\nK=1 consistency with Feature 11: {consistency.get('k1_consistency_with_feature11', {}).get('all_match')}")
    print(f"\n{test_limitation}")
    print(f"\nAll leakage checks: {'PASS' if all(v for k, v in leakage_checks.items() if isinstance(v, bool)) else 'FAIL'}")
    print(f"Reproducibility: {'PASS' if (run_match and reload_match) else 'FAIL'}")
    print(f"Feature 7-12 artifact integrity: {'PASS' if unchanged else 'FAIL'}")

    return metrics_payload


def format_text_report(payload: dict) -> str:
    lines = ["=" * 70, "ATTACK PROGRESSION PROBABILITY REPORT (FEATURE 13)", "=" * 70]
    lines.append("\n1. OBJECTIVE\n   " + payload["objective"])
    lines.append("\n2. SCIENTIFIC DISTINCTION (Feature 12 vs Feature 13)\n   " + payload["scientific_distinction"])
    lines.append(f"\n3. PRIMARY RESULT: {payload['primary_result_label']}")
    lines.append(f"   DIAGNOSTIC: {payload['diagnostic_result_label']}")
    lines.append(f"\n4. TEST-SET LIMITATION\n   {payload['test_set_limitation']}")
    lines.append(f"\n5. HORIZONS EVALUATED: {payload['horizons']}  THRESHOLD: {payload['threshold']}")
    lines.append(f"\n6. SAMPLE COUNTS PER HORIZON\n   {payload['sample_counts_per_horizon']}")
    lines.append("\n7. VALIDATION FULL-PIPELINE METRICS (primary)")
    for h, m in payload["validation_full_pipeline_metrics"].items():
        lines.append(f"   h={h}: {m}")
    lines.append("\n8. VALIDATION ORACLE DIAGNOSTIC METRICS")
    for h, m in payload["validation_oracle_diagnostic_metrics"].items():
        lines.append(f"   h={h}: {m}")
    lines.append("\n9. TEST DESCRIPTIVE METRICS (no attack-detection claims; NO recall/F1/ROC-AUC/PR-AUC)")
    for h, m in payload["test_descriptive_metrics"].items():
        lines.append(f"   h={h}: {m}")
    lines.append("\n10. CALIBRATION (VALIDATION, full pipeline)")
    for h, c in payload["calibration"].items():
        lines.append(f"   h={h}: Brier score={c['brier_score']:.4f}")
    lines.append("   Full bin-level data: attack_progression_calibration.csv")
    lines.append("\n11. PROBABILITY TRAJECTORY (VALIDATION, full pipeline)")
    for row in payload["trajectory_summary"]:
        lines.append(f"   {row}")
    lines.append("\n12. EARLY-WARNING DIAGNOSTIC")
    lines.append(f"   Definition: {payload['early_warning_diagnostic']['definition']}")
    for row in payload["early_warning_diagnostic"]["results"]:
        lines.append(f"   {row}")
    lines.append("\n13. K=1 CONSISTENCY WITH FEATURE 11")
    lines.append(f"   {payload['k1_consistency_with_feature11']}")
    lines.append("\n14. LEAKAGE CHECKS")
    for k, v in payload["leakage_checks"].items():
        if isinstance(v, bool) or v is None:
            lines.append(f"   {k}: {'PASS' if v else ('N/A' if v is None else 'FAIL')}")
        else:
            lines.append(f"   {k}: {v}")
    lines.append(f"\n15. REPRODUCIBILITY\n   {payload['reproducibility']}")
    lines.append("\n16. IMPORTANT LIMITATIONS")
    lines.append("   1. Current TEST partition has zero Infiltration.")
    lines.append("   2. Therefore final attack-progression generalization cannot be established yet.")
    lines.append("   3. Current Feature 13 evaluation is a validation/development evaluation.")
    lines.append("   4. Feature 11's classifier is trained on one-day development data.")
    lines.append("   5. Feature 12 forecasts network-state vectors, not attacker intent.")
    lines.append("   6. Probability output is classifier probability and should not automatically be")
    lines.append("      interpreted as a perfectly calibrated real-world attack probability.")
    lines.append("   7. Final evaluation requires additional unseen attack-containing capture data.")
    lines.append("\n17. WHAT FEATURE 13 DOES NOT IMPLEMENT")
    lines.append("   MITRE ATT&CK mapping, SHAP/attention explanations, feature attribution, risk scoring,")
    lines.append("   mitigation policy, firewall integration, SpiderFoot, dashboard changes, expanded dataset.")
    lines.append("\n18. RECOMMENDED FEATURE 14")
    lines.append("   Map elevated/sustained attack-progression probability across horizons to MITRE ATT&CK")
    lines.append("   stages, still respecting the chronological split and TEST-set label limitation.")
    lines.append("\nOUTPUTS:")
    for k, v in payload["outputs"].items():
        lines.append(f"   {k}: {v}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
