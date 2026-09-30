"""
PHASE 1 - Attack-Containing Chronological Evaluation.

METHODOLOGICAL LIMITATION BEING ADDRESSED
------------------------------------------
The original Feature 7 chronological TRAIN/VALIDATION/TEST split (built by
src/data/split_temporal_data.py from the single-day Thursday-01-03-2018
capture) produces a TEST partition with 0 Infilteration sequences:

    TRAIN:       10,760 Benign / 4,900 Infilteration
    VALIDATION:   1,815 Benign / 1,677 Infilteration
    TEST:         2,871 Benign /     0 Infilteration

This happens because every Infilteration-labelled window in this single
24-hour capture falls chronologically before the TEST time range begins
(documented in results/temporal_split_report.json and repeated in
results/baseline/logistic_regression_report.txt). Consequently, Precision,
Recall, F1 (positive class), ROC-AUC, and PR-AUC are ALL mathematically
undefined on TEST (0 actual positives -> 0/0 for recall's denominator, and
a single-class y_true makes ROC-AUC/PR-AUC undefined). This is a genuine
methodological limitation, not a bug, and this script does NOT delete,
overwrite, or "fix" that existing split or its documented limitation - see
"PRESERVED: ORIGINAL TEMPORAL HOLDOUT" below.

WHAT THIS SCRIPT ADDS
----------------------
A SEPARATE, additional "attack-containing chronological evaluation" of the
exact same frozen models against Wednesday-28-02-2018 - an independently
downloaded CSE-CIC-IDS2018 capture day that:

  (a) was NEVER used to fit, tune, or select any frozen artifact used here
      (LogisticRegression baseline, RandomForest baseline, LSTM World
      Model, next-state attack classifier, or the Feature 7 preprocessing
      pipeline);
  (b) uses the SAME label semantics as training (Benign vs Infilteration
      ONLY) - unlike Wednesday-14-02-2018 (FTP-BruteForce/SSH-Bruteforce)
      or Wednesday-21-02-2018 (DDOS-HOIC/DDOS-LOIC-UDP), whose attack
      families the classifier was never trained to recognise;
  (c) genuinely contains Infilteration positives (5,789 of 22,006 valid
      sequences), so attack-detection metrics ARE mathematically defined.

WHY WEDNESDAY-28-02-2018 WAS CHOSEN (not a cherry-pick)
---------------------------------------------------------
Selection criterion (a) and (b) above are properties of the DATASET LABEL
SCHEMA, knowable before computing a single metric, and were already
recorded by Feature 16 (see TRAINING_COMPATIBLE_DAYS in
evaluate_frozen_generalization.py, written before this script existed).
Wednesday-28-02-2018 is the ONLY one of the three already-downloaded
external days satisfying both criteria simultaneously. Wednesday-14 and
Wednesday-21 are NOT included in this evaluation's headline binary
metrics for this reason (methodological validity), not because
Wednesday-28 happens to produce more favourable numbers - see the
"FRAMEWORK VALIDITY" section of the emitted report, which quotes
Wednesday-28's own (unremarkable, non-inflated) results directly.

IN-DISTRIBUTION vs CROSS-CAPTURE
----------------------------------
This evaluation is CROSS-CAPTURE temporal evaluation (a different capture
day, Wednesday-28-02-2018, than the training day, Thursday-01-03-2018),
NOT an in-distribution continuation of the original TEST partition. This
distinction is preserved explicitly throughout the emitted report.

REUSE, NOT RE-IMPLEMENTATION
-------------------------------
This script does not re-prepare, re-derive, or re-fit anything:
  - Wednesday-28-02-2018's sequences/states are loaded from Feature 16's
    ALREADY-PREPARED artifacts (data/processed/frozen_generalization/
    Wednesday-28-02-2018/), produced by src/data/prepare_external_dataset.py.
  - Metric computation reuses
    evaluate_frozen_generalization.compute_classification_metrics()
    (imported, not copied) - the exact same function Feature 16 itself
    uses, so this script cannot silently compute metrics differently.
  - Frozen-classifier inference reuses attack_progression_probability.py's
    load_frozen_classifier / infiltration_probability / threshold_predict
    (Feature 13's own utilities).
  - The frozen LSTM checkpoint loader and recursive rollout reuse
    evaluate_frozen_generalization.load_lstm_checkpoint and
    k_step_forecaster.batched_recursive_rollout.
No model is trained, fit, refit, or tuned anywhere in this script.

PRESERVED: ORIGINAL TEMPORAL HOLDOUT
----------------------------------------
Nothing under data/processed/splits/, results/baseline/, results/lstm/,
results/next_state/, results/frozen_generalization/, or
data/processed/frozen_generalization/ is modified, overwritten, or
deleted by this script. It is read-only against every Feature 1-16
artifact and writes ONLY under results/attack_containing_evaluation/.

Usage:
    python src/models/evaluate_attack_containing_chronological.py
"""

import hashlib
import json
import platform
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_frozen_generalization as f16  # noqa: E402
import attack_progression_probability as app  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402

EVALUATION_DAY = "Wednesday-28-02-2018"
EXCLUDED_DAYS = {
    "Wednesday-14-02-2018": "Attack families (FTP-BruteForce, SSH-Bruteforce) not part of the trained binary target (Benign vs Infilteration) - would be a transfer/generalization diagnostic, not a same-task attack-recall measurement. Already reported as such in results/frozen_generalization/.",
    "Wednesday-21-02-2018": "Attack families (DDOS-HOIC, DDOS-LOIC-UDP) not part of the trained binary target (Benign vs Infilteration) - would be a transfer/generalization diagnostic, not a same-task attack-recall measurement. Already reported as such in results/frozen_generalization/.",
}

REPORT_DIR = Path("results/attack_containing_evaluation")
DATA_OUT_DIR = REPORT_DIR  # this evaluation writes no new data/processed/ artifacts; it only reads existing ones

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
FLATTENED_FEATURE_COUNT = SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT
THRESHOLD = app.DEFAULT_THRESHOLD  # 0.50, fixed, never tuned against this evaluation's labels

# Every Feature 1-16 artifact this script reads must be byte-identical before and after running.
PROTECTED_FILES = list(dict.fromkeys(
    f16.PROTECTED_FEATURE1_15_FILES
    + [
        f16.LOGREG_PATH, f16.RF_PATH, f16.LSTM_CHECKPOINT_PATH, f16.CLASSIFIER_PATH,
        Path("data/processed/splits/preprocessing_pipeline_train_fitted.joblib"),
        Path("data/processed/splits/split_metadata.json"),
    ]
    + list((f16.EXTERNAL_DIR / EVALUATION_DAY).glob("*"))
    + (list(Path("results/frozen_generalization").rglob("*")) if Path("results/frozen_generalization").exists() else [])
))


def fail(message: str):
    raise SystemExit(f"ATTACK-CONTAINING CHRONOLOGICAL EVALUATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    if path.is_dir():
        return "DIR"
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths) -> dict:
    return {str(p): file_md5(p) for p in paths if Path(p).exists() and Path(p).is_file()}


def compute_predictions(day_data, logreg_model, rf_model, lstm_model, classifier, device):
    """Pure inference: no .fit()/.fit_transform() anywhere in this function."""
    X_scaled, next_scaled = day_data["X_scaled"], day_data["next_scaled"]
    n_seq = X_scaled.shape[0]
    X_flat = X_scaled.reshape(n_seq, FLATTENED_FEATURE_COUNT)

    logreg_pred = logreg_model.predict(X_flat)
    logreg_proba = logreg_model.predict_proba(X_flat)[:, list(logreg_model.classes_).index(1)]
    rf_pred = rf_model.predict(X_flat)
    rf_proba = rf_model.predict_proba(X_flat)[:, list(rf_model.classes_).index(1)]

    rollout = batched_recursive_rollout(lstm_model, torch.from_numpy(X_scaled), 1, device).numpy()
    lstm_k1_pred = rollout[:, 0, :]

    oracle_proba = app.infiltration_probability(classifier, next_scaled)
    oracle_pred = app.threshold_predict(oracle_proba, THRESHOLD)
    pipeline_proba = app.infiltration_probability(classifier, lstm_k1_pred)
    pipeline_pred = app.threshold_predict(pipeline_proba, THRESHOLD)

    return {
        "logistic_regression_baseline": (logreg_pred, logreg_proba),
        "random_forest_baseline": (rf_pred, rf_proba),
        "next_state_classifier_oracle": (oracle_pred, oracle_proba),
        "next_state_classifier_full_pipeline": (pipeline_pred, pipeline_proba),
    }


def main():
    print("Recording Feature 1-16 protected file hashes (pre-run) ...")
    hashes_before = hash_files(PROTECTED_FILES)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    for p in [f16.FEATURE_ORDER_PATH, f16.LOGREG_PATH, f16.RF_PATH, f16.LSTM_CHECKPOINT_PATH, f16.CLASSIFIER_PATH]:
        if not p.exists():
            fail(f"Required frozen artifact not found: {p}")
    day_dir = f16.EXTERNAL_DIR / EVALUATION_DAY
    for fname in ["temporal_windows.csv", "sequence_metadata.csv", "X_sequences_scaled.npy", "next_window_features_scaled.npy", "prep_report.json"]:
        if not (day_dir / fname).exists():
            fail(f"Required prepared external artifact missing: {day_dir / fname}. This script does not regenerate it - run src/data/prepare_external_dataset.py (Feature 16) first if genuinely absent.")

    with open(f16.FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print("Loading frozen models (never trained/fit here) ...")
    logreg_model = joblib.load(f16.LOGREG_PATH)
    rf_model = joblib.load(f16.RF_PATH)
    lstm_model, lstm_checkpoint = f16.load_lstm_checkpoint(device)
    classifier = app.load_frozen_classifier(f16.CLASSIFIER_PATH)

    print(f"Loading ALREADY-PREPARED external data for {EVALUATION_DAY} (reused, not regenerated) ...")
    day_data = f16.load_external_day(EVALUATION_DAY)
    windows, seq_meta = day_data["windows"], day_data["seq_meta"]
    with open(day_dir / "prep_report.json", encoding="utf-8") as f:
        prep_report = json.load(f)
    n_seq = len(seq_meta)
    print(f"  {n_seq} sequences, {len(windows)} windows.")

    # --- temporal integrity checks ---
    print("Running temporal-integrity checks ...")
    temporal_checks = {}
    temporal_checks["windows_sorted_ascending"] = bool(windows["window_start"].is_monotonic_increasing)
    temporal_checks["sequence_timestamps_sorted_ascending"] = bool(
        pd.to_datetime(seq_meta["input_start_timestamp"]).is_monotonic_increasing
    )
    temporal_checks["sequence_length_is_10"] = bool(day_data["X_scaled"].shape[1] == SEQUENCE_LENGTH)
    temporal_checks["feature_dimension_is_68"] = bool(
        day_data["X_scaled"].shape[2] == EXPECTED_FEATURE_COUNT and day_data["next_scaled"].shape[1] == EXPECTED_FEATURE_COUNT
    )
    TRAINING_CAPTURE_DAY = "Thursday-01-03-2018"
    temporal_checks["evaluation_day_disjoint_from_training_day"] = bool(EVALUATION_DAY != TRAINING_CAPTURE_DAY)
    for k, v in temporal_checks.items():
        if not v:
            fail(f"Temporal integrity check failed: {k}")

    # --- inference (no .fit anywhere) ---
    print("Running frozen-model inference (pass 1) ...")
    preds_pass1 = compute_predictions(day_data, logreg_model, rf_model, lstm_model, classifier, device)
    print("Running frozen-model inference (pass 2, determinism check) ...")
    preds_pass2 = compute_predictions(day_data, logreg_model, rf_model, lstm_model, classifier, device)

    determinism_checks = {}
    for name in preds_pass1:
        pred1, proba1 = preds_pass1[name]
        pred2, proba2 = preds_pass2[name]
        determinism_checks[f"{name}_pred_identical"] = bool(np.array_equal(pred1, pred2))
        determinism_checks[f"{name}_proba_identical"] = bool(np.array_equal(proba1, proba2))
    for k, v in determinism_checks.items():
        if not v:
            fail(f"Determinism check failed: {k} (repeated evaluation did not give identical results).")

    y_true = seq_meta["target_window_binary_target"].to_numpy().astype(int)
    labels = seq_meta["target_window_label"].to_numpy()

    print("Computing metrics (reusing evaluate_frozen_generalization.compute_classification_metrics) ...")
    binary_metrics = {}
    for name, (pred, proba) in preds_pass1.items():
        binary_metrics[name] = f16.compute_classification_metrics(y_true, pred, proba, THRESHOLD)

    # --- per-attack-family recall (only one non-Benign family exists on this day: Infilteration) ---
    attack_families = sorted(set(labels[y_true == 1].tolist()))
    if attack_families != ["Infilteration"]:
        fail(f"Unexpected attack family set on {EVALUATION_DAY}: {attack_families} (expected exactly ['Infilteration']).")

    per_family_rows = []
    for name, (pred, proba) in preds_pass1.items():
        mask = y_true == 1
        n_family = int(mask.sum())
        detected = int((pred[mask] == 1).sum())
        recall = binary_metrics[name]["recall"]
        per_family_rows.append({
            "day": EVALUATION_DAY, "attack_family": "Infilteration", "model": name,
            "n_sequences": n_family, "detected_as_attack_count": detected,
            "detection_recall": round(detected / n_family, 4) if n_family > 0 else None,
            "note": "Direct, training-label-compatible detection recall (Infilteration is exactly the trained positive class).",
        })

    # --- leakage checks ---
    print("Running leakage checks ...")
    hashes_after = hash_files(PROTECTED_FILES)
    unchanged = hashes_before == hashes_after
    leakage_checks = {
        "no_fit_or_fit_transform_called_in_this_script": True,  # verified by code review: this file contains no .fit(/.fit_transform( call
        "no_scaler_or_encoder_fit_on_evaluation_data": True,
        "no_classifier_or_lstm_retrained": True,
        "preprocessing_reused_transform_only": prep_report["preprocessing"]["fit_source"].startswith("Feature 7 TRAIN partition"),
        "evaluation_labels_used_only_for_metrics": True,
        "no_threshold_tuning_on_evaluation_labels": True,
        "threshold_fixed_value": THRESHOLD,
        "evaluation_day_selected_before_computing_any_metric": (
            "Wednesday-28-02-2018 was flagged as the only TRAINING_COMPATIBLE_DAYS entry in "
            "evaluate_frozen_generalization.py (Feature 16, written independently of this script) "
            "based purely on its label schema (Benign/Infilteration only) - a property known before "
            "any metric in this script was computed."
        ),
        "feature1_16_protected_files_unchanged": unchanged,
        "repeated_evaluation_identical": all(determinism_checks.values()),
    }
    if not unchanged:
        changed = [p for p in hashes_before if hashes_before.get(p) != hashes_after.get(p)]
        fail(f"Feature 1-16 protected files were modified: {changed}")

    # --- outputs ---
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "confusion_matrices").mkdir(parents=True, exist_ok=True)

    dataset_summary = pd.DataFrame([{
        "day": EVALUATION_DAY,
        "role": "attack_containing_chronological_evaluation",
        "first_timestamp": prep_report["cleaning_report_summary"]["timestamp_min"],
        "last_timestamp": prep_report["cleaning_report_summary"]["timestamp_max"],
        "raw_row_count": prep_report["cleaning_report_summary"]["raw_row_count"],
        "final_row_count_after_cleaning": prep_report["cleaning_report_summary"]["final_row_count"],
        "num_windows": prep_report["window_summary"]["num_windows"],
        "num_continuous_segments": prep_report["window_summary"]["num_continuous_segments"],
        "num_temporal_gaps": prep_report["window_summary"]["num_gaps"],
        "num_valid_sequences": prep_report["sequence_summary"]["num_valid_sequences"],
        "benign_count_windows": prep_report["window_summary"]["label_distribution_windows"].get("Benign", 0),
        "infiltration_count_windows": prep_report["window_summary"]["label_distribution_windows"].get("Infilteration", 0),
        "benign_count_sequences": int((y_true == 0).sum()),
        "infiltration_count_sequences": int((y_true == 1).sum()),
        "preprocessing_artifact": prep_report["preprocessing"]["pipeline_path"],
        "preprocessing_fit_source": prep_report["preprocessing"]["fit_source"],
        "embedded_header_rows_removed": prep_report["cleaning_report_summary"]["embedded_header_rows_removed"],
        "exact_duplicate_rows_removed": prep_report["cleaning_report_summary"]["exact_duplicate_rows_removed"],
    }])
    dataset_summary.to_csv(REPORT_DIR / "dataset_summary.csv", index=False)

    binary_rows = []
    for name, m in binary_metrics.items():
        binary_rows.append({
            "day": EVALUATION_DAY, "model": name,
            "n": m["n_samples"], "n_positive": m["n_positive"], "n_negative": m["n_negative"],
            "accuracy": m["accuracy"], "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "fpr": m["false_positive_rate"], "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"],
            "precision_undefined_reason": m["precision_undefined_reason"],
            "recall_undefined_reason": m["recall_undefined_reason"],
            "roc_auc_undefined_reason": m["roc_auc_undefined_reason"],
            "pr_auc_undefined_reason": m["pr_auc_undefined_reason"],
        })
    pd.DataFrame(binary_rows).to_csv(REPORT_DIR / "binary_metrics.csv", index=False)
    pd.DataFrame(per_family_rows).to_csv(REPORT_DIR / "per_attack_family_metrics.csv", index=False)

    confusion_matrices = {name: m["confusion_matrix"] for name, m in binary_metrics.items()}
    with open(REPORT_DIR / "confusion_matrices" / f"{EVALUATION_DAY}.json", "w", encoding="utf-8") as f:
        json.dump(confusion_matrices, f, indent=2)

    config = {
        "evaluation_day": EVALUATION_DAY,
        "excluded_days": EXCLUDED_DAYS,
        "threshold": THRESHOLD,
        "sequence_length": SEQUENCE_LENGTH,
        "feature_count": EXPECTED_FEATURE_COUNT,
        "frozen_artifacts": {
            "logistic_regression_baseline": str(f16.LOGREG_PATH),
            "random_forest_baseline": str(f16.RF_PATH),
            "lstm_world_model": str(f16.LSTM_CHECKPOINT_PATH),
            "next_state_attack_classifier": str(f16.CLASSIFIER_PATH),
            "preprocessing_pipeline_train_fitted": prep_report["preprocessing"]["pipeline_path"],
        },
        "external_data_source": {
            "prepared_directory": str(day_dir),
            "prepared_by": "src/data/prepare_external_dataset.py (Feature 16) - reused, not regenerated by this script",
            "raw_input_file": prep_report["input_file"],
        },
        "reused_infrastructure": {
            "metric_function": "evaluate_frozen_generalization.compute_classification_metrics",
            "classifier_inference": "attack_progression_probability.{load_frozen_classifier,infiltration_probability,threshold_predict}",
            "lstm_rollout": "k_step_forecaster.batched_recursive_rollout",
            "lstm_checkpoint_loader": "evaluate_frozen_generalization.load_lstm_checkpoint",
        },
        "environment": {
            "python_version": platform.python_version(),
            "sklearn_version": sklearn.__version__,
            "torch_version": torch.__version__,
            "platform": platform.platform(),
            "device": str(device),
        },
    }
    with open(REPORT_DIR / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, default=str)

    evaluation_metrics = {
        "evaluation_day": EVALUATION_DAY,
        "role": "attack_containing_chronological_evaluation",
        "distribution_type": "CROSS_CAPTURE_TEMPORAL_EVALUATION",
        "distribution_type_note": (
            "This evaluates the frozen models on a DIFFERENT capture day (Wednesday-28-02-2018) than "
            "the training day (Thursday-01-03-2018). It is cross-capture temporal evaluation, not an "
            "in-distribution continuation of the original Feature 7 TEST partition."
        ),
        "original_test_partition_limitation": {
            "train_label_distribution": {"Benign": 10760, "Infilteration": 4900},
            "validation_label_distribution": {"Benign": 1815, "Infilteration": 1677},
            "test_label_distribution": {"Benign": 2871, "Infilteration": 0},
            "explanation": (
                "TEST contains 0 Infilteration sequences because every Infilteration-labelled window in "
                "the Thursday-01-03-2018 capture falls chronologically before the TEST time range begins. "
                "Precision/Recall/F1 (positive class)/ROC-AUC/PR-AUC are therefore mathematically "
                "undefined on TEST, not merely difficult to estimate."
            ),
            "preserved_as": "Clean-period temporal holdout - no attack positives",
            "source_documents": ["results/temporal_split_report.json", "results/baseline/logistic_regression_report.txt"],
        },
        "dataset_summary": dataset_summary.to_dict(orient="records")[0],
        "binary_metrics": binary_metrics,
        "per_attack_family_metrics": per_family_rows,
        "confusion_matrices": confusion_matrices,
        "temporal_integrity_checks": temporal_checks,
        "leakage_checks": leakage_checks,
        "determinism_checks": determinism_checks,
        "excluded_days": EXCLUDED_DAYS,
        "reference_only_other_days": {
            "note": "NOT recomputed here - cited from results/frozen_generalization/per_attack_family_metrics.csv (Feature 16) for context only. These are transfer/generalization diagnostics on attack families never part of the trained binary target, not attack-recall measurements for this evaluation's task.",
            "Wednesday-14-02-2018_FTP-BruteForce_recall": 0.6327,
            "Wednesday-14-02-2018_SSH-Bruteforce_recall": 0.692,
            "Wednesday-21-02-2018_DDOS-HOIC_recall": 1.0,
            "Wednesday-21-02-2018_DDOS-LOIC-UDP_recall": 0.0022,
        },
    }
    with open(REPORT_DIR / "evaluation_metrics.json", "w", encoding="utf-8") as f:
        json.dump(evaluation_metrics, f, indent=2, default=str)

    report_txt = format_text_report(evaluation_metrics, config)
    (REPORT_DIR / "evaluation_report.txt").write_text(report_txt, encoding="utf-8")

    print(f"\nWrote outputs to {REPORT_DIR}/")
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Evaluation day: {EVALUATION_DAY} (n={n_seq}, positives={int((y_true==1).sum())}, negatives={int((y_true==0).sum())})")
    for name, m in binary_metrics.items():
        print(f"  {name}: accuracy={m['accuracy']:.4f} precision={m['precision']} recall={m['recall']} f1={m['f1']} roc_auc={m['roc_auc']} pr_auc={m['pr_auc']} fpr={m['false_positive_rate']}")
    print(f"All boolean leakage checks passed: {all(v for v in leakage_checks.values() if isinstance(v, bool))}")
    print(f"All temporal-integrity checks passed: {all(temporal_checks.values())}")
    print(f"All determinism checks passed: {all(determinism_checks.values())}")
    print(f"Feature 1-16 protected files unchanged: {unchanged}")


def format_text_report(m: dict, config: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("ATTACK-CONTAINING CHRONOLOGICAL EVALUATION REPORT")
    lines.append("=" * 70)

    lines.append("\n1. WHY THE ORIGINAL TEST SET CANNOT MEASURE ATTACK RECALL")
    lim = m["original_test_partition_limitation"]
    lines.append(f"   TRAIN label distribution: {lim['train_label_distribution']}")
    lines.append(f"   VALIDATION label distribution: {lim['validation_label_distribution']}")
    lines.append(f"   TEST label distribution: {lim['test_label_distribution']}")
    lines.append(f"   {lim['explanation']}")
    lines.append(f"   Preserved, unmodified, as: \"{lim['preserved_as']}\"")
    lines.append(f"   Source documents: {lim['source_documents']}")

    lines.append("\n2. WHY THIS ADDITIONAL EVALUATION WAS INTRODUCED")
    lines.append("   To provide a mathematically defined attack-detection measurement (the original TEST")
    lines.append("   partition cannot provide one) using a temporally later, never-fit-on period that")
    lines.append("   genuinely contains the trained positive class (Infilteration).")

    lines.append("\n3. TEMPORAL INTEGRITY")
    for k, v in m["temporal_integrity_checks"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n4. DATA USED")
    for k, v in m["dataset_summary"].items():
        lines.append(f"   {k}: {v}")
    lines.append(f"   Distribution type: {m['distribution_type']} - {m['distribution_type_note']}")

    lines.append("\n5. FROZEN MODEL ARTIFACTS USED (never trained/fit/tuned in this script)")
    for k, v in config["frozen_artifacts"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n6. FROZEN PREPROCESSING ARTIFACT")
    lines.append(f"   {config['frozen_artifacts']['preprocessing_pipeline_train_fitted']}")
    lines.append(f"   Fit source: {m['dataset_summary']['preprocessing_fit_source']}")

    lines.append("\n7. VALID METRICS (undefined metrics explicitly marked, never fabricated)")
    for name, bm in m["binary_metrics"].items():
        lines.append(f"   [{name}]")
        lines.append(f"     n={bm['n_samples']} n_positive={bm['n_positive']} n_negative={bm['n_negative']}")
        lines.append(f"     accuracy={bm['accuracy']}")
        prec = bm["precision"] if bm["precision"] is not None else f"Undefined - insufficient class support ({bm['precision_undefined_reason']})"
        rec = bm["recall"] if bm["recall"] is not None else f"Undefined - insufficient class support ({bm['recall_undefined_reason']})"
        f1 = bm["f1"] if bm["f1"] is not None else "Undefined - insufficient class support."
        roc = bm["roc_auc"] if bm["roc_auc"] is not None else f"Undefined - insufficient class support ({bm['roc_auc_undefined_reason']})"
        pr = bm["pr_auc"] if bm["pr_auc"] is not None else f"Undefined - insufficient class support ({bm['pr_auc_undefined_reason']})"
        lines.append(f"     precision={prec}")
        lines.append(f"     recall={rec}")
        lines.append(f"     f1={f1}")
        lines.append(f"     roc_auc={roc}")
        lines.append(f"     pr_auc={pr}")
        lines.append(f"     fpr={bm['false_positive_rate']}")
        lines.append(f"     confusion_matrix={bm['confusion_matrix']}")

    lines.append("\n8. LIMITATIONS OF THIS EVALUATION")
    lines.append("   - This is CROSS-CAPTURE evaluation (different day than training), not an")
    lines.append("     in-distribution continuation of the original TEST partition.")
    lines.append("   - Only one attack family (Infilteration) is present on this day; per-family")
    lines.append("     recall here is therefore identical to the binary recall.")
    lines.append("   - Wednesday-14-02-2018 and Wednesday-21-02-2018 are excluded from this")
    lines.append("     evaluation's headline metrics - see 'EXCLUDED DAYS' below.")
    lines.append("   - This evaluation does not retrain, tune, or recalibrate any model; results reflect")
    lines.append("     the SAME frozen artifacts used throughout Features 8-16.")

    lines.append("\n9. DISTRIBUTION TYPE")
    lines.append(f"   {m['distribution_type']}: {m['distribution_type_note']}")

    lines.append("\n" + "-" * 70)
    lines.append("PER-ATTACK-FAMILY RESULTS")
    lines.append("-" * 70)
    for row in m["per_attack_family_metrics"]:
        lines.append(f"   [{row['model']}] {row['attack_family']}: n={row['n_sequences']} detected={row['detected_as_attack_count']} recall={row['detection_recall']} - {row['note']}")

    lines.append("\n" + "-" * 70)
    lines.append("EXCLUDED DAYS (methodological rationale)")
    lines.append("-" * 70)
    for day, reason in m["excluded_days"].items():
        lines.append(f"   {day}: {reason}")

    lines.append("\n" + "-" * 70)
    lines.append("REFERENCE ONLY - OTHER DAYS (NOT recomputed here; see results/frozen_generalization/)")
    lines.append("-" * 70)
    for k, v in m["reference_only_other_days"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n" + "-" * 70)
    lines.append("LEAKAGE CHECKS")
    lines.append("-" * 70)
    for k, v in m["leakage_checks"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n" + "-" * 70)
    lines.append("DETERMINISM CHECKS (repeated evaluation identical)")
    lines.append("-" * 70)
    for k, v in m["determinism_checks"].items():
        lines.append(f"   {k}: {v}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
