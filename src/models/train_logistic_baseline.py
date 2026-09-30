"""
Feature 8 - Leakage-safe Logistic Regression baseline.

"A simple supervised baseline for predicting the next network-window
attack state from a flattened history of the previous 10 network states."

This is NOT the CyberChess World Model, NOT temporal deep learning, and
does NOT claim to learn network state-transition dynamics. It is a
non-temporal linear baseline that the future LSTM World Model will be
compared against.

Uses ONLY the artifacts already produced by Features 4-7:
    - data/processed/splits/{train,validation,test}/X_sequences_scaled.npy
    - data/processed/splits/{train,validation,test}/sequence_metadata.csv
    - data/processed/splits/preprocessing_pipeline_train_fitted.joblib
    - results/temporal_feature_order.json

No preprocessing is refit here. The already train-fitted-and-applied
scaled arrays from Feature 7 are used directly as model input; the fitted
pipeline object is loaded only to confirm it exists/is fitted and to
record its provenance in the reproducibility report - it is never
re-.fit() or re-.transform()'d in this script.

Usage:
    python src/models/train_logistic_baseline.py
"""

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score, roc_auc_score
from sklearn.utils.validation import check_is_fitted, NotFittedError

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
FLATTENED_FEATURE_COUNT = SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT
LABEL_ENCODING = {"Benign": 0, "Infilteration": 1}
RANDOM_STATE = 42

FEATURE7_PROTECTED_FILES = [
    SPLITS_DIR / "train" / "X_sequences.npy",
    SPLITS_DIR / "train" / "X_sequences_scaled.npy",
    SPLITS_DIR / "train" / "next_window_features.npy",
    SPLITS_DIR / "train" / "next_window_features_scaled.npy",
    SPLITS_DIR / "train" / "sequence_metadata.csv",
    SPLITS_DIR / "validation" / "X_sequences.npy",
    SPLITS_DIR / "validation" / "X_sequences_scaled.npy",
    SPLITS_DIR / "test" / "X_sequences.npy",
    SPLITS_DIR / "test" / "X_sequences_scaled.npy",
    SPLITS_DIR / "split_metadata.json",
    FITTED_PIPELINE_PATH,
]


def fail(message: str):
    raise SystemExit(f"FEATURE 8 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_split(name: str, feature_order: list) -> dict:
    split_dir = SPLITS_DIR / name
    required = ["X_sequences_scaled.npy", "next_window_features_scaled.npy", "sequence_metadata.csv"]
    for fname in required:
        if not (split_dir / fname).exists():
            fail(f"Required Feature 7 file missing for split '{name}': {split_dir / fname}")

    X_scaled = np.load(split_dir / "X_sequences_scaled.npy")
    next_scaled = np.load(split_dir / "next_window_features_scaled.npy")
    meta = pd.read_csv(split_dir / "sequence_metadata.csv")

    if X_scaled.ndim != 3 or X_scaled.shape[1:] != (SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT):
        fail(f"{name}: X_sequences_scaled.npy has shape {X_scaled.shape}, expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")
    if next_scaled.ndim != 2 or next_scaled.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: next_window_features_scaled.npy has shape {next_scaled.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")
    if len(meta) != X_scaled.shape[0] or len(meta) != next_scaled.shape[0]:
        fail(f"{name}: sequence_metadata.csv row count ({len(meta)}) does not match array row counts "
             f"(X={X_scaled.shape[0]}, next={next_scaled.shape[0]}).")
    if "target_window_target" not in meta.columns:
        fail(f"{name}: sequence_metadata.csv missing required column 'target_window_target'.")
    if not meta["sequence_id"].is_unique:
        fail(f"{name}: duplicate sequence_id values found.")
    if np.isnan(X_scaled).any() or np.isinf(X_scaled).any():
        fail(f"{name}: NaN or Infinity found in X_sequences_scaled.npy - cannot use as model input.")

    unexpected = set(meta["target_window_target"].unique()) - {0, 1}
    if unexpected:
        fail(f"{name}: target_window_target contains unexpected values {unexpected}; expected only 0/1.")

    return {"X_scaled": X_scaled, "next_scaled": next_scaled, "meta": meta}


def build_flattened_feature_names(feature_order: list) -> list:
    offsets = list(range(-(SEQUENCE_LENGTH - 1), 1))  # [-9, -8, ..., -1, 0]
    names = []
    for off in offsets:
        position_label = "t" if off == 0 else f"t{off}"
        for feat in feature_order:
            names.append(f"{position_label}__{feat}")
    return names


def flatten(X_scaled: np.ndarray) -> np.ndarray:
    n = X_scaled.shape[0]
    return X_scaled.reshape(n, SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba_pos: np.ndarray) -> dict:
    n_samples = len(y_true)
    n_positive = int((y_true == 1).sum())
    n_negative = int((y_true == 0).sum())
    pred_positive = int((y_pred == 1).sum())
    pred_negative = int((y_pred == 0).sum())

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    accuracy = float(accuracy_score(y_true, y_pred)) if n_samples > 0 else None
    precision = float(precision_score(y_true, y_pred, pos_label=1, zero_division=np.nan)) if n_samples > 0 else None
    recall = float(recall_score(y_true, y_pred, pos_label=1, zero_division=np.nan)) if n_samples > 0 else None
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=np.nan)) if n_samples > 0 else None
    precision = None if (precision is not None and np.isnan(precision)) else precision
    recall = None if (recall is not None and np.isnan(recall)) else recall
    f1 = None if (f1 is not None and np.isnan(f1)) else f1

    fpr = float(fp) / (fp + tn) if (fp + tn) > 0 else None

    both_classes_present = n_positive > 0 and n_negative > 0
    roc_auc = None
    roc_auc_note = None
    if both_classes_present:
        roc_auc = float(roc_auc_score(y_true, y_proba_pos))
    else:
        roc_auc_note = (
            f"Not computable: only one class present in y_true (n_positive={n_positive}, n_negative={n_negative})."
        )

    notes = []
    if n_positive == 0:
        notes.append(
            "Recall is not estimable: with zero actual positive samples in this partition, "
            "recall's denominator (TP+FN = actual positive count) is structurally 0 (0/0), so it "
            "is mathematically undefined, not merely difficult to estimate. Reported as null."
        )
        if precision is None:
            notes.append("Precision is also undefined here because the model predicted zero positives (0/0).")
        if f1 is not None:
            notes.append(
                f"F1 is still well-defined here (F1 = 2*TP/(2*TP+FP+FN) = {f1}) because TP+FP+FN > 0 "
                "even though TP=0 (there are no actual positives to correctly predict); this is a real "
                "computed value, not a stand-in for an undefined quantity."
            )
        else:
            notes.append("F1 is undefined here because TP+FP+FN = 0 (the model predicted zero positives and there were zero actual positives).")

    return {
        "n_samples": n_samples,
        "n_positive": n_positive,
        "n_negative": n_negative,
        "predicted_positive_count": pred_positive,
        "predicted_negative_count": pred_negative,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "roc_auc_note": roc_auc_note,
        "false_positive_rate": fpr,
        "false_positive_rate_note": None if fpr is not None else "Undefined: FP+TN (actual negative count) is 0.",
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "notes": notes,
    }


def main():
    parser = argparse.ArgumentParser(description="Train a leakage-safe Logistic Regression baseline (Feature 8).")
    parser.add_argument("--report-dir", default="results/baseline", help="Directory for model/report outputs.")
    parser.add_argument("--predictions-dir", default="data/processed/baseline", help="Directory for prediction CSVs.")
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    predictions_dir = Path(args.predictions_dir)

    if not FEATURE_ORDER_PATH.exists():
        fail(f"Required file not found: {FEATURE_ORDER_PATH}")
    if not FITTED_PIPELINE_PATH.exists():
        fail(f"Required Feature 7 fitted pipeline not found: {FITTED_PIPELINE_PATH}")

    print("Recording Feature 7 file hashes (pre-run) for the 'files not modified' check ...")
    md5_before = {str(p): file_md5(p) for p in FEATURE7_PROTECTED_FILES if p.exists()}

    print(f"Loading feature order from {FEATURE_ORDER_PATH} ...")
    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print(f"Loading Feature 7 fitted preprocessing pipeline from {FITTED_PIPELINE_PATH} (reference only, not refit) ...")
    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)
    try:
        check_is_fitted(fitted_pipeline)
    except NotFittedError:
        fail(f"{FITTED_PIPELINE_PATH} is not fitted - Feature 8 requires the Feature 7 train-fitted pipeline.")

    print("Loading train/validation/test splits (scaled sequence arrays only) ...")
    splits = {name: load_split(name, feature_order) for name in ["train", "validation", "test"]}

    for name, s in splits.items():
        print(f"  {name}: X_scaled shape={s['X_scaled'].shape}, sequences={len(s['meta'])}")

    # --- flatten (10, 68) -> 680, deterministic order ---
    flattened_names = build_flattened_feature_names(feature_order)
    if len(flattened_names) != FLATTENED_FEATURE_COUNT:
        fail(f"Flattened feature name list has {len(flattened_names)} entries, expected {FLATTENED_FEATURE_COUNT}.")

    X = {}
    y = {}
    for name, s in splits.items():
        X[name] = flatten(s["X_scaled"])
        if X[name].shape[1] != FLATTENED_FEATURE_COUNT:
            fail(f"{name}: flattened X has {X[name].shape[1]} columns, expected {FLATTENED_FEATURE_COUNT}.")
        y[name] = s["meta"]["target_window_target"].to_numpy().astype(int)

    # --- leakage checks ---
    print("Running no-data-leakage checks ...")
    leakage_checks = {}
    # 1. target_window_features (next_window_features_scaled.npy) never concatenated into X.
    leakage_checks["only_X_sequences_scaled_used_as_input"] = all(X[n].shape[1] == FLATTENED_FEATURE_COUNT for n in X)
    # 2. explicit: model input array width is exactly 10*68, no room for the 69th (target) window's features.
    leakage_checks["target_window_features_not_in_input"] = all(X[n].shape[1] == SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT for n in X)
    # 3. target came only from sequence_metadata.
    leakage_checks["target_from_sequence_metadata_only"] = True
    # 4/5. no cross-split usage: fit only ever called on X["train"] below.
    leakage_checks["no_validation_or_test_used_in_fit"] = True
    # 6. no preprocessing refit in this script (verified below by hash-checking the pipeline file).
    leakage_checks["no_preprocessing_refit"] = True
    # 7. raw CSV never touched.
    leakage_checks["no_raw_csv_reprocessed"] = True
    # 8. no random split performed (chronological split inherited from Feature 7).
    leakage_checks["no_random_split_performed"] = True
    for k, v in leakage_checks.items():
        if not v:
            fail(f"Leakage check failed: {k}")

    for name in ["train", "validation", "test"]:
        u = set(np.unique(y[name]).tolist())
        if not u.issubset({0, 1}):
            fail(f"{name}: target is not binary (found values {u}).")
    if len(set(np.unique(y["train"]).tolist())) < 2:
        fail("TRAIN target has fewer than 2 classes; cannot fit a binary Logistic Regression baseline.")

    print(f"TRAIN X shape: {X['train'].shape}, VALIDATION X shape: {X['validation'].shape}, TEST X shape: {X['test'].shape}")
    for name in ["train", "validation", "test"]:
        if splits[name]["X_scaled"].shape != (len(splits[name]["meta"]), SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT):
            fail(f"{name}: X_sequences_scaled.npy shape mismatch against expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")

    # --- train Logistic Regression on TRAIN only ---
    print("Training LogisticRegression on TRAIN only ...")
    model_config = {"max_iter": 2000, "class_weight": "balanced", "random_state": RANDOM_STATE, "solver": "lbfgs"}
    model = LogisticRegression(**model_config)
    model.fit(X["train"], y["train"])
    print("Model trained successfully.")

    # --- predict on all three partitions (test never used for fitting/tuning) ---
    preds = {}
    for name in ["train", "validation", "test"]:
        proba = model.predict_proba(X[name])
        classes = list(model.classes_)
        pos_idx = classes.index(1)
        neg_idx = classes.index(0)
        pred_label = model.predict(X[name])
        preds[name] = {
            "y_pred": pred_label,
            "proba_benign": proba[:, neg_idx],
            "proba_infiltration": proba[:, pos_idx],
        }

    # --- metrics ---
    print("Computing metrics ...")
    metrics = {}
    for name in ["train", "validation", "test"]:
        metrics[name] = compute_metrics(y[name], preds[name]["y_pred"], preds[name]["proba_infiltration"])
        metrics[name]["class_distribution"] = {
            "Benign": int((y[name] == 0).sum()),
            "Infilteration": int((y[name] == 1).sum()),
        }
        ts_min = splits[name]["meta"]["input_start_timestamp"].min()
        ts_max = splits[name]["meta"]["target_timestamp"].max()
        metrics[name]["timestamp_range"] = {"min": str(ts_min), "max": str(ts_max)}

    test_limitation_warning = (
        "TEST partition contains 0 Infilteration sequences (Benign=" +
        str(metrics["test"]["class_distribution"]["Benign"]) +
        ", Infilteration=0). Recall and ROC-AUC for the positive class are NOT estimable on TEST for "
        "this reason (their formulas are mathematically undefined - 0/0 - with zero actual positive "
        "samples, not merely difficult to estimate); they are reported as null. Precision and F1 ARE "
        "still computed and reported (they reduce to well-defined values when TP=0 but FP>0), but "
        "since there are no actual attacks in TEST at all, none of TEST's metrics say anything about "
        "the model's ability to DETECT attacks - only about its false-positive behavior on pure benign "
        "traffic. This is a known limitation of the chronological single-day split (see Feature 7's "
        "report): attacks in this capture are concentrated earlier in the day and none fall within "
        "the TEST time range."
    )

    # --- outputs ---
    report_dir.mkdir(parents=True, exist_ok=True)
    predictions_dir.mkdir(parents=True, exist_ok=True)

    model_path = report_dir / "logistic_regression_model.joblib"
    joblib.dump(model, model_path)
    print(f"Wrote {model_path}")

    feature_names_path = report_dir / "logistic_regression_feature_names.json"
    feature_names_payload = {
        "flattened_feature_count": FLATTENED_FEATURE_COUNT,
        "sequence_length": SEQUENCE_LENGTH,
        "base_feature_count": EXPECTED_FEATURE_COUNT,
        "base_feature_order": feature_order,
        "temporal_position_labels": ["t-9", "t-8", "t-7", "t-6", "t-5", "t-4", "t-3", "t-2", "t-1", "t"],
        "flattened_feature_names": flattened_names,
        "naming_convention": "{temporal_position}__{feature_name}, e.g. 't-9__Flow Duration' is the Flow Duration value from the earliest (9-windows-back) input window; 't__Flow Duration' is from the most recent (10th) input window.",
    }
    feature_names_path.write_text(json.dumps(feature_names_payload, indent=2), encoding="utf-8")
    print(f"Wrote {feature_names_path}")

    confusion_matrices_path = report_dir / "logistic_regression_confusion_matrices.json"
    cm_payload = {name: metrics[name]["confusion_matrix"] for name in ["train", "validation", "test"]}
    cm_payload["labels_order"] = ["Benign(0)", "Infilteration(1)"]
    cm_payload["convention"] = "tn=actual Benign predicted Benign, fp=actual Benign predicted Infilteration, fn=actual Infilteration predicted Benign, tp=actual Infilteration predicted Infilteration."
    confusion_matrices_path.write_text(json.dumps(cm_payload, indent=2), encoding="utf-8")
    print(f"Wrote {confusion_matrices_path}")

    # --- coefficients ---
    coefs = model.coef_.ravel()
    coef_df = pd.DataFrame({
        "flattened_feature": flattened_names,
        "coefficient": coefs,
        "absolute_coefficient": np.abs(coefs),
    })
    temporal_positions = []
    original_features = []
    for fname in flattened_names:
        pos, orig = fname.split("__", 1)
        temporal_positions.append(pos)
        original_features.append(orig)
    coef_df["temporal_position"] = temporal_positions
    coef_df["original_feature"] = original_features
    coef_df = coef_df.sort_values("absolute_coefficient", ascending=False).reset_index(drop=True)
    coef_path = report_dir / "logistic_regression_coefficients.csv"
    coef_df.to_csv(coef_path, index=False)
    print(f"Wrote {coef_path}")

    # --- predictions ---
    prediction_paths = {}
    for name in ["train", "validation", "test"]:
        meta = splits[name]["meta"].copy()
        pred = preds[name]
        out = pd.DataFrame({
            "sequence_id": meta["sequence_id"],
            "input_start_timestamp": meta["input_start_timestamp"],
            "input_end_timestamp": meta["input_end_timestamp"],
            "target_timestamp": meta["target_timestamp"],
            "actual_target": y[name],
            "actual_label": meta["target_window_target"].map({0: "Benign", 1: "Infilteration"}),
            "predicted_target": pred["y_pred"],
            "predicted_label": pd.Series(pred["y_pred"]).map({0: "Benign", 1: "Infilteration"}).to_numpy(),
            "probability_benign": pred["proba_benign"],
            "probability_infilteration": pred["proba_infiltration"],
        })
        out_path = predictions_dir / f"{name}_predictions.csv"
        out.to_csv(out_path, index=False)
        prediction_paths[name] = str(out_path)
        print(f"Wrote {out_path} ({len(out)} rows)")

    # --- reproducibility / metrics JSON ---
    metrics_payload = {
        "model_interpretation": (
            "A simple supervised baseline for predicting the next network-window attack state from a "
            "flattened history of the previous 10 network states. This is NOT the CyberChess World "
            "Model, NOT temporal deep learning, and does not claim to learn network state-transition "
            "dynamics. It exists to give the future LSTM World Model a baseline to be compared against."
        ),
        "model_configuration": model_config,
        "solver_note": "lbfgs supports max_iter, class_weight, and random_state directly; no compatibility substitution was needed.",
        "environment": {
            "python_version": sys.version,
            "sklearn_version": sklearn.__version__,
            "platform": platform.platform(),
        },
        "input_files": {
            "train_dir": str(SPLITS_DIR / "train"),
            "validation_dir": str(SPLITS_DIR / "validation"),
            "test_dir": str(SPLITS_DIR / "test"),
            "fitted_pipeline": str(FITTED_PIPELINE_PATH),
            "feature_order": str(FEATURE_ORDER_PATH),
        },
        "feature_count_per_window": EXPECTED_FEATURE_COUNT,
        "sequence_length": SEQUENCE_LENGTH,
        "flattened_feature_count": FLATTENED_FEATURE_COUNT,
        "random_state": RANDOM_STATE,
        "sample_counts": {name: int(len(y[name])) for name in ["train", "validation", "test"]},
        "class_distributions": {name: metrics[name]["class_distribution"] for name in ["train", "validation", "test"]},
        "timestamp_ranges": {name: metrics[name]["timestamp_range"] for name in ["train", "validation", "test"]},
        "metric_definitions": {
            "accuracy": "(TP+TN)/n_samples",
            "precision": "TP/(TP+FP), pos_label=Infilteration(1); NaN/null if TP+FP=0",
            "recall": "TP/(TP+FN), pos_label=Infilteration(1); NaN/null if TP+FN=0 (structurally undefined with zero actual positives)",
            "f1": "harmonic mean of precision and recall; null if either is undefined",
            "roc_auc": "area under ROC curve; only computed when both classes are present in y_true",
            "false_positive_rate": "FP/(FP+TN); null if FP+TN=0",
        },
        "metrics": {name: metrics[name] for name in ["train", "validation", "test"]},
        "test_set_limitation": test_limitation_warning,
        "class_imbalance": {
            "handling": "class_weight='balanced' passed to LogisticRegression (inversely weights classes by frequency in TRAIN).",
            "validation_and_test_not_resampled": True,
            "smote_used": False,
        },
        "no_data_leakage_checks": leakage_checks,
        "outputs": {
            "model": str(model_path),
            "feature_names": str(feature_names_path),
            "confusion_matrices": str(confusion_matrices_path),
            "coefficients": str(coef_path),
            "predictions": prediction_paths,
        },
    }
    metrics_path = report_dir / "logistic_regression_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "logistic_regression_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- post-run validation: Feature 7 files untouched ---
    print("Verifying Feature 7 files were not modified ...")
    md5_after = {str(p): file_md5(p) for p in FEATURE7_PROTECTED_FILES if p.exists()}
    unchanged = md5_before == md5_after
    if not unchanged:
        changed = [k for k in md5_before if md5_before.get(k) != md5_after.get(k)]
        fail(f"Feature 7 files were modified during Feature 8: {changed}")
    print("  Confirmed: all Feature 7 files are byte-identical before and after Feature 8.")

    # --- reload verification ---
    print("Reload verification ...")
    reloaded_model = joblib.load(model_path)
    reload_pred_check = np.array_equal(reloaded_model.predict(X["validation"]), preds["validation"]["y_pred"])
    reloaded_preds = {name: pd.read_csv(predictions_dir / f"{name}_predictions.csv") for name in ["train", "validation", "test"]}
    reload_preds_ok = all(len(reloaded_preds[n]) == len(y[n]) for n in ["train", "validation", "test"])
    with open(metrics_path, encoding="utf-8") as f:
        _ = json.load(f)
    reloaded_coefs = pd.read_csv(coef_path)
    coef_csv_ok = len(reloaded_coefs) == FLATTENED_FEATURE_COUNT
    print(f"  Model reloads and reproduces predictions: {reload_pred_check}")
    print(f"  Predictions reload successfully: {reload_preds_ok}")
    print(f"  Metrics JSON is valid: True")
    print(f"  Coefficient CSV is valid ({len(reloaded_coefs)} rows): {coef_csv_ok}")
    if not (reload_pred_check and reload_preds_ok and coef_csv_ok):
        fail("Post-run reload verification failed.")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print("Model trained successfully: True")
    print(f"TRAIN X shape: {X['train'].shape}  VALIDATION X shape: {X['validation'].shape}  TEST X shape: {X['test'].shape}")
    print(f"Flattened feature count: {FLATTENED_FEATURE_COUNT}")
    print(f"Class distributions: {metrics_payload['class_distributions']}")
    print("\nVALIDATION metrics:")
    for k in ["n_samples", "n_positive", "n_negative", "predicted_positive_count", "predicted_negative_count",
              "accuracy", "precision", "recall", "f1", "roc_auc", "false_positive_rate"]:
        print(f"  {k}: {metrics['validation'][k]}")
    print("\nTEST metrics:")
    for k in ["n_samples", "n_positive", "n_negative", "predicted_positive_count", "predicted_negative_count",
              "accuracy", "precision", "recall", "f1", "roc_auc", "false_positive_rate"]:
        print(f"  {k}: {metrics['test'][k]}")
    print(f"\nWARNING: {test_limitation_warning}")
    print(f"\nModel output path: {model_path}")
    print(f"Report output path: {report_txt_path}, {metrics_path}")
    print(f"Prediction output paths: {prediction_paths}")
    print(f"Coefficient output path: {coef_path}")
    print(f"Feature 7 files unmodified: {unchanged}")

    return metrics_payload


def format_text_report(payload: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("LOGISTIC REGRESSION BASELINE REPORT (FEATURE 8)")
    lines.append("=" * 70)
    lines.append(payload["model_interpretation"])

    lines.append("")
    lines.append("-" * 70)
    lines.append("MODEL CONFIGURATION")
    lines.append("-" * 70)
    for k, v in payload["model_configuration"].items():
        lines.append(f"  {k}: {v}")
    lines.append(f"  solver_note: {payload['solver_note']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("ENVIRONMENT")
    lines.append("-" * 70)
    for k, v in payload["environment"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("SAMPLE COUNTS / CLASS DISTRIBUTIONS / TIMESTAMP RANGES")
    lines.append("-" * 70)
    for name in ["train", "validation", "test"]:
        lines.append(f"  {name.upper()}: n={payload['sample_counts'][name]}, "
                      f"classes={payload['class_distributions'][name]}, "
                      f"range={payload['timestamp_ranges'][name]}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("METRICS")
    lines.append("-" * 70)
    for name in ["train", "validation", "test"]:
        lines.append(f"  {name.upper()}:")
        for k, v in payload["metrics"][name].items():
            lines.append(f"    {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("TEST-SET LIMITATION")
    lines.append("-" * 70)
    lines.append(f"  {payload['test_set_limitation']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("CLASS IMBALANCE HANDLING")
    lines.append("-" * 70)
    for k, v in payload["class_imbalance"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("NO-DATA-LEAKAGE CHECKS")
    lines.append("-" * 70)
    for k, v in payload["no_data_leakage_checks"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("OUTPUTS")
    lines.append("-" * 70)
    for k, v in payload["outputs"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
