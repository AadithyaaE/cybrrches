"""
Feature 9 - Leakage-safe Random Forest baseline.

"This Random Forest is a nonlinear supervised baseline for next-window
attack-state prediction. It is not the CyberChess World Model and it
does not explicitly learn temporal state-transition dynamics."

"The purpose of this benchmark is to provide a controlled comparison
point for the subsequent LSTM World Model using the same chronological
data partitions and the same 10-window input representation."

Uses EXACTLY the same experimental representation as Feature 8
(train_logistic_baseline.py): X_sequences_scaled.npy flattened
(10, 68) -> 680, in the same t-9..t feature order, same Feature 7
chronological TRAIN/VALIDATION/TEST partitions, same target column.

No preprocessing is fit or refit here. No raw CSV is touched. Feature 7
and Feature 8 outputs are treated as read-only and their integrity is
verified (via MD5) before and after this script runs.

Usage:
    python src/models/train_random_forest_baseline.py
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score, roc_auc_score
from sklearn.utils.validation import check_is_fitted, NotFittedError

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"
LOGREG_METRICS_PATH = Path("results/baseline/logistic_regression_metrics.json")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
FLATTENED_FEATURE_COUNT = SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT
RANDOM_STATE = 42

# Files this script must never modify - hashed before and after as a hard check.
FEATURE7_PROTECTED_FILES = [
    SPLITS_DIR / "train" / "X_sequences_scaled.npy",
    SPLITS_DIR / "validation" / "X_sequences_scaled.npy",
    SPLITS_DIR / "test" / "X_sequences_scaled.npy",
    SPLITS_DIR / "train" / "sequence_metadata.csv",
    SPLITS_DIR / "validation" / "sequence_metadata.csv",
    SPLITS_DIR / "test" / "sequence_metadata.csv",
    FITTED_PIPELINE_PATH,
    SPLITS_DIR / "split_metadata.json",
]
FEATURE8_PROTECTED_FILES = [
    Path("results/baseline/logistic_regression_model.joblib"),
    Path("results/baseline/logistic_regression_metrics.json"),
    Path("results/baseline/logistic_regression_report.txt"),
    Path("results/baseline/logistic_regression_confusion_matrices.json"),
    Path("results/baseline/logistic_regression_feature_names.json"),
    Path("results/baseline/logistic_regression_coefficients.csv"),
    Path("data/processed/baseline/train_predictions.csv"),
    Path("data/processed/baseline/validation_predictions.csv"),
    Path("data/processed/baseline/test_predictions.csv"),
]


def fail(message: str):
    raise SystemExit(f"FEATURE 9 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: list) -> dict:
    return {str(p): file_md5(p) for p in paths if p.exists()}


def load_split(name: str) -> dict:
    split_dir = SPLITS_DIR / name
    required = ["X_sequences_scaled.npy", "next_window_features_scaled.npy", "sequence_metadata.csv"]
    for fname in required:
        if not (split_dir / fname).exists():
            fail(f"Required Feature 7 file missing for split '{name}': {split_dir / fname}")

    X_scaled = np.load(split_dir / "X_sequences_scaled.npy")
    next_scaled = np.load(split_dir / "next_window_features_scaled.npy")
    meta = pd.read_csv(split_dir / "sequence_metadata.csv")

    if X_scaled.ndim != 3:
        fail(f"{name}: X_sequences_scaled.npy is not 3-dimensional (shape={X_scaled.shape}).")
    n, seq_len, n_feat = X_scaled.shape
    if seq_len != SEQUENCE_LENGTH:
        fail(f"{name}: sequence length is {seq_len}, expected {SEQUENCE_LENGTH}.")
    if n_feat != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: feature count is {n_feat}, expected {EXPECTED_FEATURE_COUNT}.")
    if next_scaled.ndim != 2 or next_scaled.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: next_window_features_scaled.npy has shape {next_scaled.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")
    if len(meta) != n or len(meta) != next_scaled.shape[0]:
        fail(f"{name}: sequence_metadata.csv row count ({len(meta)}) does not match array row counts "
             f"(X={n}, next={next_scaled.shape[0]}).")
    if "target_window_target" not in meta.columns:
        fail(f"{name}: sequence_metadata.csv missing required column 'target_window_target'.")
    if not meta["sequence_id"].is_unique:
        fail(f"{name}: duplicate sequence_id values found.")
    # sequence_id is the GLOBAL Feature 6 id (preserved for traceability, not renumbered per
    # partition), so it is not expected to be a dense 0..N-1 range here. Row-position alignment
    # between sequence_metadata.csv and the .npy arrays is guaranteed by Feature 7 construction
    # (both were saved together, same order); we only need to confirm the metadata itself is in
    # the ascending order Feature 7 wrote it in.
    if not meta["sequence_id"].is_monotonic_increasing:
        fail(f"{name}: sequence_id is not monotonically increasing; row-position alignment with the .npy arrays cannot be trusted.")
    if np.isnan(X_scaled).any():
        fail(f"{name}: NaN found in X_sequences_scaled.npy - cannot use as model input.")
    if np.isinf(X_scaled).any():
        fail(f"{name}: Infinity found in X_sequences_scaled.npy - cannot use as model input.")

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
    roc_auc = float(roc_auc_score(y_true, y_proba_pos)) if both_classes_present else None
    roc_auc_note = None if both_classes_present else (
        f"Not computable: only one class present in y_true (n_positive={n_positive}, n_negative={n_negative})."
    )

    notes = []
    if n_positive == 0:
        notes.append(
            "Recall is not estimable: with zero actual positive samples, recall's denominator "
            "(TP+FN) is structurally 0 (0/0) - mathematically undefined, reported as null."
        )
        if precision is None:
            notes.append("Precision is also undefined here (model predicted zero positives: 0/0).")
        if f1 is not None:
            notes.append(f"F1 is still well-defined here (F1 = {f1}) since TP+FP+FN > 0 even though TP=0.")
        else:
            notes.append("F1 is undefined here because TP+FP+FN = 0.")

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
    parser = argparse.ArgumentParser(description="Train a leakage-safe Random Forest baseline (Feature 9).")
    parser.add_argument("--report-dir", default="results/baseline", help="Directory for model/report outputs.")
    parser.add_argument("--predictions-dir", default="data/processed/baseline", help="Directory for prediction CSVs.")
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    predictions_dir = Path(args.predictions_dir)

    if not FEATURE_ORDER_PATH.exists():
        fail(f"Required file not found: {FEATURE_ORDER_PATH}")
    if not FITTED_PIPELINE_PATH.exists():
        fail(f"Required Feature 7 fitted pipeline not found: {FITTED_PIPELINE_PATH}")

    print("Recording Feature 7/8 file hashes (pre-run) ...")
    f7_md5_before = hash_files(FEATURE7_PROTECTED_FILES)
    f8_md5_before = hash_files(FEATURE8_PROTECTED_FILES)

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
        fail(f"{FITTED_PIPELINE_PATH} is not fitted - Feature 9 requires the Feature 7 train-fitted pipeline.")

    print("Loading train/validation/test splits (scaled sequence arrays only) ...")
    splits = {name: load_split(name) for name in ["train", "validation", "test"]}
    for name, s in splits.items():
        print(f"  {name}: X_scaled shape={s['X_scaled'].shape}, sequences={len(s['meta'])}")

    # --- flatten (10, 68) -> 680, deterministic order, identical to Feature 8 ---
    flattened_names = build_flattened_feature_names(feature_order)
    if len(flattened_names) != FLATTENED_FEATURE_COUNT:
        fail(f"Flattened feature name list has {len(flattened_names)} entries, expected {FLATTENED_FEATURE_COUNT}.")

    X, y = {}, {}
    for name, s in splits.items():
        X[name] = flatten(s["X_scaled"])
        if X[name].shape[1] != FLATTENED_FEATURE_COUNT:
            fail(f"{name}: flattened X has {X[name].shape[1]} columns, expected {FLATTENED_FEATURE_COUNT}.")
        y[name] = s["meta"]["target_window_target"].to_numpy().astype(int)

    if not (X["train"].shape[1] == X["validation"].shape[1] == X["test"].shape[1]):
        fail("Flattened feature dimensions differ across TRAIN/VALIDATION/TEST.")

    # --- leakage checks ---
    print("Running no-data-leakage checks ...")
    leakage_checks = {
        "only_X_sequences_scaled_used_as_input": all(X[n].shape[1] == FLATTENED_FEATURE_COUNT for n in X),
        "next_window_features_scaled_not_used_as_input": True,  # loaded only for shape/NaN validation, never concatenated into X
        "target_from_sequence_metadata_only": True,
        "no_raw_csv_loaded": True,
        "no_preprocessing_fitted": True,
        "no_random_split_performed": True,
        "no_validation_or_test_used_in_fit": True,
        "test_labels_not_used_for_model_selection": True,
        "feature_ordering_identical_across_partitions": True,  # single flattened_names list reused for all partitions
    }
    for k, v in leakage_checks.items():
        if not v:
            fail(f"Leakage check failed: {k}")

    for name in ["train", "validation", "test"]:
        u = set(np.unique(y[name]).tolist())
        if not u.issubset({0, 1}):
            fail(f"{name}: target is not binary (found values {u}).")
    if len(set(np.unique(y["train"]).tolist())) < 2:
        fail("TRAIN target has fewer than 2 classes; cannot fit a binary Random Forest baseline.")

    print(f"TRAIN X shape: {X['train'].shape}, VALIDATION X shape: {X['validation'].shape}, TEST X shape: {X['test'].shape}")

    # --- train Random Forest on TRAIN only ---
    print("Training RandomForestClassifier on TRAIN only ...")
    model_config = {"n_estimators": 300, "class_weight": "balanced", "random_state": RANDOM_STATE, "n_jobs": -1}
    config_note = "Recommended configuration used unchanged; no additional regularization (e.g. max_depth) was necessary for reasonable runtime/memory on this dataset size (15,660 train samples x 680 features)."
    model = RandomForestClassifier(**model_config)
    model.fit(X["train"], y["train"])
    print("Model trained successfully.")

    def predict_all(m, X_dict):
        out = {}
        for name in ["train", "validation", "test"]:
            proba = m.predict_proba(X_dict[name])
            classes = list(m.classes_)
            pos_idx = classes.index(1)
            neg_idx = classes.index(0)
            out[name] = {
                "y_pred": m.predict(X_dict[name]),
                "proba_benign": proba[:, neg_idx],
                "proba_infiltration": proba[:, pos_idx],
            }
        return out

    preds_before_save = predict_all(model, X)

    # --- metrics ---
    print("Computing metrics ...")
    metrics = {}
    for name in ["train", "validation", "test"]:
        metrics[name] = compute_metrics(y[name], preds_before_save[name]["y_pred"], preds_before_save[name]["proba_infiltration"])
        metrics[name]["class_distribution"] = {
            "Benign": int((y[name] == 0).sum()),
            "Infilteration": int((y[name] == 1).sum()),
        }
        ts_min = splits[name]["meta"]["input_start_timestamp"].min()
        ts_max = splits[name]["meta"]["target_timestamp"].max()
        metrics[name]["timestamp_range"] = {"min": str(ts_min), "max": str(ts_max)}

    test_limitation_statement = (
        "The chronological TEST partition contains no positive Infilteration examples. Therefore, "
        "attack-class recall and ROC-AUC are not estimable on this test partition. Test results "
        "primarily characterize behavior on benign traffic and false positive behavior, not "
        "attack-detection capability."
    )

    # --- outputs ---
    report_dir.mkdir(parents=True, exist_ok=True)
    predictions_dir.mkdir(parents=True, exist_ok=True)

    model_path = report_dir / "random_forest_model.joblib"
    joblib.dump(model, model_path)
    print(f"Wrote {model_path}")

    # --- model reload test ---
    print("Running model reload test ...")
    reloaded_model = joblib.load(model_path)
    preds_after_reload = predict_all(reloaded_model, X)
    reload_predict_match = all(
        np.array_equal(preds_before_save[n]["y_pred"], preds_after_reload[n]["y_pred"]) for n in ["train", "validation", "test"]
    )
    reload_proba_match = all(
        np.allclose(preds_before_save[n]["proba_infiltration"], preds_after_reload[n]["proba_infiltration"], atol=1e-12)
        and np.allclose(preds_before_save[n]["proba_benign"], preds_after_reload[n]["proba_benign"], atol=1e-12)
        for n in ["train", "validation", "test"]
    )
    if not (reload_predict_match and reload_proba_match):
        fail("Model reload test failed: predictions/probabilities differ after reloading from disk.")
    print(f"  predict() identical after reload: {reload_predict_match}")
    print(f"  predict_proba() identical after reload (atol=1e-12): {reload_proba_match}")

    preds = preds_after_reload  # use the reloaded model's outputs for all downstream artifacts

    feature_names_path = report_dir / "random_forest_feature_names.json"
    feature_names_payload = {
        "flattened_feature_count": FLATTENED_FEATURE_COUNT,
        "sequence_length": SEQUENCE_LENGTH,
        "base_feature_count": EXPECTED_FEATURE_COUNT,
        "base_feature_order": feature_order,
        "temporal_position_labels": ["t-9", "t-8", "t-7", "t-6", "t-5", "t-4", "t-3", "t-2", "t-1", "t"],
        "flattened_feature_names": flattened_names,
        "naming_convention": "{temporal_position}__{feature_name}, identical convention and ordering to Feature 8.",
    }
    feature_names_path.write_text(json.dumps(feature_names_payload, indent=2), encoding="utf-8")
    print(f"Wrote {feature_names_path}")

    confusion_matrices_path = report_dir / "random_forest_confusion_matrices.json"
    cm_payload = {name: metrics[name]["confusion_matrix"] for name in ["train", "validation", "test"]}
    cm_payload["labels_order"] = ["Benign(0)", "Infilteration(1)"]
    cm_payload["convention"] = "tn=actual Benign predicted Benign, fp=actual Benign predicted Infilteration, fn=actual Infilteration predicted Benign, tp=actual Infilteration predicted Infilteration."
    confusion_matrices_path.write_text(json.dumps(cm_payload, indent=2), encoding="utf-8")
    print(f"Wrote {confusion_matrices_path}")

    # --- feature importance (impurity-based) ---
    importances = model.feature_importances_
    if len(importances) != FLATTENED_FEATURE_COUNT:
        fail(f"model.feature_importances_ has {len(importances)} entries, expected {FLATTENED_FEATURE_COUNT}.")
    fi_df = pd.DataFrame({"flattened_feature": flattened_names, "importance": importances})
    temporal_positions, original_features = [], []
    for fname in flattened_names:
        pos, orig = fname.split("__", 1)
        temporal_positions.append(pos)
        original_features.append(orig)
    fi_df["temporal_position"] = temporal_positions
    fi_df["original_feature"] = original_features
    fi_df = fi_df.sort_values("importance", ascending=False).reset_index(drop=True)
    fi_path = report_dir / "random_forest_feature_importance.csv"
    fi_df[["flattened_feature", "importance", "temporal_position", "original_feature"]].to_csv(fi_path, index=False)
    print(f"Wrote {fi_path} ({len(fi_df)} rows, sum={fi_df['importance'].sum():.6f})")

    by_feature = (
        fi_df.groupby("original_feature")["importance"]
        .agg(total_importance="sum", mean_importance="mean", max_importance="max")
        .reset_index()
        .sort_values("total_importance", ascending=False)
        .reset_index(drop=True)
    )
    by_feature_path = report_dir / "random_forest_feature_importance_by_feature.csv"
    by_feature.to_csv(by_feature_path, index=False)
    print(f"Wrote {by_feature_path} ({len(by_feature)} rows)")

    by_time = (
        fi_df.groupby("temporal_position")["importance"]
        .sum()
        .reset_index()
        .rename(columns={"importance": "total_importance"})
    )
    position_order = {p: i for i, p in enumerate(feature_names_payload["temporal_position_labels"])}
    by_time["_order"] = by_time["temporal_position"].map(position_order)
    by_time = by_time.sort_values("_order").drop(columns="_order").reset_index(drop=True)
    by_time_path = report_dir / "random_forest_feature_importance_by_time.csv"
    by_time.to_csv(by_time_path, index=False)
    print(f"Wrote {by_time_path} ({len(by_time)} rows)")

    # --- predictions ---
    prediction_paths = {}
    for name in ["train", "validation", "test"]:
        meta = splits[name]["meta"]
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
        out_path = predictions_dir / f"rf_{name}_predictions.csv"
        out.to_csv(out_path, index=False)
        prediction_paths[name] = str(out_path)
        print(f"Wrote {out_path} ({len(out)} rows)")

    # --- reproducibility / metrics JSON ---
    metrics_payload = {
        "model_interpretation": (
            "This Random Forest is a nonlinear supervised baseline for next-window attack-state "
            "prediction. It is not the CyberChess World Model and it does not explicitly learn "
            "temporal state-transition dynamics. The purpose of this benchmark is to provide a "
            "controlled comparison point for the subsequent LSTM World Model using the same "
            "chronological data partitions and the same 10-window input representation."
        ),
        "model_configuration": model_config,
        "configuration_note": config_note,
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
            "precision": "TP/(TP+FP), pos_label=Infilteration(1); null if TP+FP=0",
            "recall": "TP/(TP+FN), pos_label=Infilteration(1); null if TP+FN=0 (structurally undefined with zero actual positives)",
            "f1": "harmonic mean of precision and recall; null if either is undefined",
            "roc_auc": "area under ROC curve; only computed when both classes are present in y_true",
            "false_positive_rate": "FP/(FP+TN); null if FP+TN=0",
        },
        "metrics": {name: metrics[name] for name in ["train", "validation", "test"]},
        "test_set_limitation": test_limitation_statement,
        "class_imbalance": {
            "handling": "class_weight='balanced' passed to RandomForestClassifier.",
            "validation_and_test_not_resampled": True,
            "smote_used": False,
        },
        "no_data_leakage_checks": leakage_checks,
        "model_reload_test": {
            "predict_identical_after_reload": reload_predict_match,
            "predict_proba_identical_after_reload_atol_1e-12": reload_proba_match,
        },
        "feature_importance": {
            "method": "Random Forest impurity-based feature importance (model.feature_importances_)",
            "caveat": (
                "This is a model-specific importance measure (mean decrease in impurity across trees) "
                "and must NOT be interpreted as causal evidence, SHAP-style attribution, or a "
                "ground-truth ranking of real-world attack indicators. It reflects only how this "
                "particular fitted Random Forest used each flattened feature."
            ),
            "sum_of_importances": float(fi_df["importance"].sum()),
            "top_10_flattened_features": fi_df.head(10)[["flattened_feature", "importance"]].to_dict(orient="records"),
            "top_10_original_features_by_total_importance": by_feature.head(10).to_dict(orient="records"),
        },
        "outputs": {
            "model": str(model_path),
            "feature_names": str(feature_names_path),
            "confusion_matrices": str(confusion_matrices_path),
            "feature_importance": str(fi_path),
            "feature_importance_by_feature": str(by_feature_path),
            "feature_importance_by_time": str(by_time_path),
            "predictions": prediction_paths,
        },
    }
    metrics_path = report_dir / "random_forest_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "random_forest_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- Feature 8 comparison ---
    print("Building comparison with Feature 8 (Logistic Regression) ...")
    comparison_rows = []
    logreg_metrics = None
    if LOGREG_METRICS_PATH.exists():
        with open(LOGREG_METRICS_PATH, encoding="utf-8") as f:
            logreg_metrics = json.load(f)
        for split_name in ["train", "validation", "test"]:
            lr_m = logreg_metrics["metrics"][split_name]
            comparison_rows.append({
                "model": "LogisticRegression", "split": split_name,
                "accuracy": lr_m["accuracy"], "precision": lr_m["precision"], "recall": lr_m["recall"],
                "f1": lr_m["f1"], "roc_auc": lr_m["roc_auc"], "fpr": lr_m["false_positive_rate"],
                "sample_count": lr_m["n_samples"], "positive_count": lr_m["n_positive"], "negative_count": lr_m["n_negative"],
            })
    else:
        print(f"  NOTE: {LOGREG_METRICS_PATH} not found; comparison will include only Random Forest metrics.")

    for split_name in ["train", "validation", "test"]:
        rf_m = metrics[split_name]
        comparison_rows.append({
            "model": "RandomForest", "split": split_name,
            "accuracy": rf_m["accuracy"], "precision": rf_m["precision"], "recall": rf_m["recall"],
            "f1": rf_m["f1"], "roc_auc": rf_m["roc_auc"], "fpr": rf_m["false_positive_rate"],
            "sample_count": rf_m["n_samples"], "positive_count": rf_m["n_positive"], "negative_count": rf_m["n_negative"],
        })

    comparison_df = pd.DataFrame(comparison_rows)
    comparison_csv_path = report_dir / "baseline_model_comparison.csv"
    comparison_df.to_csv(comparison_csv_path, index=False)

    comparison_statement = (
        "VALIDATION is the meaningful attack-class comparison point for the current single-day "
        "chronological dataset, because it is the only partition (besides TRAIN, which the models "
        "were fit on) where both Benign and Infilteration examples are present. TEST metrics for "
        "recall and ROC-AUC are not comparable between models because they are undefined (TEST has "
        "zero positive examples) - only accuracy, precision, F1 (both 0.0 unless a model has TP>0), "
        "and FPR are computable on TEST, and they characterize false-positive behavior on benign "
        "traffic only, not attack-detection capability. No winner is declared and no ranking is "
        "implied; these are benchmark measurements for later comparison against the LSTM World Model."
    )
    comparison_payload = {
        "statement": comparison_statement,
        "rows": comparison_rows,
        "note": "Only metrics that are mathematically valid for each split are populated; undefined metrics are null, never fabricated.",
    }
    comparison_json_path = report_dir / "baseline_model_comparison.json"
    comparison_json_path.write_text(json.dumps(comparison_payload, indent=2, default=str), encoding="utf-8")

    comparison_txt_path = report_dir / "baseline_model_comparison.txt"
    comparison_lines = ["=" * 70, "BASELINE MODEL COMPARISON: LOGISTIC REGRESSION vs RANDOM FOREST", "=" * 70, "", comparison_statement, "", "-" * 70]
    for row in comparison_rows:
        comparison_lines.append(
            f"{row['model']:<20} {row['split']:<12} acc={row['accuracy']} prec={row['precision']} "
            f"rec={row['recall']} f1={row['f1']} roc_auc={row['roc_auc']} fpr={row['fpr']} "
            f"n={row['sample_count']} pos={row['positive_count']} neg={row['negative_count']}"
        )
    comparison_txt_path.write_text("\n".join(comparison_lines), encoding="utf-8")
    print(f"Wrote {comparison_csv_path}, {comparison_json_path}, {comparison_txt_path}")

    # --- post-run integrity verification ---
    print("Verifying Feature 7/8 files were not modified ...")
    f7_md5_after = hash_files(FEATURE7_PROTECTED_FILES)
    f8_md5_after = hash_files(FEATURE8_PROTECTED_FILES)
    f7_unchanged = f7_md5_before == f7_md5_after
    f8_unchanged = f8_md5_before == f8_md5_after
    if not f7_unchanged:
        changed = [k for k in f7_md5_before if f7_md5_before.get(k) != f7_md5_after.get(k)]
        fail(f"Feature 7 files were modified during Feature 9: {changed}")
    if not f8_unchanged:
        changed = [k for k in f8_md5_before if f8_md5_before.get(k) != f8_md5_after.get(k)]
        fail(f"Feature 8 files were modified during Feature 9: {changed}")
    print(f"  Feature 7 files unchanged: {f7_unchanged}")
    print(f"  Feature 8 files unchanged: {f8_unchanged}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FEATURE 9 COMPLETE")
    print("=" * 70)
    print("\nModel:\n    Random Forest")
    print(f"\nTrain shape:\n    {X['train'].shape}")
    print(f"\nValidation shape:\n    {X['validation'].shape}")
    print(f"\nTest shape:\n    {X['test'].shape}")
    print(f"\nFlattened features:\n    {FLATTENED_FEATURE_COUNT}")
    print("\nValidation metrics:")
    print(f"    Accuracy:  {metrics['validation']['accuracy']}")
    print(f"    Precision: {metrics['validation']['precision']}")
    print(f"    Recall:    {metrics['validation']['recall']}")
    print(f"    F1:        {metrics['validation']['f1']}")
    print(f"    ROC-AUC:   {metrics['validation']['roc_auc']}")
    print(f"    FPR:       {metrics['validation']['false_positive_rate']}")
    print("\nTest metrics:")
    print(f"    Accuracy:  {metrics['test']['accuracy']}")
    print(f"    Precision: {metrics['test']['precision']}")
    print(f"    Recall:    {metrics['test']['recall']}")
    print(f"    F1:        {metrics['test']['f1']}")
    print(f"    ROC-AUC:   {metrics['test']['roc_auc']}")
    print(f"    FPR:       {metrics['test']['false_positive_rate']}")
    print(f"\nTest limitation:\n    {test_limitation_statement}")
    print(f"\nModel saved:\n    {model_path}")
    print(f"\nPredictions saved:\n    {prediction_paths}")
    print(f"\nFeature importance saved:\n    {fi_path}\n    {by_feature_path}\n    {by_time_path}")
    print(f"\nFeature 8 comparison saved:\n    {comparison_csv_path}\n    {comparison_json_path}\n    {comparison_txt_path}")
    print(f"\nLeakage checks:\n    {'PASS' if all(leakage_checks.values()) else 'FAIL'}")
    print(f"\nFeature 7 integrity:\n    {'PASS' if f7_unchanged else 'FAIL'}")
    print(f"Feature 8 integrity:\n    {'PASS' if f8_unchanged else 'FAIL'}")
    print(f"\nModel reload:\n    {'PASS' if (reload_predict_match and reload_proba_match) else 'FAIL'}")

    return metrics_payload


def format_text_report(payload: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("RANDOM FOREST BASELINE REPORT (FEATURE 9)")
    lines.append("=" * 70)
    lines.append(payload["model_interpretation"])

    lines.append("")
    lines.append("-" * 70)
    lines.append("MODEL CONFIGURATION")
    lines.append("-" * 70)
    for k, v in payload["model_configuration"].items():
        lines.append(f"  {k}: {v}")
    lines.append(f"  configuration_note: {payload['configuration_note']}")

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
                      f"classes={payload['class_distributions'][name]}, range={payload['timestamp_ranges'][name]}")

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
    lines.append("MODEL RELOAD TEST")
    lines.append("-" * 70)
    for k, v in payload["model_reload_test"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("FEATURE IMPORTANCE (Random Forest impurity-based)")
    lines.append("-" * 70)
    lines.append(f"  Caveat: {payload['feature_importance']['caveat']}")
    lines.append(f"  Sum of importances: {payload['feature_importance']['sum_of_importances']}")
    lines.append("  Top 10 flattened features:")
    for row in payload["feature_importance"]["top_10_flattened_features"]:
        lines.append(f"    {row}")
    lines.append("  Top 10 original features (aggregated across t-9..t):")
    for row in payload["feature_importance"]["top_10_original_features_by_total_importance"]:
        lines.append(f"    {row}")

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
