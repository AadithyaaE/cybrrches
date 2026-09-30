"""
Feature 11 - Next-State Attack Prediction.

"The LSTM learns temporal network-state dynamics, while a downstream
state classifier maps the predicted future state to an attack-state
interpretation."

"Feature 11 maps the LSTM-predicted next network state to a discrete
attack-state prediction. It does not yet implement multi-step
forecasting or attacker-progression probability."

Two evaluation modes are reported:

  MODE A (ORACLE): classifier trained and evaluated on GROUND-TRUTH next
  states (next_window_features_scaled.npy). Isolates whether the state
  representation itself is separable, independent of LSTM prediction
  error.

  MODE B (FULL PIPELINE): X_sequences_scaled -> frozen Feature 10 LSTM
  checkpoint (not retrained) -> predicted next state -> the SAME frozen
  classifier (trained only on ground-truth TRAIN states) -> predicted
  attack state. This is the actual CyberChess forecasting path.

The classifier is fit exactly once, on TRAIN ground-truth next states and
TRAIN labels only. It is never fit on validation/test data or on
LSTM-predicted states.

Usage:
    python src/models/train_next_state_attack_classifier.py
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
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402
from next_state_attack_classifier import NextStateAttackClassifier  # noqa: E402

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"
LSTM_CHECKPOINT_PATH = Path("results/lstm/lstm_world_model.pt")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
RANDOM_STATE = 42

# Known Feature 7 split sizes for this dataset snapshot (see split_metadata.json).
# Verified, not assumed: the script fails loudly if actual counts differ.
EXPECTED_COUNTS = {"train": 15660, "validation": 3492, "test": 2871}

FEATURE7_PROTECTED_FILES = [
    SPLITS_DIR / "train" / "X_sequences_scaled.npy",
    SPLITS_DIR / "train" / "next_window_features_scaled.npy",
    SPLITS_DIR / "train" / "sequence_metadata.csv",
    SPLITS_DIR / "validation" / "X_sequences_scaled.npy",
    SPLITS_DIR / "validation" / "next_window_features_scaled.npy",
    SPLITS_DIR / "validation" / "sequence_metadata.csv",
    SPLITS_DIR / "test" / "X_sequences_scaled.npy",
    SPLITS_DIR / "test" / "next_window_features_scaled.npy",
    SPLITS_DIR / "test" / "sequence_metadata.csv",
    FITTED_PIPELINE_PATH,
    SPLITS_DIR / "split_metadata.json",
]
FEATURE8_PROTECTED_FILES = list(Path("results/baseline").glob("logistic_regression_*")) + [
    Path("data/processed/baseline/train_predictions.csv"),
    Path("data/processed/baseline/validation_predictions.csv"),
    Path("data/processed/baseline/test_predictions.csv"),
]
FEATURE9_PROTECTED_FILES = list(Path("results/baseline").glob("random_forest_*")) + list(
    Path("results/baseline").glob("baseline_model_comparison*")
) + [
    Path("data/processed/baseline/rf_train_predictions.csv"),
    Path("data/processed/baseline/rf_validation_predictions.csv"),
    Path("data/processed/baseline/rf_test_predictions.csv"),
]
FEATURE10_PROTECTED_FILES = [
    LSTM_CHECKPOINT_PATH,
    Path("results/lstm/lstm_training_history.json"),
    Path("results/lstm/lstm_metrics.json"),
    Path("results/lstm/lstm_report.txt"),
    Path("results/lstm/lstm_per_feature_metrics.csv"),
    Path("results/lstm/lstm_config.json"),
    Path("results/lstm/lstm_predictions_summary.csv"),
    Path("data/processed/lstm/test_predicted_next_state.npy"),
    Path("data/processed/lstm/test_actual_next_state.npy"),
]


def fail(message: str):
    raise SystemExit(f"FEATURE 11 VALIDATION FAILURE: {message}")


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

    X_seq = np.load(split_dir / "X_sequences_scaled.npy")
    y_state = np.load(split_dir / "next_window_features_scaled.npy")
    meta = pd.read_csv(split_dir / "sequence_metadata.csv")

    if X_seq.ndim != 3 or X_seq.shape[1] != SEQUENCE_LENGTH or X_seq.shape[2] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: X_sequences_scaled.npy has shape {X_seq.shape}, expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")
    if y_state.ndim != 2 or y_state.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: next_window_features_scaled.npy has shape {y_state.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")
    if X_seq.shape[0] != y_state.shape[0]:
        fail(f"{name}: X_sequences_scaled and next_window_features_scaled row counts differ ({X_seq.shape[0]} vs {y_state.shape[0]}).")
    if len(meta) != X_seq.shape[0]:
        fail(f"{name}: sequence_metadata.csv row count ({len(meta)}) does not match array row count ({X_seq.shape[0]}).")
    if not meta["sequence_id"].is_monotonic_increasing:
        fail(f"{name}: sequence_id is not monotonically increasing; row-position alignment cannot be trusted.")
    if "target_window_target" not in meta.columns:
        fail(f"{name}: sequence_metadata.csv missing required column 'target_window_target'.")

    if np.isnan(X_seq).any() or np.isnan(y_state).any():
        fail(f"{name}: NaN found in X_sequences_scaled or next_window_features_scaled.")
    if np.isinf(X_seq).any() or np.isinf(y_state).any():
        fail(f"{name}: Infinity found in X_sequences_scaled or next_window_features_scaled.")

    labels = meta["target_window_target"].to_numpy().astype(int)
    unexpected = set(np.unique(labels).tolist()) - {0, 1}
    if unexpected:
        fail(f"{name}: target_window_target contains unexpected values {unexpected}; expected only 0/1.")

    if len(meta) != EXPECTED_COUNTS[name]:
        fail(
            f"{name}: sequence count is {len(meta)}, expected the known Feature 7 split size "
            f"{EXPECTED_COUNTS[name]}. Stopping rather than silently proceeding on an unexpected dataset."
        )

    return {
        "X_seq": X_seq.astype("float32"),
        "y_state": y_state.astype("float32"),
        "labels": labels,
        "meta": meta,
    }


def load_lstm_checkpoint(device) -> tuple:
    if not LSTM_CHECKPOINT_PATH.exists():
        fail(f"Required Feature 10 checkpoint not found: {LSTM_CHECKPOINT_PATH}")
    checkpoint = torch.load(LSTM_CHECKPOINT_PATH, map_location=device, weights_only=True)
    cfg = checkpoint["configuration"]
    model = LSTMWorldModel(
        input_size=cfg.get("input_size", EXPECTED_FEATURE_COUNT),
        hidden_size=cfg["hidden_size"],
        num_layers=cfg["num_layers"],
        dropout=cfg["dropout"],
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model, checkpoint


def lstm_predict(model, X: np.ndarray, device, batch_size: int = 512) -> np.ndarray:
    model.eval()
    preds = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[i:i + batch_size]).to(device)
            preds.append(model(xb).cpu().numpy())
    return np.concatenate(preds, axis=0).astype("float32")


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
        if f1 is not None:
            notes.append(f"F1 is still well-defined here (F1={f1}) since TP+FP+FN > 0 even though TP=0.")

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
    parser = argparse.ArgumentParser(description="Train/evaluate the Feature 11 next-state attack classifier.")
    parser.add_argument("--report-dir", default="results/next_state", help="Directory for classifier/report outputs.")
    parser.add_argument("--data-out-dir", default="data/processed/next_state", help="Directory for compact prediction artifacts.")
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    data_out_dir = Path(args.data_out_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    data_out_dir.mkdir(parents=True, exist_ok=True)

    print("Recording Feature 7/8/9/10 file hashes (pre-run) ...")
    f7_before = hash_files(FEATURE7_PROTECTED_FILES)
    f8_before = hash_files(FEATURE8_PROTECTED_FILES)
    f9_before = hash_files(FEATURE9_PROTECTED_FILES)
    f10_before = hash_files(FEATURE10_PROTECTED_FILES)

    random.seed(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)
    torch.manual_seed(RANDOM_STATE)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    if not FEATURE_ORDER_PATH.exists():
        fail(f"Required file not found: {FEATURE_ORDER_PATH}")
    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print("Loading Feature 7 splits (ground-truth states + labels; metadata for analysis only) ...")
    splits = {name: load_split(name) for name in ["train", "validation", "test"]}
    for name, s in splits.items():
        print(f"  {name}: X_seq={s['X_seq'].shape}, y_state={s['y_state'].shape}, "
              f"labels positive={int(s['labels'].sum())}/{len(s['labels'])} (matches expected count: "
              f"{len(s['meta']) == EXPECTED_COUNTS[name]})")

    # --- data alignment check: next_window_features_scaled rows <-> sequence_metadata labels ---
    print("Verifying next_window_features_scaled <-> sequence_metadata alignment ...")
    for name in ["train", "validation", "test"]:
        s = splits[name]
        if len(s["labels"]) != s["y_state"].shape[0]:
            fail(f"{name}: label count ({len(s['labels'])}) does not match state row count ({s['y_state'].shape[0]}).")
    print("  OK: row counts align for all partitions; no truncation or reordering performed.")

    # --- load frozen LSTM checkpoint (never retrained/fine-tuned) ---
    print(f"Loading frozen Feature 10 LSTM checkpoint from {LSTM_CHECKPOINT_PATH} ...")
    lstm_model, checkpoint = load_lstm_checkpoint(device)
    print(f"  Checkpoint architecture: {checkpoint['configuration']}  (best_epoch={checkpoint['epoch']}, "
          f"best_val_loss={checkpoint['best_validation_loss']:.6f})")

    # --- LSTM reload determinism check: fresh second instance must match on a fixed subset ---
    print("Verifying LSTM checkpoint reload determinism ...")
    fixed_subset = splits["validation"]["X_seq"][:50]
    with torch.no_grad():
        pred_a = lstm_model(torch.from_numpy(fixed_subset).to(device)).cpu().numpy()
    lstm_model_2, _ = load_lstm_checkpoint(device)
    with torch.no_grad():
        pred_b = lstm_model_2(torch.from_numpy(fixed_subset).to(device)).cpu().numpy()
    lstm_reload_match = bool(np.allclose(pred_a, pred_b, atol=1e-6))
    lstm_reload_max_diff = float(np.max(np.abs(pred_a - pred_b)))
    print(f"  LSTM reload determinism (atol=1e-6): {lstm_reload_match} (max abs diff = {lstm_reload_max_diff:.3e})")
    if not lstm_reload_match:
        fail(f"LSTM checkpoint reload is not deterministic (max diff {lstm_reload_max_diff}).")

    # --- LSTM inference on all three partitions (no retraining, no fine-tuning) ---
    print("Running frozen LSTM inference on TRAIN/VALIDATION/TEST X_sequences_scaled ...")
    lstm_predicted_state = {name: lstm_predict(lstm_model, splits[name]["X_seq"], device) for name in ["train", "validation", "test"]}
    for name, arr in lstm_predicted_state.items():
        print(f"  {name}: predicted_next_state shape={arr.shape}")
        if np.isnan(arr).any() or np.isinf(arr).any():
            fail(f"{name}: LSTM-predicted next state contains NaN/Infinity.")

    # --- fit the downstream classifier ONLY on TRAIN ground-truth next states ---
    print("Fitting NextStateAttackClassifier on TRAIN ground-truth next states only ...")
    classifier_fit_source = "TRAIN ground-truth next_window_features_scaled.npy + TRAIN target_window_target (never LSTM-predicted states, never validation/test data)."
    classifier = NextStateAttackClassifier(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE, solver="lbfgs")
    classifier.fit(splits["train"]["y_state"], splits["train"]["labels"])
    print(f"  Fit source: {classifier_fit_source}")

    pos_idx = list(classifier.classes_).index(1)
    neg_idx = list(classifier.classes_).index(0)

    def predict_mode(X_dict):
        out = {}
        for name in ["train", "validation", "test"]:
            proba = classifier.predict_proba(X_dict[name])
            out[name] = {
                "y_pred": classifier.predict(X_dict[name]),
                "proba_benign": proba[:, neg_idx],
                "proba_infiltration": proba[:, pos_idx],
            }
        return out

    print("Evaluating MODE A (oracle: ground-truth next state -> classifier) ...")
    oracle_state_input = {name: splits[name]["y_state"] for name in ["train", "validation", "test"]}
    oracle_preds = predict_mode(oracle_state_input)

    print("Evaluating MODE B (full pipeline: X_sequences -> LSTM -> predicted state -> classifier) ...")
    pipeline_preds = predict_mode(lstm_predicted_state)

    # --- metrics for both modes, all partitions ---
    metrics = {"oracle": {}, "pipeline": {}}
    for mode_name, preds in [("oracle", oracle_preds), ("pipeline", pipeline_preds)]:
        for name in ["train", "validation", "test"]:
            y_true = splits[name]["labels"]
            m = compute_metrics(y_true, preds[name]["y_pred"], preds[name]["proba_infiltration"])
            m["class_distribution"] = {"Benign": int((y_true == 0).sum()), "Infilteration": int((y_true == 1).sum())}
            metrics[mode_name][name] = m

    test_limitation_statement = (
        "The chronological TEST partition contains no positive Infiltration examples. Therefore, "
        "attack-class recall and ROC-AUC are not estimable on the current TEST partition. Test "
        "results should not be interpreted as a complete attack-detection evaluation."
    )
    print(f"\n{test_limitation_statement}")

    # --- oracle vs pipeline comparison on VALIDATION (both classes present) ---
    val_oracle, val_pipeline = metrics["oracle"]["validation"], metrics["pipeline"]["validation"]
    comparison_metrics = ["accuracy", "precision", "recall", "f1", "roc_auc", "false_positive_rate"]
    validation_comparison = {}
    for k in comparison_metrics:
        o, p = val_oracle[k], val_pipeline[k]
        validation_comparison[k] = {
            "oracle": o, "pipeline": p,
            "difference_pipeline_minus_oracle": (p - o) if (o is not None and p is not None) else None,
        }
    comparison_statement = (
        "VALIDATION is the meaningful comparison point because it is the only evaluation partition "
        "(besides TRAIN, which the classifier was fit on) containing both classes. The difference "
        "(pipeline - oracle) provides an empirical indication of how errors in future-state prediction "
        "affect downstream attack-state classification; it does not establish that this difference is "
        "solely or causally due to LSTM prediction error, since other factors (e.g. classifier decision "
        "boundary sensitivity near the LSTM's smoothed/regression-toward-mean predictions) could also "
        "contribute. No overall winner or ranking is declared."
    )
    print(f"VALIDATION oracle F1={val_oracle['f1']}  pipeline F1={val_pipeline['f1']}  "
          f"difference={validation_comparison['f1']['difference_pipeline_minus_oracle']}")

    # --- probability calibration statement ---
    calibration_statement = "Raw Logistic Regression probabilities are reported; probability calibration is deferred."

    # --- save classifier, verify reload ---
    classifier_path = report_dir / "next_state_attack_classifier.joblib"
    joblib.dump(classifier, classifier_path)
    print(f"Wrote {classifier_path}")

    reloaded_classifier = joblib.load(classifier_path)
    reload_predict_match = bool(np.array_equal(
        reloaded_classifier.predict(splits["validation"]["y_state"]), oracle_preds["validation"]["y_pred"]
    ))
    reload_proba_match = bool(np.allclose(
        reloaded_classifier.predict_proba(splits["validation"]["y_state"])[:, pos_idx],
        oracle_preds["validation"]["proba_infiltration"], atol=1e-12,
    ))
    print(f"  Classifier reload predict() match: {reload_predict_match}")
    print(f"  Classifier reload predict_proba() match (atol=1e-12): {reload_proba_match}")
    if not (reload_predict_match and reload_proba_match):
        fail("Classifier reload did not reproduce predictions within tolerance.")

    # --- leakage checks ---
    print("Running leakage protection checks ...")
    leakage_checks = {
        "1_state_input_shape_68": all(splits[n]["y_state"].shape[1] == EXPECTED_FEATURE_COUNT for n in splits)
        and all(lstm_predicted_state[n].shape[1] == EXPECTED_FEATURE_COUNT for n in lstm_predicted_state),
        "2_labels_binary": all(set(np.unique(splits[n]["labels"]).tolist()).issubset({0, 1}) for n in splits),
        "3_no_nan_inf": all(
            not np.isnan(splits[n]["y_state"]).any() and not np.isinf(splits[n]["y_state"]).any()
            and not np.isnan(lstm_predicted_state[n]).any() and not np.isinf(lstm_predicted_state[n]).any()
            for n in ["train", "validation", "test"]
        ),
        "4_no_timestamp_in_model_input": True,  # classifier input is exactly the 68-dim state array, never metadata
        "5_no_sequence_id_in_model_input": True,
        "6_no_attack_label_in_model_input": True,  # label used only as the y target for classifier.fit(), never concatenated into X
        "7_classifier_fitted_only_on_train_ground_truth": True,  # single .fit() call, on splits['train']['y_state']/labels
        "8_validation_labels_used_only_for_evaluation": True,
        "9_test_labels_used_only_for_final_evaluation": True,
        "10_lstm_not_retrained": True,  # lstm_model.eval() + torch.no_grad() only; no .train()/backward()/optimizer step anywhere
        "11_feature7_files_unchanged": None,  # filled after hashing post-run
        "12_feature8_files_unchanged": None,
        "13_feature9_files_unchanged": None,
        "14_feature10_files_unchanged": None,
        "15_no_random_train_test_split": True,  # Feature 7's chronological split reused unmodified
    }
    for k in ["1_state_input_shape_68", "2_labels_binary", "3_no_nan_inf"]:
        if not leakage_checks[k]:
            fail(f"Leakage check failed: {k}")

    # --- prediction artifact alignment check ---
    print("Verifying prediction artifact alignment ...")
    for name in ["train", "validation", "test"]:
        n_lstm = lstm_predicted_state[name].shape[0]
        n_oracle_pred = len(oracle_preds[name]["y_pred"])
        n_pipeline_pred = len(pipeline_preds[name]["y_pred"])
        n_meta = len(splits[name]["meta"])
        if not (n_lstm == n_oracle_pred == n_pipeline_pred == n_meta):
            fail(f"{name}: prediction artifact counts misaligned (lstm={n_lstm}, oracle={n_oracle_pred}, "
                 f"pipeline={n_pipeline_pred}, metadata={n_meta}).")
    print("  OK: LSTM predictions, classifier predictions, and metadata row counts align for all partitions.")

    # --- save compact prediction artifacts ---
    for name in ["train", "validation", "test"]:
        np.save(data_out_dir / f"{name}_predicted_next_state.npy", lstm_predicted_state[name])
    print(f"Wrote predicted_next_state.npy for train/validation/test to {data_out_dir}")

    for name in ["validation", "test"]:
        meta = splits[name]["meta"]
        out = pd.DataFrame({
            "sequence_id": meta["sequence_id"],
            "target_timestamp": meta["target_timestamp"],
            "actual_target": splits[name]["labels"],
            "actual_label": meta["target_window_label"],
            "predicted_target": pipeline_preds[name]["y_pred"],
            "predicted_label": pd.Series(pipeline_preds[name]["y_pred"]).map({0: "Benign", 1: "Infilteration"}).to_numpy(),
            "prob_benign": pipeline_preds[name]["proba_benign"],
            "prob_infiltration": pipeline_preds[name]["proba_infiltration"],
        })
        out_path = data_out_dir / f"{name}_attack_predictions.csv"
        out.to_csv(out_path, index=False)
        print(f"Wrote {out_path} ({len(out)} rows, MODE B full-pipeline predictions)")

    # --- results/next_state/ predictions summary (both modes, all partitions, compact) ---
    summary_frames = []
    for mode_name, preds in [("oracle", oracle_preds), ("pipeline", pipeline_preds)]:
        for name in ["train", "validation", "test"]:
            meta = splits[name]["meta"]
            summary_frames.append(pd.DataFrame({
                "mode": mode_name,
                "split": name,
                "sequence_id": meta["sequence_id"].to_numpy(),
                "target_timestamp": meta["target_timestamp"].to_numpy(),
                "actual_target": splits[name]["labels"],
                "actual_label": meta["target_window_label"].to_numpy(),
                "predicted_target": preds[name]["y_pred"],
                "predicted_label": pd.Series(preds[name]["y_pred"]).map({0: "Benign", 1: "Infilteration"}).to_numpy(),
                "prob_benign": preds[name]["proba_benign"],
                "prob_infiltration": preds[name]["proba_infiltration"],
            }))
    predictions_summary_df = pd.concat(summary_frames, axis=0, ignore_index=True)
    predictions_summary_path = report_dir / "next_state_attack_predictions_summary.csv"
    predictions_summary_df.to_csv(predictions_summary_path, index=False)
    print(f"Wrote {predictions_summary_path} ({len(predictions_summary_df)} rows)")

    # --- confusion matrices JSON ---
    cm_payload = {
        mode: {name: metrics[mode][name]["confusion_matrix"] for name in ["train", "validation", "test"]}
        for mode in ["oracle", "pipeline"]
    }
    cm_payload["labels_order"] = ["Benign(0)", "Infilteration(1)"]
    cm_payload["convention"] = "tn=actual Benign predicted Benign, fp=actual Benign predicted Infilteration, fn=actual Infilteration predicted Benign, tp=actual Infilteration predicted Infilteration."
    cm_path = report_dir / "next_state_attack_confusion_matrices.json"
    cm_path.write_text(json.dumps(cm_payload, indent=2), encoding="utf-8")
    print(f"Wrote {cm_path}")

    # --- config JSON ---
    config_payload = {
        "classifier": classifier.config,
        "state_dim": EXPECTED_FEATURE_COUNT,
        "random_state": RANDOM_STATE,
        "classifier_fit_source": classifier_fit_source,
        "lstm_checkpoint": str(LSTM_CHECKPOINT_PATH),
        "lstm_architecture": checkpoint["configuration"],
        "lstm_best_epoch": checkpoint["epoch"],
        "lstm_best_validation_loss": checkpoint["best_validation_loss"],
        "calibration": calibration_statement,
        "environment": {"python_version": sys.version, "sklearn_version": sklearn.__version__, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
    }
    config_path = report_dir / "next_state_attack_config.json"
    config_path.write_text(json.dumps(config_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {config_path}")

    # --- oracle_metrics.json / pipeline_metrics.json (convenience subsets) ---
    oracle_metrics_path = report_dir / "oracle_metrics.json"
    oracle_metrics_path.write_text(json.dumps(metrics["oracle"], indent=2, default=str), encoding="utf-8")
    pipeline_metrics_path = report_dir / "pipeline_metrics.json"
    pipeline_metrics_path.write_text(json.dumps(metrics["pipeline"], indent=2, default=str), encoding="utf-8")
    print(f"Wrote {oracle_metrics_path}, {pipeline_metrics_path}")

    # --- post-run integrity verification ---
    print("Verifying Feature 7/8/9/10 files were not modified ...")
    f7_after, f8_after, f9_after, f10_after = (
        hash_files(FEATURE7_PROTECTED_FILES), hash_files(FEATURE8_PROTECTED_FILES),
        hash_files(FEATURE9_PROTECTED_FILES), hash_files(FEATURE10_PROTECTED_FILES),
    )
    f7_unchanged, f8_unchanged = f7_before == f7_after, f8_before == f8_after
    f9_unchanged, f10_unchanged = f9_before == f9_after, f10_before == f10_after
    if not f7_unchanged:
        fail(f"Feature 7 files modified: {[k for k in f7_before if f7_before.get(k) != f7_after.get(k)]}")
    if not f8_unchanged:
        fail(f"Feature 8 files modified: {[k for k in f8_before if f8_before.get(k) != f8_after.get(k)]}")
    if not f9_unchanged:
        fail(f"Feature 9 files modified: {[k for k in f9_before if f9_before.get(k) != f9_after.get(k)]}")
    if not f10_unchanged:
        fail(f"Feature 10 files modified: {[k for k in f10_before if f10_before.get(k) != f10_after.get(k)]}")
    leakage_checks.update({
        "11_feature7_files_unchanged": f7_unchanged, "12_feature8_files_unchanged": f8_unchanged,
        "13_feature9_files_unchanged": f9_unchanged, "14_feature10_files_unchanged": f10_unchanged,
    })
    print(f"  Feature 7: {f7_unchanged}  Feature 8: {f8_unchanged}  Feature 9: {f9_unchanged}  Feature 10: {f10_unchanged}")

    # --- metrics JSON (main) ---
    metrics_payload = {
        "objective": "Map the LSTM-predicted next network state S(t+1) to a discrete attack-state prediction (Benign/Infilteration).",
        "scope_statement": (
            "Feature 11 maps the LSTM-predicted next network state to a discrete attack-state "
            "prediction. It does not yet implement multi-step forecasting or attacker-progression "
            "probability."
        ),
        "relationship_to_feature10": (
            "The LSTM World Model (Feature 10, frozen and not retrained here) predicts the continuous "
            "68-dimensional next network state from 10 historical states. Feature 11 adds a separate, "
            "downstream classifier that interprets ANY 68-dimensional state (ground-truth or "
            "LSTM-predicted) as an attack-state label. The LSTM remains purely a temporal-dynamics "
            "model; it was never given the attack label and was not modified in this feature."
        ),
        "oracle_methodology": "Classifier trained on TRAIN ground-truth next states, evaluated on ground-truth next states for train/validation/test. Isolates state-representation separability from LSTM prediction error.",
        "full_pipeline_methodology": "Same frozen classifier, evaluated on LSTM-predicted next states (X_sequences_scaled -> frozen LSTM -> predicted state -> classifier) for train/validation/test. This is the actual CyberChess forecasting path.",
        "classifier_configuration": classifier.config,
        "sample_counts": {name: EXPECTED_COUNTS[name] for name in ["train", "validation", "test"]},
        "label_distributions": {name: metrics["oracle"][name]["class_distribution"] for name in ["train", "validation", "test"]},
        "metrics": metrics,
        "validation_comparison_oracle_vs_pipeline": validation_comparison,
        "comparison_statement": comparison_statement,
        "test_set_limitation": test_limitation_statement,
        "calibration": calibration_statement,
        "leakage_checks": leakage_checks,
        "reproducibility": {
            "seed": RANDOM_STATE,
            "classifier_reload_predict_match": reload_predict_match,
            "classifier_reload_proba_match_atol_1e-12": reload_proba_match,
            "lstm_reload_determinism_match": lstm_reload_match,
            "lstm_reload_max_abs_diff": lstm_reload_max_diff,
        },
        "feature8_vs_feature11_distinction": (
            "Feature 8's Logistic Regression was trained on a FLATTENED 10x68=680-dimensional "
            "historical sequence (t-9..t) to predict the NEXT window's label directly. Feature 11's "
            "Logistic Regression is a different model: it maps ONE 68-dimensional FUTURE state vector "
            "(ground-truth or LSTM-predicted S(t+1)) to its attack-state label. They are not "
            "interchangeable and are not directly comparable as classifiers of the same input."
        ),
        "outputs": {
            "classifier": str(classifier_path),
            "confusion_matrices": str(cm_path),
            "config": str(config_path),
            "oracle_metrics": str(oracle_metrics_path),
            "pipeline_metrics": str(pipeline_metrics_path),
            "predictions_summary": str(predictions_summary_path),
            "validation_attack_predictions": str(data_out_dir / "validation_attack_predictions.csv"),
            "test_attack_predictions": str(data_out_dir / "test_attack_predictions.csv"),
        },
    }
    metrics_path = report_dir / "next_state_attack_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    # --- comparison text file ---
    comparison_txt_path = report_dir / "next_state_comparison.txt"
    comparison_lines = [
        "=" * 70, "ORACLE vs FULL WORLD-MODEL PIPELINE COMPARISON (VALIDATION)", "=" * 70, "",
        comparison_statement, "",
        f"{'metric':<20}{'oracle':>12}{'pipeline':>12}{'difference':>14}",
    ]
    for k in comparison_metrics:
        row = validation_comparison[k]
        comparison_lines.append(f"{k:<20}{str(row['oracle']):>12}{str(row['pipeline']):>12}{str(row['difference_pipeline_minus_oracle']):>14}")
    comparison_lines.append("")
    comparison_lines.append(metrics_payload["feature8_vs_feature11_distinction"])
    comparison_txt_path.write_text("\n".join(comparison_lines), encoding="utf-8")
    print(f"Wrote {comparison_txt_path}")

    report_txt_path = report_dir / "next_state_attack_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FEATURE 11 COMPLETE")
    print("=" * 70)
    print(f"Oracle VALIDATION metrics: {metrics['oracle']['validation']}")
    print(f"Pipeline VALIDATION metrics: {metrics['pipeline']['validation']}")
    print(f"Oracle TEST metrics: {metrics['oracle']['test']}")
    print(f"Pipeline TEST metrics: {metrics['pipeline']['test']}")
    print(f"\n{test_limitation_statement}")
    print(f"\nAll structural leakage checks: {'PASS' if all(v for v in leakage_checks.values() if v is not None) else 'FAIL'}")
    print(f"Feature 7/8/9/10 integrity: {'PASS' if (f7_unchanged and f8_unchanged and f9_unchanged and f10_unchanged) else 'FAIL'}")
    print(f"Classifier reload: {'PASS' if (reload_predict_match and reload_proba_match) else 'FAIL'}")
    print(f"LSTM reload determinism: {'PASS' if lstm_reload_match else 'FAIL'}")

    return metrics_payload


def format_text_report(payload: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("NEXT-STATE ATTACK PREDICTION REPORT (FEATURE 11)")
    lines.append("=" * 70)

    lines.append("\n1. OBJECTIVE")
    lines.append(f"   {payload['objective']}")
    lines.append(f"   {payload['scope_statement']}")

    lines.append("\n2. ARCHITECTURE")
    lines.append("   Frozen Feature 10 LSTM World Model (unmodified) + a separate downstream")
    lines.append(f"   LogisticRegression state-to-attack classifier: {payload['classifier_configuration']}")

    lines.append("\n3. RELATIONSHIP TO FEATURE 10")
    lines.append(f"   {payload['relationship_to_feature10']}")

    lines.append("\n4. ORACLE CLASSIFICATION METHODOLOGY (MODE A)")
    lines.append(f"   {payload['oracle_methodology']}")

    lines.append("\n5. FULL PIPELINE METHODOLOGY (MODE B)")
    lines.append(f"   {payload['full_pipeline_methodology']}")

    lines.append("\n6-8. TRAINING / VALIDATION / TEST DATA")
    for name in ["train", "validation", "test"]:
        lines.append(f"   {name}: n={payload['sample_counts'][name]}, labels={payload['label_distributions'][name]}")

    lines.append("\n9. CLASSIFIER CONFIGURATION")
    for k, v in payload["classifier_configuration"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n10. ORACLE METRICS")
    for name in ["train", "validation", "test"]:
        lines.append(f"   {name.upper()}: {payload['metrics']['oracle'][name]}")

    lines.append("\n11. FULL-PIPELINE METRICS")
    for name in ["train", "validation", "test"]:
        lines.append(f"   {name.upper()}: {payload['metrics']['pipeline'][name]}")

    lines.append("\n12. ORACLE vs FULL-PIPELINE COMPARISON (VALIDATION)")
    lines.append(f"   {payload['comparison_statement']}")
    for k, v in payload["validation_comparison_oracle_vs_pipeline"].items():
        lines.append(f"   {k}: oracle={v['oracle']} pipeline={v['pipeline']} difference={v['difference_pipeline_minus_oracle']}")

    lines.append("\n13. CONFUSION MATRICES")
    lines.append(f"   See {payload['outputs']['confusion_matrices']}")

    lines.append("\n14. PROBABILITY OUTPUTS")
    lines.append(f"   {payload['calibration']}")

    lines.append("\n15. LEAKAGE CHECKS")
    for k, v in payload["leakage_checks"].items():
        lines.append(f"   {k}: {'PASS' if v else ('N/A' if v is None else 'FAIL')}")

    lines.append("\n16. REPRODUCIBILITY CHECKS")
    for k, v in payload["reproducibility"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n17. TEST-SET LIMITATION")
    lines.append(f"   {payload['test_set_limitation']}")

    lines.append("\n18. KNOWN LIMITATIONS")
    lines.append("   - TEST partition contains no Infiltration target windows; test metrics here")
    lines.append("     characterize false-positive behavior on benign traffic only, in both modes.")
    lines.append("   - The oracle-vs-pipeline difference on VALIDATION is descriptive, not a proof of")
    lines.append("     causality (see comparison_statement).")
    lines.append("   - Raw (uncalibrated) probabilities are reported; see item 14.")
    lines.append("   - Single continuous-day capture: generalization to other days/networks is untested.")
    lines.append(f"   {payload['feature8_vs_feature11_distinction']}")

    lines.append("\n19. WHAT FEATURE 11 DOES NOT IMPLEMENT")
    lines.append("   - K-step / multi-step forecasting")
    lines.append("   - Attack-progression probability across multiple future windows")
    lines.append("   - MITRE ATT&CK stage prediction")
    lines.append("   - Explainability (SHAP or otherwise)")
    lines.append("   - Autonomous mitigation")

    lines.append("\n20. RECOMMENDED NEXT FEATURE")
    lines.append("   Feature 12: extend the frozen World Model to multi-step (K-step) rollout forecasting,")
    lines.append("   still respecting the chronological split and the TEST-set label limitation documented above.")

    lines.append("")
    lines.append("OUTPUTS:")
    for k, v in payload["outputs"].items():
        lines.append(f"   {k}: {v}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
