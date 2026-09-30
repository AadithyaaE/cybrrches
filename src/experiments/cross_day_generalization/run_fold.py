"""
Feature 17, Experiment B - trains a NEW LogReg/RandomForest/LSTM/next-state
classifier on a combination of TRAINING days only, and evaluates on one
completely held-out day. Never touches Features 1-16's frozen artifacts for
writing (only reads the Feature 4 unfitted preprocessing template and the
Feature 10 LSTM architecture class, both reused unmodified). Saves all new
model artifacts under results/cross_day_generalization/trained_models/.

LEAKAGE ISOLATION (see leakage_audit.py for automated verification):
  - The held-out day's raw file/rows are NEVER included in ANY concatenation
    used for preprocessing fitting, LSTM training, or classifier fitting.
  - The preprocessing pipeline is fit ONLY on the training days' window
    feature vectors (mirroring Feature 7's own methodology exactly, reusing
    the same unfitted reference pipeline template).
  - The held-out day's sequences are transformed via .transform() only.
  - The classification threshold stays 0.50 (never tuned on any data).
"""

import argparse
import json
import random
import sys
import time
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
sys.path.insert(0, str(ROOT / "src/data"))
sys.path.insert(0, str(ROOT / "src/models"))
sys.path.insert(0, str(ROOT))

from lstm_world_model import LSTMWorldModel  # noqa: E402 - Feature 10, unmodified
from k_step_forecaster import batched_recursive_rollout  # noqa: E402 - Feature 12, unmodified
from next_state_attack_classifier import NextStateAttackClassifier  # noqa: E402 - Feature 11, unmodified
from attack_progression_probability import infiltration_probability, threshold_predict, DEFAULT_THRESHOLD  # noqa: E402 - Feature 13, unmodified
import prepare_external_dataset as pext  # noqa: E402 - Feature 16, unmodified
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from src.experiments.cross_day_generalization.common import (  # noqa: E402
    DAY_REGISTRY, SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT, HORIZONS, RANDOM_SEED,
    prepare_day_windows_and_sequences, chronological_train_val_split, extended_regression_stats,
    brier_score, degenerate_prediction_check,
)

UNFITTED_PIPELINE_TEMPLATE = ROOT / "data/processed/model_ready/preprocessing_pipeline.joblib"
OUT_ROOT = ROOT / "results/cross_day_generalization"

LSTM_CONFIG = {"batch_size": 128, "learning_rate": 1e-3, "max_epochs": 50, "patience": 7, "seed": RANDOM_SEED}
LOGREG_CONFIG = {"max_iter": 2000, "class_weight": "balanced", "random_state": RANDOM_SEED, "solver": "lbfgs"}
RF_CONFIG = {"n_estimators": 300, "class_weight": "balanced", "random_state": RANDOM_SEED, "n_jobs": -1}


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def compute_classification_metrics(y_true, y_pred, y_proba_pos, threshold=DEFAULT_THRESHOLD) -> dict:
    """Identical structure/semantics to Feature 16's evaluate_frozen_generalization.compute_classification_metrics()."""
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


def scale_sequences(pipeline, X_raw, next_raw, feature_order):
    n, t, f_ = X_raw.shape
    flat_df = pd.DataFrame(X_raw.reshape(n * t, f_), columns=feature_order)
    X_scaled = np.asarray(pipeline.transform(flat_df), dtype="float32").reshape(n, t, f_)
    next_scaled = np.asarray(pipeline.transform(pd.DataFrame(next_raw, columns=feature_order)), dtype="float32")
    return X_scaled, next_scaled


def train_lstm(X_train, y_train, X_val, y_val, device, log_lines):
    set_seed(LSTM_CONFIG["seed"])
    model = LSTMWorldModel(input_size=EXPECTED_FEATURE_COUNT, hidden_size=128, num_layers=2, dropout=0.2).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=LSTM_CONFIG["learning_rate"])
    loss_fn = torch.nn.MSELoss()

    train_ds = torch.utils.data.TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train))
    val_ds = torch.utils.data.TensorDataset(torch.from_numpy(X_val), torch.from_numpy(y_val))
    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=LSTM_CONFIG["batch_size"], shuffle=True, num_workers=0)
    val_loader = torch.utils.data.DataLoader(val_ds, batch_size=LSTM_CONFIG["batch_size"], shuffle=False, num_workers=0)

    best_val_loss = float("inf")
    best_state = None
    best_epoch = 0
    epochs_without_improvement = 0
    history = []
    t0 = time.time()
    for epoch in range(1, LSTM_CONFIG["max_epochs"] + 1):
        model.train()
        train_losses = []
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            pred = model(xb)
            loss = loss_fn(pred, yb)
            loss.backward()
            optimizer.step()
            train_losses.append(loss.item())
        model.eval()
        val_losses = []
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(device), yb.to(device)
                val_losses.append(loss_fn(model(xb), yb).item())
        train_loss, val_loss = float(np.mean(train_losses)), float(np.mean(val_losses))
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss})
        log_lines.append(f"  epoch {epoch:3d}/{LSTM_CONFIG['max_epochs']}: train_loss={train_loss:.6f} val_loss={val_loss:.6f}")
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            best_epoch = epoch
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= LSTM_CONFIG["patience"]:
                log_lines.append(f"  Early stopping at epoch {epoch} (no VAL improvement for {LSTM_CONFIG['patience']} epochs).")
                break
    training_seconds = time.time() - t0
    model.load_state_dict(best_state)
    return model, {"epochs_run": len(history), "best_epoch": best_epoch, "best_validation_loss": best_val_loss,
                   "early_stopped": len(history) < LSTM_CONFIG["max_epochs"], "training_seconds": training_seconds, "history": history}


def run_fold(fold_name: str, train_days: list, holdout_day: str, day_cache: dict):
    print(f"\n{'='*70}\nFOLD: {fold_name}  TRAIN={train_days}  HOLDOUT={holdout_day}\n{'='*70}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log_lines = [f"Fold {fold_name}: train_days={train_days} holdout_day={holdout_day} device={device}"]

    feature_order, numeric_features, onehot_protocol_columns, _ = pext.load_reference_artifacts()

    for day in train_days + [holdout_day]:
        if day not in day_cache:
            print(f"Preparing {day} (clean -> states -> windows -> raw sequences; Feature 2/16 code, unmodified) ...")
            day_cache[day] = prepare_day_windows_and_sequences(day, feature_order, numeric_features, onehot_protocol_columns)

    # ---- 1. fit preprocessing on TRAINING DAYS' windows only (never the held-out day) ----
    print("Fitting fold-specific preprocessing pipeline on TRAIN-day windows only ...")
    train_window_frames = [day_cache[d]["windows"][feature_order] for d in train_days]
    combined_train_windows = pd.concat(train_window_frames, axis=0, ignore_index=True)
    pipeline = joblib.load(UNFITTED_PIPELINE_TEMPLATE)  # fresh unfitted clone of Feature 4's template, never the frozen fitted one
    pipeline.fit(combined_train_windows)

    # ---- 2. scale each day's raw sequences via THIS fold's pipeline (transform-only for ALL days, including holdout) ----
    scaled = {}
    for day in train_days + [holdout_day]:
        X_scaled, next_scaled = scale_sequences(pipeline, day_cache[day]["X_raw"], day_cache[day]["next_raw"], feature_order)
        scaled[day] = {"X_scaled": X_scaled, "next_scaled": next_scaled}

    # ---- 3. concatenate TRAINING days' sequences (each day's own chronological order preserved; days concatenated, never interleaved/shuffled) ----
    X_train_all = np.concatenate([scaled[d]["X_scaled"] for d in train_days], axis=0)
    next_train_all = np.concatenate([scaled[d]["next_scaled"] for d in train_days], axis=0)
    y_train_all = np.concatenate([day_cache[d]["seq_meta"]["target_window_binary_target"].to_numpy().astype(int) for d in train_days], axis=0)
    day_tags_train = np.concatenate([[d] * len(day_cache[d]["seq_meta"]) for d in train_days])

    # ---- 4. per-day chronological train/val split (never shuffled across time; days never interleaved) ----
    train_idx_parts, val_idx_parts, offset = [], [], 0
    for d in train_days:
        n_d = len(day_cache[d]["seq_meta"])
        tr_i, va_i = chronological_train_val_split(day_cache[d]["seq_meta"])
        train_idx_parts.append(tr_i + offset)
        val_idx_parts.append(va_i + offset)
        offset += n_d
    lstm_train_idx = np.concatenate(train_idx_parts)
    lstm_val_idx = np.concatenate(val_idx_parts)

    print(f"Combined training sequences: {len(y_train_all)} (LSTM-train={len(lstm_train_idx)}, LSTM-val={len(lstm_val_idx)}); "
          f"day breakdown: { {d: int((day_tags_train == d).sum()) for d in train_days} }")

    # ---- 5. train LogReg + RF on flattened 680-dim input (Feature 8/9 philosophy) ----
    print("Training Logistic Regression baseline (flattened 680-dim) ...")
    n_train = len(y_train_all)
    X_flat_train = X_train_all.reshape(n_train, SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT)
    logreg = LogisticRegression(**LOGREG_CONFIG)
    logreg.fit(X_flat_train, y_train_all)

    print("Training Random Forest baseline (flattened 680-dim) ...")
    rf = RandomForestClassifier(**RF_CONFIG)
    rf.fit(X_flat_train, y_train_all)

    # ---- 6. train LSTM world model (Feature 10 architecture/hyperparameters) ----
    print("Training LSTM World Model ...")
    lstm_model, lstm_train_report = train_lstm(
        X_train_all[lstm_train_idx], next_train_all[lstm_train_idx],
        X_train_all[lstm_val_idx], next_train_all[lstm_val_idx], device, log_lines,
    )
    for line in lstm_train_report["history"][-3:]:
        print(f"  ... epoch {line['epoch']}: train_loss={line['train_loss']:.6f} val_loss={line['val_loss']:.6f}")
    print(f"  LSTM training done: {lstm_train_report['epochs_run']} epochs, best_epoch={lstm_train_report['best_epoch']}, "
          f"training_seconds={lstm_train_report['training_seconds']:.1f}")

    # ---- 7. train next-state attack classifier on TRAINING days' ground-truth next-states only ----
    print("Training next-state attack classifier (Feature 11 philosophy, LogisticRegression on 68D state) ...")
    classifier = NextStateAttackClassifier(max_iter=2000, class_weight="balanced", random_state=RANDOM_SEED, solver="lbfgs")
    classifier.fit(next_train_all, y_train_all)

    # ---- 8. evaluate everything on the HELD-OUT day only ----
    print(f"Evaluating on held-out day {holdout_day} (never used in any fit above) ...")
    X_hold, next_hold = scaled[holdout_day]["X_scaled"], scaled[holdout_day]["next_scaled"]
    seq_meta_hold = day_cache[holdout_day]["seq_meta"]
    y_hold = seq_meta_hold["target_window_binary_target"].to_numpy().astype(int)
    n_hold = len(y_hold)

    results = {"fold_name": fold_name, "train_days": train_days, "holdout_day": holdout_day,
               "n_train_sequences": int(n_train), "n_holdout_sequences": int(n_hold)}

    if n_hold == 0:
        results["note"] = "0 sequences in held-out day - no evaluation possible."
        return results, {"logreg": logreg, "rf": rf, "lstm": lstm_model, "classifier": classifier, "pipeline": pipeline}, lstm_train_report, log_lines

    X_flat_hold = X_hold.reshape(n_hold, SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT)
    logreg_pred = logreg.predict(X_flat_hold)
    logreg_proba = logreg.predict_proba(X_flat_hold)[:, list(logreg.classes_).index(1)]
    rf_pred = rf.predict(X_flat_hold)
    rf_proba = rf.predict_proba(X_flat_hold)[:, list(rf.classes_).index(1)]
    results["logistic_regression_binary"] = compute_classification_metrics(y_hold, logreg_pred, logreg_proba)
    results["random_forest_binary"] = compute_classification_metrics(y_hold, rf_pred, rf_proba)

    rollout_full = batched_recursive_rollout(lstm_model, torch.from_numpy(X_hold), max(HORIZONS), device).numpy()
    lstm_k1_pred = rollout_full[:, 0, :]
    results["lstm_one_step_regression"] = extended_regression_stats(lstm_k1_pred, next_hold, feature_order)

    oracle_proba = infiltration_probability(classifier, next_hold)
    oracle_pred = threshold_predict(oracle_proba)
    pipeline_proba = infiltration_probability(classifier, lstm_k1_pred)
    pipeline_pred = threshold_predict(pipeline_proba)
    results["next_state_classifier_oracle_binary"] = compute_classification_metrics(y_hold, oracle_pred, oracle_proba)
    results["next_state_classifier_full_pipeline_binary"] = compute_classification_metrics(y_hold, pipeline_pred, pipeline_proba)

    # ---- 9. K-step forecasting + attack progression, per horizon ----
    windows_hold = day_cache[holdout_day]["windows"]
    horizon_results = {}
    for h in HORIZONS:
        end_wid = seq_meta_hold["input_end_window"].to_numpy()
        seg = windows_hold.set_index("window_id")["segment_id"]
        target_wid = end_wid + h
        in_range = target_wid <= (len(windows_hold) - 1)
        clipped = np.where(in_range, target_wid, 0)
        end_seg = seg.reindex(end_wid).to_numpy()
        target_seg = seg.reindex(clipped).to_numpy()
        valid = in_range & (target_seg == end_seg)
        n_valid = int(valid.sum())
        if n_valid == 0:
            horizon_results[h] = {"n": 0, "note": "No valid sequences at this horizon."}
            continue
        rollout_h = rollout_full[valid, h - 1, :]
        actual_h = windows_hold.set_index("window_id").loc[clipped[valid], feature_order].to_numpy()
        actual_h_scaled = np.asarray(pipeline.transform(pd.DataFrame(actual_h, columns=feature_order)), dtype="float32")
        y_h = windows_hold.set_index("window_id").loc[clipped[valid], "binary_target"].to_numpy().astype(int)
        reg_h = extended_regression_stats(rollout_h, actual_h_scaled, feature_order)
        proba_h = infiltration_probability(classifier, rollout_h)
        pred_h = threshold_predict(proba_h)
        cls_h = compute_classification_metrics(y_h, pred_h, proba_h)
        horizon_results[h] = {"regression": reg_h, "attack_progression": cls_h}
    results["horizons"] = horizon_results
    results["lstm_training"] = {k: v for k, v in lstm_train_report.items() if k != "history"}

    models = {"logreg": logreg, "rf": rf, "lstm": lstm_model, "classifier": classifier, "pipeline": pipeline}
    return results, models, lstm_train_report, log_lines


def save_fold_models(fold_name: str, models: dict):
    out_dir = OUT_ROOT / "trained_models" / fold_name
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(models["logreg"], out_dir / "logistic_regression_model.joblib")
    joblib.dump(models["rf"], out_dir / "random_forest_model.joblib")
    joblib.dump(models["classifier"], out_dir / "next_state_attack_classifier.joblib")
    joblib.dump(models["pipeline"], out_dir / "preprocessing_pipeline_fold_fitted.joblib")
    torch.save({"model_state_dict": models["lstm"].state_dict(), "configuration": models["lstm"].config_dict()}, out_dir / "lstm_world_model.pt")
    print(f"Saved fold models to {out_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fold-name", required=True)
    parser.add_argument("--train-days", nargs="+", required=True)
    parser.add_argument("--holdout-day", required=True)
    args = parser.parse_args()

    day_cache = {}
    results, models, lstm_report, log_lines = run_fold(args.fold_name, args.train_days, args.holdout_day, day_cache)
    save_fold_models(args.fold_name, models)

    out_dir = OUT_ROOT / "configs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{args.fold_name}_config.json").write_text(json.dumps({
        "fold_name": args.fold_name, "train_days": args.train_days, "holdout_day": args.holdout_day,
        "lstm_config": LSTM_CONFIG, "logreg_config": LOGREG_CONFIG, "rf_config": RF_CONFIG,
        "random_seed": RANDOM_SEED,
    }, indent=2), encoding="utf-8")

    results_path = OUT_ROOT / f"{args.fold_name}_results.json"
    results_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {results_path}")
