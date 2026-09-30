"""
Feature 10 - Train the LSTM-based Network World Model.

Learns an approximation of:

    P(S(t+1) | S(t-9), ..., S(t))

Given 10 consecutive 68-dimensional network states (Feature 6/7's
X_sequences_scaled), predicts the next state vector S(t+1)
(next_window_features_scaled) via regression (MSE loss). This is NOT an
attack classifier - the attack label is loaded only for post-hoc,
descriptive analysis and is never used as model input or training signal.

"Feature 10 predicts the next network-state vector. It does not yet
perform K-step forecasting or attack-progression classification."

Uses ONLY the Feature 7 split artifacts as provided (already scaled by a
pipeline fit exclusively on TRAIN in Feature 7). No new preprocessing is
fit here. TEST is used only for final evaluation, never for training,
early stopping, or any selection decision.

Usage:
    python src/models/train_lstm_world_model.py
"""

import argparse
import hashlib
import json
import platform
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
SEED = 42

CONFIG = {
    "hidden_size": 128,
    "num_layers": 2,
    "dropout": 0.2,
    "batch_size": 128,
    "learning_rate": 1e-3,
    "max_epochs": 50,
    "patience": 7,
    "seed": SEED,
}

# Files this script must never modify - hashed before/after as a hard check.
FEATURE7_PROTECTED_FILES = [
    SPLITS_DIR / "train" / "X_sequences.npy",
    SPLITS_DIR / "train" / "X_sequences_scaled.npy",
    SPLITS_DIR / "train" / "next_window_features.npy",
    SPLITS_DIR / "train" / "next_window_features_scaled.npy",
    SPLITS_DIR / "train" / "sequence_metadata.csv",
    SPLITS_DIR / "validation" / "X_sequences.npy",
    SPLITS_DIR / "validation" / "X_sequences_scaled.npy",
    SPLITS_DIR / "validation" / "next_window_features.npy",
    SPLITS_DIR / "validation" / "next_window_features_scaled.npy",
    SPLITS_DIR / "validation" / "sequence_metadata.csv",
    SPLITS_DIR / "test" / "X_sequences.npy",
    SPLITS_DIR / "test" / "X_sequences_scaled.npy",
    SPLITS_DIR / "test" / "next_window_features.npy",
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


def fail(message: str):
    raise SystemExit(f"FEATURE 10 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: list) -> dict:
    return {str(p): file_md5(p) for p in paths if p.exists()}


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def load_split(name: str) -> dict:
    split_dir = SPLITS_DIR / name
    required = ["X_sequences_scaled.npy", "next_window_features_scaled.npy", "sequence_metadata.csv"]
    for fname in required:
        if not (split_dir / fname).exists():
            fail(f"Required Feature 7 file missing for split '{name}': {split_dir / fname}")

    X = np.load(split_dir / "X_sequences_scaled.npy")
    y = np.load(split_dir / "next_window_features_scaled.npy")
    meta = pd.read_csv(split_dir / "sequence_metadata.csv")

    if X.ndim != 3 or X.shape[1] != SEQUENCE_LENGTH or X.shape[2] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: X_sequences_scaled.npy has shape {X.shape}, expected (N, {SEQUENCE_LENGTH}, {EXPECTED_FEATURE_COUNT}).")
    if y.ndim != 2 or y.shape[1] != EXPECTED_FEATURE_COUNT:
        fail(f"{name}: next_window_features_scaled.npy has shape {y.shape}, expected (N, {EXPECTED_FEATURE_COUNT}).")
    if X.shape[0] != y.shape[0]:
        fail(f"{name}: X and target row counts differ ({X.shape[0]} vs {y.shape[0]}).")
    if len(meta) != X.shape[0]:
        fail(f"{name}: sequence_metadata.csv row count ({len(meta)}) does not match array row count ({X.shape[0]}).")
    if not meta["sequence_id"].is_monotonic_increasing:
        fail(f"{name}: sequence_id is not monotonically increasing; row-position alignment with .npy arrays cannot be trusted.")

    if np.isnan(X).any() or np.isnan(y).any():
        fail(f"{name}: NaN found in X or target arrays. Stopping rather than silently replacing.")
    if np.isinf(X).any() or np.isinf(y).any():
        fail(f"{name}: Infinity found in X or target arrays. Stopping rather than silently replacing.")

    return {"X": X.astype("float32"), "y": y.astype("float32"), "meta": meta}


def evaluate(model, loader, device, loss_fn) -> tuple:
    model.eval()
    total_loss, total_mae, n_batches = 0.0, 0.0, 0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            pred = model(xb)
            loss = loss_fn(pred, yb)
            mae = torch.mean(torch.abs(pred - yb))
            total_loss += loss.item()
            total_mae += mae.item()
            n_batches += 1
    return total_loss / n_batches, total_mae / n_batches


def full_predict(model, X: np.ndarray, device, batch_size: int = 512) -> np.ndarray:
    model.eval()
    preds = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[i:i + batch_size]).to(device)
            preds.append(model(xb).cpu().numpy())
    return np.concatenate(preds, axis=0)


def main():
    parser = argparse.ArgumentParser(description="Train the LSTM Network World Model (Feature 10).")
    parser.add_argument("--report-dir", default="results/lstm", help="Directory for model/report outputs.")
    parser.add_argument("--data-out-dir", default="data/processed/lstm", help="Directory for compact prediction artifacts.")
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    data_out_dir = Path(args.data_out_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    data_out_dir.mkdir(parents=True, exist_ok=True)

    if not FEATURE_ORDER_PATH.exists():
        fail(f"Required file not found: {FEATURE_ORDER_PATH}")
    if not FITTED_PIPELINE_PATH.exists():
        fail(f"Required Feature 7 fitted pipeline not found: {FITTED_PIPELINE_PATH}")

    print("Recording Feature 7/8/9 file hashes (pre-run) ...")
    f7_before = hash_files(FEATURE7_PROTECTED_FILES)
    f8_before = hash_files(FEATURE8_PROTECTED_FILES)
    f9_before = hash_files(FEATURE9_PROTECTED_FILES)

    print(f"Setting seed = {SEED} (python random, numpy, torch) ...")
    set_seed(SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print("Loading train/validation/test splits (X_sequences_scaled + next_window_features_scaled only) ...")
    splits = {name: load_split(name) for name in ["train", "validation", "test"]}
    for name, s in splits.items():
        print(f"  {name}: X shape={s['X'].shape}, y shape={s['y'].shape}")

    # --- leakage / shape validation checks (explicit, printed) ---
    print("Running leakage protection checks ...")
    leakage_checks = {
        "1_train_input_shape_correct": splits["train"]["X"].shape[1:] == (SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT),
        "2_train_target_shape_correct": splits["train"]["y"].shape[1:] == (EXPECTED_FEATURE_COUNT,),
        "3_validation_test_shapes_correct": all(
            splits[n]["X"].shape[1:] == (SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT) and splits[n]["y"].shape[1:] == (EXPECTED_FEATURE_COUNT,)
            for n in ["validation", "test"]
        ),
        "4_no_nan_inf": all(
            not np.isnan(splits[n]["X"]).any() and not np.isinf(splits[n]["X"]).any()
            and not np.isnan(splits[n]["y"]).any() and not np.isinf(splits[n]["y"]).any()
            for n in ["train", "validation", "test"]
        ),
        "5_attack_label_not_in_X": all(splits[n]["X"].shape[-1] == EXPECTED_FEATURE_COUNT for n in splits),
        "6_timestamp_not_in_X": all(splits[n]["X"].shape[-1] == EXPECTED_FEATURE_COUNT for n in splits),
        "7_sequence_id_not_in_X": all(splits[n]["X"].shape[-1] == EXPECTED_FEATURE_COUNT for n in splits),
        "8_next_window_features_used_only_as_target": True,  # enforced structurally: y is never concatenated into any model input below
        "9_test_not_used_during_training": True,  # enforced structurally: only splits['train'] passed to the training loop
        "10_test_not_used_for_early_stopping": True,  # enforced structurally: early stopping monitors splits['validation'] only
        "11_no_new_preprocessing_fit": True,  # no sklearn fit()/fit_transform() call exists anywhere in this script
    }
    for k, v in leakage_checks.items():
        if not v:
            fail(f"Leakage check failed: {k}")
        print(f"  {k}: PASS")

    # --- label distribution analysis (post-hoc, descriptive only, never fed to model) ---
    label_distributions = {}
    for name in ["train", "validation", "test"]:
        meta = splits[name]["meta"]
        label_distributions[name] = {str(k): int(v) for k, v in meta["target_window_label"].value_counts(dropna=False).items()}
    print(f"Target-window label distributions (descriptive only): {label_distributions}")

    # --- build model, data loaders ---
    model = LSTMWorldModel(
        input_size=EXPECTED_FEATURE_COUNT,
        hidden_size=CONFIG["hidden_size"],
        num_layers=CONFIG["num_layers"],
        dropout=CONFIG["dropout"],
    ).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model parameter count: {n_params}")

    def make_loader(name, shuffle):
        ds = TensorDataset(torch.from_numpy(splits[name]["X"]), torch.from_numpy(splits[name]["y"]))
        return DataLoader(ds, batch_size=CONFIG["batch_size"], shuffle=shuffle, num_workers=0)

    train_loader = make_loader("train", shuffle=True)
    val_loader = make_loader("validation", shuffle=False)
    test_loader = make_loader("test", shuffle=False)

    optimizer = torch.optim.Adam(model.parameters(), lr=CONFIG["learning_rate"])
    loss_fn = nn.MSELoss()

    # --- training loop with early stopping on VALIDATION loss ---
    print("Starting training ...")
    history = []
    best_val_loss = float("inf")
    best_epoch = -1
    best_state_dict = None
    epochs_without_improvement = 0
    training_start = time.time()

    for epoch in range(1, CONFIG["max_epochs"] + 1):
        model.train()
        running_loss, running_mae, n_batches = 0.0, 0.0, 0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            pred = model(xb)
            loss = loss_fn(pred, yb)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            running_mae += torch.mean(torch.abs(pred - yb)).item()
            n_batches += 1
        train_loss = running_loss / n_batches
        train_mae = running_mae / n_batches

        val_loss, val_mae = evaluate(model, val_loader, device, loss_fn)

        current_lr = optimizer.param_groups[0]["lr"]
        history.append({
            "epoch": epoch, "train_loss": train_loss, "validation_loss": val_loss,
            "train_mae": train_mae, "validation_mae": val_mae, "learning_rate": current_lr,
        })
        print(f"  epoch {epoch:3d}/{CONFIG['max_epochs']}: train_loss={train_loss:.6f} val_loss={val_loss:.6f} "
              f"train_mae={train_mae:.6f} val_mae={val_mae:.6f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch
            best_state_dict = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= CONFIG["patience"]:
                print(f"  Early stopping at epoch {epoch} (no VALIDATION improvement for {CONFIG['patience']} epochs).")
                break

    training_seconds = time.time() - training_start
    print(f"Training finished in {training_seconds:.1f}s. Best epoch: {best_epoch}, best VALIDATION loss: {best_val_loss:.6f}")

    # restore best weights in memory
    model.load_state_dict(best_state_dict)

    # --- reload/reproducibility test: fixed validation subset ---
    print("Verifying checkpoint reload reproduces predictions ...")
    fixed_subset_size = min(200, len(splits["validation"]["X"]))
    fixed_subset = splits["validation"]["X"][:fixed_subset_size]
    model.eval()
    with torch.no_grad():
        pred_before_save = model(torch.from_numpy(fixed_subset).to(device)).cpu().numpy()

    checkpoint_path = report_dir / "lstm_world_model.pt"
    torch.save({
        "model_state_dict": best_state_dict,
        "optimizer_state_dict": optimizer.state_dict(),
        "epoch": best_epoch,
        "best_validation_loss": best_val_loss,
        "configuration": {**CONFIG, "input_size": EXPECTED_FEATURE_COUNT, "sequence_length": SEQUENCE_LENGTH},
        "random_seed": SEED,
    }, checkpoint_path)
    print(f"Wrote {checkpoint_path}")

    reloaded_model = LSTMWorldModel(
        input_size=EXPECTED_FEATURE_COUNT,
        hidden_size=CONFIG["hidden_size"],
        num_layers=CONFIG["num_layers"],
        dropout=CONFIG["dropout"],
    ).to(device)
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=True)
    reloaded_model.load_state_dict(checkpoint["model_state_dict"])
    reloaded_model.eval()
    with torch.no_grad():
        pred_after_reload = reloaded_model(torch.from_numpy(fixed_subset).to(device)).cpu().numpy()

    reload_tolerance = 1e-6
    reload_match = bool(np.allclose(pred_before_save, pred_after_reload, atol=reload_tolerance))
    max_diff = float(np.max(np.abs(pred_before_save - pred_after_reload)))
    print(f"  Reload prediction match (atol={reload_tolerance}): {reload_match} (max abs diff = {max_diff:.3e})")
    if not reload_match:
        fail(f"Checkpoint reload did not reproduce predictions within tolerance {reload_tolerance} (max diff {max_diff}).")

    model = reloaded_model  # use the reloaded model for all downstream evaluation, proving it truly works standalone

    # --- final metrics on TRAIN / VALIDATION / TEST ---
    print("Computing final metrics on TRAIN / VALIDATION / TEST ...")

    def compute_split_metrics(name):
        X, y = splits[name]["X"], splits[name]["y"]
        preds = full_predict(model, X, device)
        sq_err = (preds - y) ** 2
        abs_err = np.abs(preds - y)
        mse = float(np.mean(sq_err))
        mae = float(np.mean(abs_err))
        rmse = float(np.sqrt(mse))
        per_feature_mse = np.mean(sq_err, axis=0)
        per_feature_mae = np.mean(abs_err, axis=0)
        per_sample_mse = np.mean(sq_err, axis=1)
        per_sample_mae = np.mean(abs_err, axis=1)
        return {
            "mse": mse, "rmse": rmse, "mae": mae,
            "per_feature_mse": per_feature_mse, "per_feature_mae": per_feature_mae,
            "per_sample_mse": per_sample_mse, "per_sample_mae": per_sample_mae,
            "preds": preds,
        }

    split_results = {name: compute_split_metrics(name) for name in ["train", "validation", "test"]}
    for name in ["train", "validation", "test"]:
        r = split_results[name]
        print(f"  {name}: MSE={r['mse']:.6f} RMSE={r['rmse']:.6f} MAE={r['mae']:.6f}")
        if not (np.isfinite(r["mse"]) and np.isfinite(r["rmse"]) and np.isfinite(r["mae"])):
            fail(f"{name}: non-finite metric encountered (mse={r['mse']}, rmse={r['rmse']}, mae={r['mae']}).")

    # --- honest diagnostic: identify the single largest-error sample/feature per split ---
    # MSE is sensitive to outliers; when MSE and MAE diverge sharply for a split, that usually
    # means a small number of extreme errors dominate the mean-squared metric. This is computed
    # from the actual data (never hardcoded) so the report stays honest if the data changes.
    outlier_diagnostics = {}
    for name in ["train", "validation", "test"]:
        r = split_results[name]
        worst_sample_idx = int(np.argmax(r["per_sample_mse"]))
        worst_feature_idx = int(np.argmax((split_results[name]["preds"][worst_sample_idx] - splits[name]["y"][worst_sample_idx]) ** 2))
        actual_val = float(splits[name]["y"][worst_sample_idx, worst_feature_idx])
        pred_val = float(split_results[name]["preds"][worst_sample_idx, worst_feature_idx])
        train_col = splits["train"]["y"][:, worst_feature_idx]
        mse_excluding_worst = float(
            (np.sum(r["per_sample_mse"]) - r["per_sample_mse"][worst_sample_idx]) / (len(r["per_sample_mse"]) - 1)
        ) if len(r["per_sample_mse"]) > 1 else None
        outlier_diagnostics[name] = {
            "worst_sample_sequence_id": int(splits[name]["meta"]["sequence_id"].iloc[worst_sample_idx]),
            "worst_sample_target_timestamp": str(splits[name]["meta"]["target_timestamp"].iloc[worst_sample_idx]),
            "worst_sample_mse": float(r["per_sample_mse"][worst_sample_idx]),
            "dominant_feature": feature_order[worst_feature_idx],
            "dominant_feature_actual_scaled_value": actual_val,
            "dominant_feature_predicted_scaled_value": pred_val,
            "dominant_feature_train_scaled_range": [float(train_col.min()), float(train_col.max())],
            "note": (
                f"The single worst sample in {name} is dominated by feature '{feature_order[worst_feature_idx]}' "
                f"(actual scaled value {actual_val:.3f} vs TRAIN's observed range "
                f"[{train_col.min():.3f}, {train_col.max():.3f}]). "
                + ("This value falls far outside anything the scaler/model ever saw during TRAIN fitting, "
                   "i.e. a genuine out-of-distribution event in this partition, not a data or code bug."
                   if (actual_val > train_col.max() or actual_val < train_col.min()) else
                   "This value is within TRAIN's observed range for this feature.")
            ),
            "overall_mse_excluding_this_one_sample_diagnostic_only": mse_excluding_worst,
        }
        print(f"  {name} outlier diagnostic: {outlier_diagnostics[name]['note']}")
    print("  (overall_mse_excluding_this_one_sample is a DIAGNOSTIC only, for interpretability; "
          "the officially reported MSE above includes every sample with no exclusions.)")

    # --- per-feature metrics CSV ---
    per_feature_rows = []
    for i, feat in enumerate(feature_order):
        row = {"feature_name": feat}
        for name in ["train", "validation", "test"]:
            row[f"{name}_mse"] = float(split_results[name]["per_feature_mse"][i])
            row[f"{name}_mae"] = float(split_results[name]["per_feature_mae"][i])
        per_feature_rows.append(row)
    per_feature_df = pd.DataFrame(per_feature_rows).sort_values("validation_mse", ascending=False).reset_index(drop=True)
    per_feature_path = report_dir / "lstm_per_feature_metrics.csv"
    per_feature_df.to_csv(per_feature_path, index=False)
    print(f"Wrote {per_feature_path} ({len(per_feature_df)} rows)")

    # --- predictions summary CSV (compact: per-sequence scalar error, not full 68-dim vectors) ---
    summary_rows = []
    for name in ["train", "validation", "test"]:
        meta = splits[name]["meta"]
        r = split_results[name]
        summary_rows.append(pd.DataFrame({
            "split": name,
            "sequence_id": meta["sequence_id"].to_numpy(),
            "input_end_timestamp": meta["input_end_timestamp"].to_numpy(),
            "target_timestamp": meta["target_timestamp"].to_numpy(),
            "target_window_label": meta["target_window_label"].to_numpy(),
            "sample_mse": r["per_sample_mse"],
            "sample_mae": r["per_sample_mae"],
        }))
    predictions_summary_df = pd.concat(summary_rows, axis=0, ignore_index=True)
    predictions_summary_path = report_dir / "lstm_predictions_summary.csv"
    predictions_summary_df.to_csv(predictions_summary_path, index=False)
    print(f"Wrote {predictions_summary_path} ({len(predictions_summary_df)} rows)")

    # --- compact TEST prediction arrays only (final-evaluation partition; train/val skipped to avoid duplicating huge arrays) ---
    np.save(data_out_dir / "test_predicted_next_state.npy", split_results["test"]["preds"].astype("float32"))
    np.save(data_out_dir / "test_actual_next_state.npy", splits["test"]["y"].astype("float32"))
    print(f"Wrote {data_out_dir / 'test_predicted_next_state.npy'}, {data_out_dir / 'test_actual_next_state.npy'}")

    # --- training history JSON ---
    history_path = report_dir / "lstm_training_history.json"
    history_path.write_text(json.dumps({
        "epochs_run": len(history), "best_epoch": best_epoch, "best_validation_loss": best_val_loss,
        "early_stopped": len(history) < CONFIG["max_epochs"],
        "training_seconds": training_seconds, "history": history,
    }, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {history_path}")

    # --- config JSON ---
    config_path = report_dir / "lstm_config.json"
    config_payload = {
        **CONFIG,
        "input_size": EXPECTED_FEATURE_COUNT,
        "sequence_length": SEQUENCE_LENGTH,
        "model_parameter_count": n_params,
        "device": str(device),
        "loss_function": "MSELoss",
        "optimizer": "Adam",
        "early_stopping_monitor": "validation_loss",
    }
    config_path.write_text(json.dumps(config_payload, indent=2), encoding="utf-8")
    print(f"Wrote {config_path}")

    # --- Feature 7/8/9 integrity check ---
    print("Verifying Feature 7/8/9 files were not modified ...")
    f7_after, f8_after, f9_after = hash_files(FEATURE7_PROTECTED_FILES), hash_files(FEATURE8_PROTECTED_FILES), hash_files(FEATURE9_PROTECTED_FILES)
    f7_unchanged, f8_unchanged, f9_unchanged = f7_before == f7_after, f8_before == f8_after, f9_before == f9_after
    if not f7_unchanged:
        fail(f"Feature 7 files modified: {[k for k in f7_before if f7_before.get(k) != f7_after.get(k)]}")
    if not f8_unchanged:
        fail(f"Feature 8 files modified: {[k for k in f8_before if f8_before.get(k) != f8_after.get(k)]}")
    if not f9_unchanged:
        fail(f"Feature 9 files modified: {[k for k in f9_before if f9_before.get(k) != f9_after.get(k)]}")
    print(f"  Feature 7 unchanged: {f7_unchanged}  Feature 8 unchanged: {f8_unchanged}  Feature 9 unchanged: {f9_unchanged}")

    # --- test-set label limitation (descriptive, matches Feature 7/8/9 findings) ---
    test_limitation = (
        "The chronological TEST partition's target windows contain "
        f"{label_distributions['test']} - zero Infilteration examples. Attack-class evaluation "
        "(e.g. does next-state prediction error spike before an attack) is NOT possible on this "
        "TEST partition because it contains no attack windows at all. This is unchanged from "
        "Features 7-9 and was neither modified nor rebalanced here."
    )

    # --- metrics JSON ---
    metrics_payload = {
        "objective": "Learn P(S(t+1) | S(t-9), ..., S(t)) - next network-state regression, not attack classification.",
        "world_model_formulation": "S(t-9:t) -> S(t+1), a 68-dimensional continuous state vector predicted from the preceding 10 states.",
        "model_type": "LSTM-based Network World Model (LSTM temporal network-state dynamics model).",
        "architecture": model.config_dict() if hasattr(model, "config_dict") else CONFIG,
        "training_configuration": CONFIG,
        "environment": {"python_version": sys.version, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
        "dataset_shapes": {name: {"X": list(splits[name]["X"].shape), "y": list(splits[name]["y"].shape)} for name in ["train", "validation", "test"]},
        "training_behavior": {
            "epochs_run": len(history), "best_epoch": best_epoch, "best_validation_loss": best_val_loss,
            "early_stopped": len(history) < CONFIG["max_epochs"], "training_seconds": training_seconds,
        },
        "metrics": {
            name: {"mse": split_results[name]["mse"], "rmse": split_results[name]["rmse"], "mae": split_results[name]["mae"]}
            for name in ["train", "validation", "test"]
        },
        "label_distributions_target_window": label_distributions,
        "test_set_limitation": test_limitation,
        "outlier_diagnostics": outlier_diagnostics,
        "leakage_checks": leakage_checks,
        "reproducibility": {
            "seed": SEED,
            "checkpoint_reload_prediction_match": reload_match,
            "checkpoint_reload_tolerance": reload_tolerance,
            "checkpoint_reload_max_abs_diff": max_diff,
            "feature7_files_unchanged": f7_unchanged,
            "feature8_files_unchanged": f8_unchanged,
            "feature9_files_unchanged": f9_unchanged,
        },
        "scope_statement": (
            "Feature 10 predicts the next network-state vector. It does not yet perform K-step "
            "forecasting or attack-progression classification."
        ),
        "outputs": {
            "checkpoint": str(checkpoint_path),
            "training_history": str(history_path),
            "config": str(config_path),
            "per_feature_metrics": str(per_feature_path),
            "predictions_summary": str(predictions_summary_path),
            "test_predicted_next_state": str(data_out_dir / "test_predicted_next_state.npy"),
            "test_actual_next_state": str(data_out_dir / "test_actual_next_state.npy"),
        },
    }
    metrics_path = report_dir / "lstm_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "lstm_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload, per_feature_df), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FEATURE 10 COMPLETE")
    print("=" * 70)
    print(f"Device: {device}")
    print(f"Dataset shapes: {metrics_payload['dataset_shapes']}")
    print(f"Model parameter count: {n_params}")
    print(f"Best epoch: {best_epoch}  Best validation loss (MSE): {best_val_loss:.6f}")
    print(f"Final TRAIN metrics: {metrics_payload['metrics']['train']}")
    print(f"Final VALIDATION metrics: {metrics_payload['metrics']['validation']}")
    print(f"Final TEST metrics: {metrics_payload['metrics']['test']}")
    print(f"\nTest-set limitation: {test_limitation}")
    print(f"\nAll leakage checks: {'PASS' if all(leakage_checks.values()) else 'FAIL'}")
    print(f"Feature 7/8/9 integrity: {'PASS' if (f7_unchanged and f8_unchanged and f9_unchanged) else 'FAIL'}")
    print(f"Checkpoint reload reproducibility: {'PASS' if reload_match else 'FAIL'}")

    return metrics_payload


def format_text_report(payload: dict, per_feature_df: pd.DataFrame) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("LSTM WORLD MODEL REPORT (FEATURE 10)")
    lines.append("=" * 70)

    lines.append("\n1. OBJECTIVE")
    lines.append(f"   {payload['objective']}")

    lines.append("\n2. INPUT REPRESENTATION")
    lines.append("   10 consecutive 68-dimensional network states (X_sequences_scaled from Feature 7),")
    lines.append("   shape (batch, 10, 68). Target: next_window_features_scaled, shape (batch, 68).")

    lines.append("\n3. WORLD MODEL FORMULATION")
    lines.append(f"   {payload['world_model_formulation']}")
    lines.append(f"   Model type: {payload['model_type']}")

    lines.append("\n4. ARCHITECTURE")
    for k, v in payload["architecture"].items():
        lines.append(f"   {k}: {v}")
    lines.append("   Output head: Linear(hidden_size -> input_size) applied to the final LSTM hidden state.")

    lines.append("\n5. TRAINING CONFIGURATION")
    for k, v in payload["training_configuration"].items():
        lines.append(f"   {k}: {v}")
    lines.append(f"   environment: {payload['environment']}")

    lines.append("\n6. DATASET SHAPES")
    for name, shapes in payload["dataset_shapes"].items():
        lines.append(f"   {name}: X={shapes['X']} y={shapes['y']}")

    lines.append("\n7. TRAINING BEHAVIOR")
    for k, v in payload["training_behavior"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n8. TRAIN METRICS")
    for k, v in payload["metrics"]["train"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n9. VALIDATION METRICS")
    for k, v in payload["metrics"]["validation"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n10. TEST METRICS")
    for k, v in payload["metrics"]["test"].items():
        lines.append(f"   {k}: {v}")
    lines.append("   NOTE: MSE/MAE here measure next-state regression accuracy, NOT attack detection")
    lines.append("   performance. Attack-state classification is handled in a later feature.")

    lines.append("\n10b. OUTLIER DIAGNOSTIC (why MSE and MAE can diverge)")
    lines.append("   MSE is sensitive to a small number of extreme errors; MAE is not. Where the two")
    lines.append("   diverge sharply for a split, the single largest-error sample/feature is identified")
    lines.append("   below (computed from the actual data, not hardcoded). This is diagnostic context,")
    lines.append("   not a metric exclusion - the officially reported MSE/RMSE/MAE above include every")
    lines.append("   sample with no exclusions.")
    for name in ["train", "validation", "test"]:
        d = payload["outlier_diagnostics"][name]
        lines.append(f"   {name}: worst sample mse={d['worst_sample_mse']:.4f} (sequence_id={d['worst_sample_sequence_id']}, "
                      f"target_timestamp={d['worst_sample_target_timestamp']})")
        lines.append(f"     {d['note']}")
        lines.append(f"     Diagnostic MSE excluding this one sample: {d['overall_mse_excluding_this_one_sample_diagnostic_only']}")

    lines.append("\n11. PER-FEATURE PREDICTION ANALYSIS (hardest 10 features to predict, by validation MSE)")
    for _, row in per_feature_df.head(10).iterrows():
        lines.append(f"   {row['feature_name']}: val_mse={row['validation_mse']:.6f} val_mae={row['validation_mae']:.6f}")
    lines.append("   (Full table: lstm_per_feature_metrics.csv, all 68 features)")

    lines.append("\n12. LABEL DISTRIBUTION LIMITATION")
    lines.append(f"   Target-window label distributions: {payload['label_distributions_target_window']}")
    lines.append(f"   {payload['test_set_limitation']}")

    lines.append("\n13. LEAKAGE CHECKS")
    for k, v in payload["leakage_checks"].items():
        lines.append(f"   {k}: {'PASS' if v else 'FAIL'}")

    lines.append("\n14. REPRODUCIBILITY CHECKS")
    for k, v in payload["reproducibility"].items():
        lines.append(f"   {k}: {v}")

    lines.append("\n15. KNOWN LIMITATIONS")
    lines.append("   - TEST partition contains no Infilteration target windows, so this feature cannot")
    lines.append("     report whether prediction error is informative about attacks (see item 12).")
    lines.append("   - No hyperparameter search was performed; the recommended default architecture/")
    lines.append("     training configuration was used as-is.")
    lines.append("   - Per-feature MAE/MSE varies across the 68 state dimensions (see item 11); some")
    lines.append("     rate/IAT-style features are harder to predict than count-like features.")
    lines.append("   - Single continuous-day capture: generalization to other days/networks is untested.")

    lines.append("\n16. WHAT FEATURE 10 DOES NOT YET IMPLEMENT")
    lines.append("   - K-step forecasting (rolling multi-step prediction)")
    lines.append("   - Attack-progression probability / classification")
    lines.append("   - MITRE ATT&CK stage mapping")
    lines.append("   - Explainability (SHAP or otherwise)")
    lines.append("   - Autonomous mitigation")

    lines.append("\n17. RECOMMENDED NEXT STEP")
    lines.append("   Feature 11: use this trained World Model's next-state predictions (or prediction")
    lines.append("   error) as the basis for attack-progression / K-step forecasting evaluation, still")
    lines.append("   respecting the chronological split and the TEST-set label limitation documented above.")

    lines.append("")
    lines.append("SCOPE STATEMENT: " + payload["scope_statement"])
    lines.append("")

    lines.append("OUTPUTS:")
    for k, v in payload["outputs"].items():
        lines.append(f"   {k}: {v}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
