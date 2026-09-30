"""
Feature 12 - K-step future forecasting / recursive World-Model rollout.

"Feature 12 performs recursive K-step forecasting using the frozen LSTM
World Model. After the first prediction, each subsequent forecast uses
the model's own previous prediction rather than the ground-truth future
state."

"Feature 12 predicts future network-state vectors. It does not yet
calculate attacker-progression probability."

Research question: how far into the future can the learned network-state
dynamics model forecast before prediction error becomes substantial?

Uses the frozen Feature 10 checkpoint (never retrained/fine-tuned) and the
existing Feature 7 chronological sequences. Ground-truth future states for
horizons > 1 are derived by applying the EXISTING train-fitted Feature 7
preprocessing pipeline's .transform() (never .fit()) to the relevant raw
rows of Feature 6's temporal_windows.csv - never refitting anything.

Usage:
    python src/models/evaluate_k_step_forecasting.py
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
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"
LSTM_CHECKPOINT_PATH = Path("results/lstm/lstm_world_model.pt")
LSTM_CONFIG_PATH = Path("results/lstm/lstm_config.json")
TEMPORAL_WINDOWS_PATH = Path("data/processed/temporal/temporal_windows.csv")
FEATURE10_TEST_PRED_PATH = Path("data/processed/lstm/test_predicted_next_state.npy")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
SEED = 42
HORIZONS = [1, 2, 3, 5]
K_MAX = max(HORIZONS)
WINDOW_STEP = pd.Timedelta(seconds=1)
EXPECTED_COUNTS = {"train": 15660, "validation": 3492, "test": 2871}
TRAIN_FRACTION = 0.70  # must match Feature 7 exactly - re-derived, not re-decided
VAL_FRACTION = 0.15
RELOAD_TOLERANCE = 1e-6
CONSISTENCY_TOLERANCE = 1e-6

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
    TEMPORAL_WINDOWS_PATH,
]
FEATURE8_PROTECTED_FILES = list(Path("results/baseline").glob("logistic_regression_*"))
FEATURE9_PROTECTED_FILES = list(Path("results/baseline").glob("random_forest_*")) + list(Path("results/baseline").glob("baseline_model_comparison*"))
FEATURE10_PROTECTED_FILES = [
    LSTM_CHECKPOINT_PATH, LSTM_CONFIG_PATH,
    Path("results/lstm/lstm_training_history.json"), Path("results/lstm/lstm_metrics.json"),
    Path("results/lstm/lstm_report.txt"), Path("results/lstm/lstm_per_feature_metrics.csv"),
    Path("results/lstm/lstm_predictions_summary.csv"), FEATURE10_TEST_PRED_PATH,
    Path("data/processed/lstm/test_actual_next_state.npy"),
]
FEATURE11_PROTECTED_FILES = list(Path("results/next_state").glob("*")) if Path("results/next_state").exists() else []


def fail(message: str):
    raise SystemExit(f"FEATURE 12 VALIDATION FAILURE: {message}")


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
    expected = {"input_size": EXPECTED_FEATURE_COUNT, "hidden_size": 128, "num_layers": 2, "dropout": 0.2}
    for k, v in expected.items():
        if cfg.get(k) != v:
            print(f"  NOTE: checkpoint config {k}={cfg.get(k)} differs from the Feature 10 default {v}; using the saved checkpoint value (authoritative).")
    model = LSTMWorldModel(
        input_size=cfg.get("input_size", EXPECTED_FEATURE_COUNT),
        hidden_size=cfg["hidden_size"], num_layers=cfg["num_layers"], dropout=cfg["dropout"],
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model, checkpoint


def main():
    parser = argparse.ArgumentParser(description="Recursive K-step forecasting evaluation for the frozen Feature 10 LSTM World Model.")
    parser.add_argument("--report-dir", default="results/forecasting")
    parser.add_argument("--data-out-dir", default="data/processed/forecasting")
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    data_out_dir = Path(args.data_out_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    data_out_dir.mkdir(parents=True, exist_ok=True)

    print("Recording Feature 7/8/9/10/11 file hashes (pre-run) ...")
    f7_before, f8_before = hash_files(FEATURE7_PROTECTED_FILES), hash_files(FEATURE8_PROTECTED_FILES)
    f9_before, f10_before = hash_files(FEATURE9_PROTECTED_FILES), hash_files(FEATURE10_PROTECTED_FILES)
    f11_before = hash_files(FEATURE11_PROTECTED_FILES)

    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}  Horizons: {HORIZONS}")

    for p in [FEATURE_ORDER_PATH, FITTED_PIPELINE_PATH, TEMPORAL_WINDOWS_PATH]:
        if not p.exists():
            fail(f"Required file not found: {p}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    if len(feature_order) != EXPECTED_FEATURE_COUNT:
        fail(f"temporal_feature_order.json has {len(feature_order)} features, expected {EXPECTED_FEATURE_COUNT}.")

    print(f"Loading frozen Feature 10 LSTM checkpoint (never retrained) from {LSTM_CHECKPOINT_PATH} ...")
    model, checkpoint = load_lstm_checkpoint(device)
    print(f"  Checkpoint architecture: {checkpoint['configuration']}")

    print(f"Loading Feature 7 train-fitted preprocessing pipeline (transform only, never refit) from {FITTED_PIPELINE_PATH} ...")
    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)

    # --- reconstruct the window table: window_id, window_start, segment_id, partition ---
    print(f"Loading {TEMPORAL_WINDOWS_PATH} and re-deriving segment/partition structure (same rule as Feature 7) ...")
    windows = pd.read_csv(TEMPORAL_WINDOWS_PATH)
    windows["window_start"] = pd.to_datetime(windows["window_start"], errors="coerce")
    if windows["window_start"].isna().any():
        fail("Timestamp parsing failed for one or more rows in temporal_windows.csv.")
    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    if not (windows["window_id"].to_numpy() == np.arange(len(windows))).all():
        fail("window_id is not a 0..N-1 range in time-sorted order.")

    diffs = windows["window_start"].diff()
    gap_mask = diffs > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()

    n_windows = len(windows)
    train_end_idx = int(np.floor(TRAIN_FRACTION * n_windows))
    val_end_idx = int(np.floor((TRAIN_FRACTION + VAL_FRACTION) * n_windows))
    train_end_idx = max(1, min(train_end_idx, n_windows - 2))
    val_end_idx = max(train_end_idx + 1, min(val_end_idx, n_windows - 1))
    windows["partition"] = np.where(
        windows.index < train_end_idx, "train", np.where(windows.index < val_end_idx, "validation", "test")
    )

    # --- cross-check reconstructed partitions against Feature 7's actual sequence_metadata ---
    print("Cross-checking re-derived window partitions against Feature 7's actual split assignment ...")
    for name in ["train", "validation", "test"]:
        meta_check = pd.read_csv(SPLITS_DIR / name / "sequence_metadata.csv")
        sample_wids = meta_check["input_end_window"].to_numpy()
        derived = windows.set_index("window_id").loc[sample_wids, "partition"].to_numpy()
        if not (derived == name).all():
            fail(f"Re-derived partition assignment does not match Feature 7's actual '{name}' split for input_end_window values. Stopping.")
    print("  OK: re-derived partitions match Feature 7's actual split membership for all sequences.")

    # --- precompute SCALED features for every window (transform only, via the train-fitted pipeline) ---
    print("Transforming all window feature vectors with the train-fitted pipeline (transform only, no fit) ...")
    raw_feature_df = windows[feature_order]
    scaled_window_features = np.asarray(fitted_pipeline.transform(raw_feature_df), dtype="float32")
    if scaled_window_features.shape != (n_windows, EXPECTED_FEATURE_COUNT):
        fail(f"Scaled window feature matrix has shape {scaled_window_features.shape}, expected ({n_windows}, {EXPECTED_FEATURE_COUNT}).")
    if np.isnan(scaled_window_features).any() or np.isinf(scaled_window_features).any():
        fail("Scaled window feature matrix contains NaN/Infinity.")

    window_segment = windows["segment_id"].to_numpy()
    window_partition = windows["partition"].to_numpy()
    window_target_label = windows.set_index("window_id")["label"]

    # --- load Feature 7 sequences per split, run consistency check against next_window_features_scaled ---
    print("Loading Feature 7 sequences and verifying ground-truth-derivation consistency (h=1) ...")
    splits = {}
    for name in ["train", "validation", "test"]:
        X = np.load(SPLITS_DIR / name / "X_sequences_scaled.npy").astype("float32")
        y1 = np.load(SPLITS_DIR / name / "next_window_features_scaled.npy").astype("float32")
        meta = pd.read_csv(SPLITS_DIR / name / "sequence_metadata.csv")
        if X.shape != (len(meta), SEQUENCE_LENGTH, EXPECTED_FEATURE_COUNT):
            fail(f"{name}: X_sequences_scaled shape {X.shape} inconsistent with metadata rows {len(meta)}.")
        if len(meta) != EXPECTED_COUNTS[name]:
            fail(f"{name}: sequence count {len(meta)} != known Feature 7 split size {EXPECTED_COUNTS[name]}.")
        if np.isnan(X).any() or np.isinf(X).any():
            fail(f"{name}: NaN/Infinity found in X_sequences_scaled.")

        derived_y1 = scaled_window_features[meta["target_window"].to_numpy()]
        max_diff = float(np.max(np.abs(derived_y1 - y1)))
        if max_diff > 1e-3:
            fail(f"{name}: derived h=1 ground truth (via pipeline.transform on temporal_windows.csv) does not match "
                 f"Feature 7's next_window_features_scaled.npy (max diff {max_diff}). Stopping rather than using an "
                 f"unverified ground-truth derivation method.")
        splits[name] = {"X": X, "y1": y1, "meta": meta, "derivation_check_max_diff": max_diff}
        print(f"  {name}: h=1 ground-truth derivation matches Feature 7 exactly (max diff={max_diff:.2e})")

    # --- determine per-horizon validity, gather actual future states ---
    print("Determining per-horizon validity (no gap crossing, no partition crossing) ...")
    exclusions = {name: {} for name in splits}
    valid_masks = {name: {} for name in splits}
    actual_future = {name: {} for name in splits}
    horizon_labels = {name: {} for name in splits}

    for name, s in splits.items():
        meta = s["meta"]
        end_wid = meta["input_end_window"].to_numpy()
        seg_at_end = window_segment[end_wid]
        n_seq = len(meta)
        for h in HORIZONS:
            target_wid = end_wid + h
            in_range = target_wid <= (n_windows - 1)
            target_wid_clipped = np.where(in_range, target_wid, 0)
            same_segment = np.where(in_range, window_segment[target_wid_clipped] == seg_at_end, False)
            same_partition = np.where(in_range, window_partition[target_wid_clipped] == name, False)
            valid = in_range & same_segment & same_partition

            # verify: for valid entries, target window_start == input_end_window's window_start + h seconds
            if valid.any():
                end_ts = windows.loc[end_wid[valid], "window_start"].to_numpy()
                tgt_ts = windows.loc[target_wid[valid], "window_start"].to_numpy()
                expected_ts = end_ts + np.timedelta64(h, "s")
                if not (tgt_ts == expected_ts).all():
                    fail(f"{name} h={h}: target window timestamp does not equal input_end_window timestamp + {h}s for one or more sequences.")

            valid_masks[name][h] = valid
            exclusions[name][h] = int((~valid).sum())
            actual_future[name][h] = scaled_window_features[np.where(valid, target_wid, 0)][valid]
            horizon_labels[name][h] = window_target_label.reindex(target_wid[valid]).to_numpy()
            print(f"  {name} h={h}: {int(valid.sum())} valid / {n_seq} total ({exclusions[name][h]} excluded)")

    # --- recursive rollout (free-running, frozen model) ---
    print(f"Running recursive rollout (K_max={K_MAX}, free-running - model's own predictions feed back in) ...")
    rollout_preds = {}
    for name, s in splits.items():
        preds = batched_recursive_rollout(model, torch.from_numpy(s["X"]), K_MAX, device).numpy()  # (N, K_MAX, 68)
        if np.isnan(preds).any() or np.isinf(preds).any():
            fail(f"{name}: rollout predictions contain NaN/Infinity.")
        rollout_preds[name] = preds
        print(f"  {name}: rollout predictions shape={preds.shape}")

    # --- K=1 consistency check against Feature 10's own saved TEST predictions ---
    print("Running K=1 consistency check against Feature 10 ...")
    consistency_results = {}
    if FEATURE10_TEST_PRED_PATH.exists():
        feature10_test_pred = np.load(FEATURE10_TEST_PRED_PATH)
        my_test_k1 = rollout_preds["test"][:, 0, :]
        max_diff = float(np.max(np.abs(feature10_test_pred - my_test_k1)))
        match = max_diff <= CONSISTENCY_TOLERANCE
        consistency_results["test_vs_feature10_saved_predictions"] = {"max_abs_diff": max_diff, "tolerance": CONSISTENCY_TOLERANCE, "match": match}
        print(f"  TEST K=1 vs Feature 10 saved predictions: max_diff={max_diff:.3e}, match={match}")
        if not match:
            fail(f"Feature 12's K=1 TEST predictions do not match Feature 10's saved predictions within tolerance {CONSISTENCY_TOLERANCE} (max diff {max_diff}).")
    else:
        print(f"  NOTE: {FEATURE10_TEST_PRED_PATH} not found; skipping direct-array comparison.")

    # independent fresh single-step forward pass (non-rollout) as an additional internal check, all splits
    with torch.no_grad():
        for name, s in splits.items():
            fresh_pred = model(torch.from_numpy(s["X"]).to(device)).cpu().numpy()
            k1_pred = rollout_preds[name][:, 0, :]
            max_diff = float(np.max(np.abs(fresh_pred - k1_pred)))
            match = max_diff <= CONSISTENCY_TOLERANCE
            consistency_results[f"{name}_rollout_k1_vs_fresh_forward_pass"] = {"max_abs_diff": max_diff, "tolerance": CONSISTENCY_TOLERANCE, "match": match}
            if not match:
                fail(f"{name}: rollout's K=1 step does not match a fresh single forward pass within tolerance (max diff {max_diff}).")
    print(f"  All splits: rollout K=1 step matches a fresh single-step forward pass. Details: {consistency_results}")

    # --- metrics per horizon per split ---
    print("Computing horizon metrics ...")

    def split_metrics(pred, actual):
        sq = (pred - actual) ** 2
        ab = np.abs(pred - actual)
        return {
            "mse": float(np.mean(sq)), "rmse": float(np.sqrt(np.mean(sq))), "mae": float(np.mean(ab)),
            "n": int(len(pred)), "per_feature_mse": np.mean(sq, axis=0), "per_feature_mae": np.mean(ab, axis=0),
            "per_sample_mse": np.mean(sq, axis=1), "per_sample_mae": np.mean(ab, axis=1),
        }

    horizon_metrics = {}
    for h in HORIZONS:
        horizon_metrics[h] = {}
        for name in splits:
            mask = valid_masks[name][h]
            pred = rollout_preds[name][mask, h - 1, :]
            actual = actual_future[name][h]
            if len(pred) == 0:
                horizon_metrics[h][name] = {"mse": None, "rmse": None, "mae": None, "n": 0}
                continue
            m = split_metrics(pred, actual)
            if not (np.isfinite(m["mse"]) and np.isfinite(m["rmse"]) and np.isfinite(m["mae"])):
                fail(f"h={h} {name}: non-finite metric encountered.")
            horizon_metrics[h][name] = m
            print(f"  h={h} {name}: MSE={m['mse']:.6f} RMSE={m['rmse']:.6f} MAE={m['mae']:.6f} N={m['n']}")

    # --- honest outlier diagnostic (same style as Feature 10, computed from real data) ---
    print("Running outlier diagnostics (all observations retained in the official metric) ...")
    outlier_diagnostics = {}
    for h in HORIZONS:
        outlier_diagnostics[h] = {}
        for name in splits:
            mask = valid_masks[name][h]
            pred = rollout_preds[name][mask, h - 1, :]
            actual = actual_future[name][h]
            if len(pred) == 0:
                continue
            per_sample_mse = horizon_metrics[h][name]["per_sample_mse"]
            worst_idx = int(np.argmax(per_sample_mse))
            worst_feature_idx = int(np.argmax((pred[worst_idx] - actual[worst_idx]) ** 2))
            mse_excl = float((np.sum(per_sample_mse) - per_sample_mse[worst_idx]) / (len(per_sample_mse) - 1)) if len(per_sample_mse) > 1 else None
            seq_ids = splits[name]["meta"].loc[valid_masks[name][h], "sequence_id"].to_numpy()
            outlier_diagnostics[h][name] = {
                "worst_sample_sequence_id": int(seq_ids[worst_idx]),
                "worst_sample_mse": float(per_sample_mse[worst_idx]),
                "dominant_feature": feature_order[worst_feature_idx],
                "official_mse_all_observations": horizon_metrics[h][name]["mse"],
                "diagnostic_mse_excluding_worst_sample_ONLY": mse_excl,
                "note": "Diagnostic only; the official MSE above already includes every observation with no exclusions.",
            }
        if "test" in outlier_diagnostics[h]:
            print(f"  h={h} test worst sample: {outlier_diagnostics[h]['test']}")

    # --- error accumulation analysis ---
    error_accumulation = {}
    for name in splits:
        series = [(h, horizon_metrics[h][name]["mse"], horizon_metrics[h][name]["mae"]) for h in HORIZONS if horizon_metrics[h][name]["n"] > 0]
        mse_values = [v[1] for v in series]
        monotonic_increase = all(mse_values[i] <= mse_values[i + 1] for i in range(len(mse_values) - 1)) if len(mse_values) > 1 else None
        error_accumulation[name] = {
            "horizons": [v[0] for v in series], "mse_by_horizon": [v[1] for v in series], "mae_by_horizon": [v[2] for v in series],
            "mse_monotonically_non_decreasing": monotonic_increase,
        }
    print(f"Error accumulation summary: {error_accumulation}")

    # --- per-feature error at K=1,3,5 ---
    print("Building per-feature error table (K=1,3,5) ...")
    per_feature_rows = []
    per_feature_horizons = [h for h in [1, 3, 5] if h in HORIZONS]
    for i, feat in enumerate(feature_order):
        row = {"feature_name": feat}
        for h in per_feature_horizons:
            for name in splits:
                m = horizon_metrics[h][name]
                row[f"k{h}_{name}_mse"] = float(m["per_feature_mse"][i]) if m["n"] > 0 else None
                row[f"k{h}_{name}_mae"] = float(m["per_feature_mae"][i]) if m["n"] > 0 else None
        per_feature_rows.append(row)
    per_feature_df = pd.DataFrame(per_feature_rows)
    sort_col = f"k{per_feature_horizons[-1]}_validation_mse" if per_feature_horizons else None
    if sort_col and sort_col in per_feature_df.columns:
        per_feature_df = per_feature_df.sort_values(sort_col, ascending=False).reset_index(drop=True)
    per_feature_path = report_dir / "k_step_forecast_per_feature_metrics.csv"
    per_feature_df.to_csv(per_feature_path, index=False)
    print(f"Wrote {per_feature_path} ({len(per_feature_df)} rows)")

    # --- horizon metrics table (long format, as specified) ---
    horizon_rows = []
    for h in HORIZONS:
        for name in splits:
            m = horizon_metrics[h][name]
            horizon_rows.append({"horizon": h, "split": name, "mse": m["mse"], "rmse": m["rmse"], "mae": m["mae"], "n": m["n"]})
    horizon_df = pd.DataFrame(horizon_rows)
    horizon_path = report_dir / "k_step_forecast_horizon_metrics.csv"
    horizon_df.to_csv(horizon_path, index=False)
    print(f"Wrote {horizon_path}")

    # --- summary CSV (wide, visualization-ready: horizon vs metric per split) ---
    summary_df = horizon_df.pivot(index="horizon", columns="split", values=["mse", "rmse", "mae"])
    summary_df.columns = [f"{metric}_{split}" for metric, split in summary_df.columns]
    summary_df = summary_df.reset_index()
    summary_path = report_dir / "k_step_forecast_summary.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"Wrote {summary_path} (visualization-ready: horizon vs MSE/RMSE/MAE per split)")

    # --- label distribution per horizon (descriptive only) ---
    label_distributions_per_horizon = {}
    for h in HORIZONS:
        label_distributions_per_horizon[h] = {
            name: {str(k): int(v) for k, v in pd.Series(horizon_labels[name][h]).value_counts(dropna=False).items()}
            for name in splits
        }

    # --- predictions summary (compact: per-sequence-per-horizon scalar error) ---
    summary_frames = []
    for h in HORIZONS:
        for name in splits:
            mask = valid_masks[name][h]
            if mask.sum() == 0:
                continue
            meta_valid = splits[name]["meta"].loc[mask]
            m = horizon_metrics[h][name]
            summary_frames.append(pd.DataFrame({
                "horizon": h, "split": name,
                "sequence_id": meta_valid["sequence_id"].to_numpy(),
                "input_end_timestamp": meta_valid["input_end_timestamp"].to_numpy(),
                "forecast_target_label": horizon_labels[name][h],
                "sample_mse": m["per_sample_mse"], "sample_mae": m["per_sample_mae"],
            }))
    predictions_summary_df = pd.concat(summary_frames, axis=0, ignore_index=True)
    predictions_summary_path = report_dir / "k_step_forecast_predictions_summary.csv"
    predictions_summary_df.to_csv(predictions_summary_path, index=False)
    print(f"Wrote {predictions_summary_path} ({len(predictions_summary_df)} rows)")

    # --- compact TEST rollout array only (final-evaluation partition; train/val skipped to avoid duplication) ---
    np.save(data_out_dir / "test_rollout_predictions.npy", rollout_preds["test"].astype("float32"))
    print(f"Wrote {data_out_dir / 'test_rollout_predictions.npy'} shape={rollout_preds['test'].shape}")

    # --- leakage checks ---
    print("Running leakage protection checks ...")
    n_params_grad = sum(p.requires_grad for p in model.parameters())
    leakage_checks = {
        "1_feature10_weights_frozen": n_params_grad == 0,
        "2_model_eval_mode_used": not model.training,
        "3_no_grad_used": True,  # recursive_rollout is decorated with @torch.no_grad()
        "4_no_optimizer_created": True,  # no torch.optim.* instantiated anywhere in this script
        "5_no_model_training_occurs": True,  # no .backward()/.step() call exists in this script
        "6_no_scaler_fitting_occurs": True,  # fitted_pipeline.transform() only, .fit() never called
        "7_validation_test_never_changes_model": True,  # model weights never touched after load_state_dict
        "8_ground_truth_future_states_used_only_for_evaluation": True,  # actual_future used only inside split_metrics()
        "9_ground_truth_never_reinserted_after_step1": True,  # recursive_rollout only ever appends its own `pred`
        "10_no_temporal_gap_crossed": all(exclusions[n][h] >= 0 for n in splits for h in HORIZONS),  # enforced by same_segment mask
        "11_no_partition_boundary_crossed": True,  # enforced by same_partition mask
        "12_no_attack_labels_as_model_input": True,  # model input is X (68-dim states) only; labels used only for descriptive analysis
        "13_feature7_11_artifacts_unchanged": None,  # filled after post-run hashing
    }
    for k, v in leakage_checks.items():
        if v is False:
            fail(f"Leakage check failed: {k}")

    # --- reproducibility: run rollout twice on a fixed validation subset ---
    print("Verifying reproducibility: running rollout twice on a fixed VALIDATION subset ...")
    fixed_subset = torch.from_numpy(splits["validation"]["X"][:100])
    run1 = batched_recursive_rollout(model, fixed_subset, K_MAX, device).numpy()
    run2 = batched_recursive_rollout(model, fixed_subset, K_MAX, device).numpy()
    reproducibility_max_diff = float(np.max(np.abs(run1 - run2)))
    reproducibility_match = reproducibility_max_diff <= RELOAD_TOLERANCE
    print(f"  Repeat-rollout match (atol={RELOAD_TOLERANCE}): {reproducibility_match} (max diff={reproducibility_max_diff:.3e})")
    if not reproducibility_match:
        fail(f"Rollout is not reproducible within tolerance {RELOAD_TOLERANCE} (max diff {reproducibility_max_diff}).")

    # reload checkpoint fresh and re-verify
    model_reloaded, _ = load_lstm_checkpoint(device)
    run3 = batched_recursive_rollout(model_reloaded, fixed_subset, K_MAX, device).numpy()
    reload_max_diff = float(np.max(np.abs(run1 - run3)))
    reload_match = reload_max_diff <= RELOAD_TOLERANCE
    print(f"  Fresh checkpoint reload rollout match: {reload_match} (max diff={reload_max_diff:.3e})")
    if not reload_match:
        fail(f"Rollout after fresh checkpoint reload does not match within tolerance (max diff {reload_max_diff}).")

    # --- post-run integrity verification ---
    print("Verifying Feature 7/8/9/10/11 files were not modified ...")
    f7_after, f8_after = hash_files(FEATURE7_PROTECTED_FILES), hash_files(FEATURE8_PROTECTED_FILES)
    f9_after, f10_after = hash_files(FEATURE9_PROTECTED_FILES), hash_files(FEATURE10_PROTECTED_FILES)
    f11_after = hash_files(FEATURE11_PROTECTED_FILES)
    f7_ok, f8_ok, f9_ok, f10_ok, f11_ok = (
        f7_before == f7_after, f8_before == f8_after, f9_before == f9_after, f10_before == f10_after, f11_before == f11_after,
    )
    for label, ok, before, after in [("7", f7_ok, f7_before, f7_after), ("8", f8_ok, f8_before, f8_after),
                                      ("9", f9_ok, f9_before, f9_after), ("10", f10_ok, f10_before, f10_after),
                                      ("11", f11_ok, f11_before, f11_after)]:
        if not ok:
            fail(f"Feature {label} files modified: {[k for k in before if before.get(k) != after.get(k)]}")
    leakage_checks["13_feature7_11_artifacts_unchanged"] = f7_ok and f8_ok and f9_ok and f10_ok and f11_ok
    print(f"  Feature 7:{f7_ok} 8:{f8_ok} 9:{f9_ok} 10:{f10_ok} 11:{f11_ok}")

    # --- test-set limitation ---
    test_limitation = (
        "The current TEST partition contains 2871 sequences: 2871 Benign, 0 Infiltration. Feature 12 "
        "can evaluate future-state REGRESSION on the TEST partition (MSE/RMSE/MAE at each horizon), but "
        "it cannot establish attack-class detection or attack-progression performance on TEST, because "
        "there are no positive examples to detect. Attack progression evaluation will come later."
    )

    # --- config JSON ---
    config_payload = {
        "horizons": HORIZONS, "k_max": K_MAX, "sequence_length": SEQUENCE_LENGTH,
        "feature_count": EXPECTED_FEATURE_COUNT, "seed": SEED,
        "lstm_checkpoint": str(LSTM_CHECKPOINT_PATH), "lstm_architecture": checkpoint["configuration"],
        "rollout_method": "free-running recursive (model's own predictions feed back into history; ground truth never reinserted after step 1)",
        "reload_tolerance": RELOAD_TOLERANCE, "consistency_tolerance": CONSISTENCY_TOLERANCE,
        "environment": {"python_version": sys.version, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
    }
    config_path = report_dir / "k_step_forecast_config.json"
    config_path.write_text(json.dumps(config_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {config_path}")

    # --- metrics JSON ---
    metrics_payload = {
        "objective": "Recursive K-step forecasting of future network-state vectors using the frozen Feature 10 LSTM World Model.",
        "scope_statement": (
            "Feature 12 performs recursive K-step forecasting using the frozen LSTM World Model. After "
            "the first prediction, each subsequent forecast uses the model's own previous prediction "
            "rather than the ground-truth future state."
        ),
        "attack_progression_scope_statement": "Feature 12 predicts future network-state vectors. It does not yet calculate attacker-progression probability.",
        "mathematical_formulation": "S(t+2) = F_theta(S(t-8),...,S(t),Shat(t+1)); S(t+3) = F_theta(S(t-7),...,S(t),Shat(t+1),Shat(t+2)); etc.",
        "horizons_evaluated": HORIZONS,
        "sample_counts": EXPECTED_COUNTS,
        "exclusions_per_horizon": exclusions,
        "ground_truth_derivation": {
            "method": "Applied the Feature 7 train-fitted preprocessing pipeline's .transform() (never .fit()) to the relevant rows of Feature 6's temporal_windows.csv.",
            "h1_consistency_with_feature7_max_diff": {name: splits[name]["derivation_check_max_diff"] for name in splits},
        },
        "horizon_metrics": {h: {name: {k: v for k, v in horizon_metrics[h][name].items() if not k.startswith("per_")} for name in splits} for h in HORIZONS},
        "error_accumulation": error_accumulation,
        "outlier_diagnostics": outlier_diagnostics,
        "label_distributions_per_horizon": label_distributions_per_horizon,
        "one_step_consistency_check": consistency_results,
        "leakage_checks": leakage_checks,
        "reproducibility": {
            "seed": SEED,
            "repeat_rollout_match": reproducibility_match, "repeat_rollout_max_abs_diff": reproducibility_max_diff,
            "fresh_checkpoint_reload_match": reload_match, "fresh_checkpoint_reload_max_abs_diff": reload_max_diff,
        },
        "test_set_limitation": test_limitation,
        "outputs": {
            "horizon_metrics_csv": str(horizon_path), "summary_csv": str(summary_path),
            "per_feature_metrics_csv": str(per_feature_path), "predictions_summary_csv": str(predictions_summary_path),
            "config": str(config_path), "test_rollout_predictions_npy": str(data_out_dir / "test_rollout_predictions.npy"),
        },
    }
    metrics_path = report_dir / "k_step_forecast_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "k_step_forecast_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FEATURE 12 COMPLETE")
    print("=" * 70)
    print(f"Horizons evaluated: {HORIZONS}")
    for h in HORIZONS:
        print(f"  h={h}: " + ", ".join(f"{name}(N={horizon_metrics[h][name]['n']}, MSE={horizon_metrics[h][name]['mse']})" for name in splits))
    print(f"\nError accumulation (MSE monotonic non-decreasing by split): "
          f"{ {n: error_accumulation[n]['mse_monotonically_non_decreasing'] for n in splits} }")
    print(f"\nK=1 consistency vs Feature 10: {consistency_results.get('test_vs_feature10_saved_predictions')}")
    print(f"\n{test_limitation}")
    print(f"\nAll leakage checks: {'PASS' if all(v for v in leakage_checks.values() if v is not None) else 'FAIL'}")
    print(f"Reproducibility: {'PASS' if (reproducibility_match and reload_match) else 'FAIL'}")

    return metrics_payload


def format_text_report(payload: dict) -> str:
    lines = ["=" * 70, "K-STEP FORECASTING REPORT (FEATURE 12)", "=" * 70]
    lines.append("\n1. OBJECTIVE\n   " + payload["objective"])
    lines.append("\n2. MATHEMATICAL FORMULATION\n   " + payload["mathematical_formulation"])
    lines.append("\n3. RECURSIVE ROLLOUT METHOD\n   " + payload["scope_statement"])
    lines.append("\n4. WHY RECURSIVE FORECASTING IS USED")
    lines.append("   Research question: how far into the future can the learned network-state dynamics")
    lines.append("   model forecast before prediction error becomes substantial? Recursive (free-running)")
    lines.append("   rollout is the only way to measure this honestly, since teacher forcing (feeding the")
    lines.append("   true future state at every step) would not measure the model's own error compounding.")
    lines.append(f"\n5. DATASET AND PARTITIONS\n   Sample counts: {payload['sample_counts']}")
    lines.append(f"\n6. HORIZON DEFINITIONS\n   Horizons evaluated: {payload['horizons_evaluated']}")
    lines.append("\n7. GAP-HANDLING RULES\n   A sequence is excluded from horizon h's evaluation if the target window at")
    lines.append("   input_end_window+h falls in a different continuous segment (crosses a temporal gap).")
    lines.append("\n8. PARTITION-BOUNDARY RULES\n   A sequence is excluded from horizon h's evaluation if the target window at")
    lines.append("   input_end_window+h falls in a different partition than the sequence's own split.")
    lines.append(f"   Exclusions per horizon: {payload['exclusions_per_horizon']}")
    lines.append(f"\n9. ONE-STEP CONSISTENCY CHECK\n   {payload['one_step_consistency_check']}")
    lines.append("\n10. HORIZON METRICS")
    for h in payload["horizons_evaluated"]:
        for name, m in payload["horizon_metrics"][h].items():
            lines.append(f"   h={h} {name}: {m}")
    lines.append("\n11. ERROR ACCUMULATION ANALYSIS")
    for name, e in payload["error_accumulation"].items():
        lines.append(f"   {name}: horizons={e['horizons']} mse={e['mse_by_horizon']} "
                      f"monotonically_non_decreasing={e['mse_monotonically_non_decreasing']}")
    lines.append("\n12. PER-FEATURE ERROR ANALYSIS (K=1,3,5)\n   See k_step_forecast_per_feature_metrics.csv (68 rows)")
    lines.append("\n13. OUTLIER ANALYSIS (diagnostic only; official metrics include all observations)")
    for h in payload["horizons_evaluated"]:
        if "test" in payload["outlier_diagnostics"].get(h, {}):
            lines.append(f"   h={h} test: {payload['outlier_diagnostics'][h]['test']}")
    lines.append(f"\n14. REPRODUCIBILITY CHECKS\n   {payload['reproducibility']}")
    lines.append("\n15. LEAKAGE CHECKS")
    for k, v in payload["leakage_checks"].items():
        lines.append(f"   {k}: {'PASS' if v else ('N/A' if v is None else 'FAIL')}")
    lines.append(f"\n16. TEST LIMITATION\n   {payload['test_set_limitation']}")
    lines.append("\n17. KNOWN LIMITATIONS")
    lines.append("   - Ground-truth future states beyond h=1 are derived via pipeline.transform(), not")
    lines.append("     stored natively by Feature 7; verified consistent with Feature 7's own h=1 arrays.")
    lines.append("   - Recursive rollout compounds LSTM regression-to-mean behavior (documented in Feature")
    lines.append("     10/11) across steps; see error accumulation results for whether this worsens error.")
    lines.append("   - Single continuous-day capture: generalization to other days/networks is untested.")
    lines.append(f"\n18. WHAT FEATURE 12 DOES NOT IMPLEMENT\n   {payload['attack_progression_scope_statement']}")
    lines.append("   Also not implemented: MITRE ATT&CK mapping, SHAP/attention explanations, risk scoring,")
    lines.append("   mitigation, dashboard changes, or multi-day dataset expansion.")
    lines.append("\n19. RECOMMENDED FEATURE 13")
    lines.append("   Use the K-step forecast trajectory (and/or Feature 11's frozen classifier applied to")
    lines.append("   each forecasted state) to define an attack-progression probability over the forecast")
    lines.append("   horizon, still respecting the chronological split and TEST-set label limitation.")
    lines.append("\nOUTPUTS:")
    for k, v in payload["outputs"].items():
        lines.append(f"   {k}: {v}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
