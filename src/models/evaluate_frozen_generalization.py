"""
Feature 16 - Attack-Diverse Frozen Generalization Evaluation.

Evaluates the EXISTING frozen Feature 8-15 models on three unseen external
CSE-CIC-IDS2018 capture days, WITHOUT retraining, refitting, or tuning
anything. External labels are used ONLY to compute evaluation metrics.

TWO EVALUATION VIEWS (documented, never conflated):
    A. BINARY ANOMALY VIEW (primary, all 3 days): Benign (0) vs
       non-Benign (1), generically. This is the only view that is
       scientifically valid for Wednesday-14-02-2018 (FTP-BruteForce/
       SSH-Bruteforce) and Wednesday-21-02-2018 (DDOS-HOIC/DDOS-LOIC-UDP),
       since the trained classifier has never seen those attack families
       - results there are GENERALIZATION/TRANSFER diagnostics, not
       validated attack-family classification.
    B. TRAINING-LABEL-COMPATIBLE VIEW (Wednesday-28-02-2018 only): the
       external label set is exactly {Benign, Infilteration}, identical
       in semantics to the training target, so this view IS directly
       comparable to Features 8/9/11/13's own Thursday-01-03-2018 results.

Frozen components loaded (never fit/trained/tuned here):
    - results/baseline/logistic_regression_model.joblib   (Feature 8)
    - results/baseline/random_forest_model.joblib          (Feature 9)
    - results/lstm/lstm_world_model.pt                     (Feature 10)
    - results/next_state/next_state_attack_classifier.joblib (Feature 11)
    - src/models/k_step_forecaster.py :: batched_recursive_rollout (Feature 12)
    - src/models/attack_progression_probability.py                 (Feature 13)
    - src/models/mitre_stage_mapper.py                              (Feature 14)
    - src/models/model_explainer.py                                 (Feature 15)
    - data/processed/splits/preprocessing_pipeline_train_fitted.joblib
      (Feature 7 - used via .transform() only, inside prepare_external_dataset.py;
       never refit here or there)

Usage:
    python src/models/evaluate_frozen_generalization.py
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
import torch
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, accuracy_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402
from attack_progression_probability import load_frozen_classifier, infiltration_probability, threshold_predict, DEFAULT_THRESHOLD  # noqa: E402
import mitre_stage_mapper as mapper  # noqa: E402
import model_explainer as expl  # noqa: E402

EXTERNAL_DAYS = ["Wednesday-28-02-2018", "Wednesday-14-02-2018", "Wednesday-21-02-2018"]
EXTERNAL_DIR = Path("data/processed/frozen_generalization")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
LOGREG_PATH = Path("results/baseline/logistic_regression_model.joblib")
RF_PATH = Path("results/baseline/random_forest_model.joblib")
LSTM_CHECKPOINT_PATH = Path("results/lstm/lstm_world_model.pt")
CLASSIFIER_PATH = Path("results/next_state/next_state_attack_classifier.joblib")
FITTED_PIPELINE_PATH = Path("data/processed/splits/preprocessing_pipeline_train_fitted.joblib")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
HORIZONS = [1, 2, 3, 5]
K_MAX = max(HORIZONS)
EXPLAIN_SAMPLE_SIZE = 10

# Only Wednesday-28-02-2018 has label semantics genuinely comparable to the trained target.
TRAINING_COMPATIBLE_DAYS = {"Wednesday-28-02-2018"}

PROTECTED_FEATURE1_15_FILES = (
    [
        Path("data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv"),
        Path("data/processed/splits/preprocessing_pipeline_train_fitted.joblib"),
        Path("data/processed/splits/train/X_sequences_scaled.npy"),
        Path("data/processed/splits/validation/X_sequences_scaled.npy"),
        Path("data/processed/splits/test/X_sequences_scaled.npy"),
        LOGREG_PATH, RF_PATH, LSTM_CHECKPOINT_PATH, CLASSIFIER_PATH,
        Path("results/temporal_feature_order.json"), Path("results/model_feature_list.json"),
        Path("results/state_schema.json"),
    ]
    + (list(Path("results/attack_progression").glob("*")) if Path("results/attack_progression").exists() else [])
    + (list(Path("results/mitre").glob("*")) if Path("results/mitre").exists() else [])
    + (list(Path("results/explainability").glob("*")) if Path("results/explainability").exists() else [])
)


def fail(message: str):
    raise SystemExit(f"FEATURE 16 VALIDATION FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: list) -> dict:
    return {str(p): file_md5(p) for p in paths if p.exists()}


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


def compute_classification_metrics(y_true, y_pred, y_proba_pos, threshold=DEFAULT_THRESHOLD):
    y_true = np.asarray(y_true).astype(int)
    n = len(y_true)
    n_pos, n_neg = int((y_true == 1).sum()), int((y_true == 0).sum())
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp) / (fp + tn) if (fp + tn) > 0 else None
    accuracy = float(accuracy_score(y_true, y_pred)) if n > 0 else None

    result = {
        "n_samples": n, "n_positive": n_pos, "n_negative": n_neg,
        "attack_prevalence_pct": round(n_pos / n * 100, 4) if n > 0 else None,
        "predicted_positive_count": int((y_pred == 1).sum()), "predicted_negative_count": int((y_pred == 0).sum()),
        "accuracy": accuracy,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": fpr,
        "false_positive_rate_undefined_reason": None if fpr is not None else "FP+TN (actual negative count) is 0.",
        "roc_auc": None, "roc_auc_undefined_reason": None,
        "pr_auc": None, "pr_auc_undefined_reason": None,
        "precision": None, "recall": None, "f1": None,
        "precision_undefined_reason": None, "recall_undefined_reason": None,
    }
    prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=np.nan))
    result["precision"] = None if np.isnan(prec) else prec
    result["recall"] = None if np.isnan(rec) else rec
    result["f1"] = None if np.isnan(f1) else f1
    if result["precision"] is None:
        result["precision_undefined_reason"] = "TP+FP = 0 (model predicted zero positives): 0/0."
    if result["recall"] is None:
        result["recall_undefined_reason"] = "TP+FN = 0 (zero actual positives): 0/0."

    if n_pos > 0 and n_neg > 0:
        result["roc_auc"] = float(roc_auc_score(y_true, y_proba_pos))
        result["pr_auc"] = float(average_precision_score(y_true, y_proba_pos))
    else:
        reason = f"Only one class present in y_true (n_positive={n_pos}, n_negative={n_neg})."
        result["roc_auc_undefined_reason"] = reason
        result["pr_auc_undefined_reason"] = reason
    return result


def regression_metrics(pred, actual):
    sq = (pred - actual) ** 2
    ab = np.abs(pred - actual)
    return {
        "mse": float(np.mean(sq)), "rmse": float(np.sqrt(np.mean(sq))), "mae": float(np.mean(ab)), "n": int(len(pred)),
        "per_feature_mse": np.mean(sq, axis=0), "per_feature_mae": np.mean(ab, axis=0), "per_sample_mse": np.mean(sq, axis=1),
    }


def horizon_validity_external(windows, meta, h):
    """Segment-continuity-only validity check (no partition concept for external held-out data)."""
    end_wid = meta["input_end_window"].to_numpy()
    seg = windows.set_index("window_id")["segment_id"]
    n_windows = len(windows)
    target_wid = end_wid + h
    in_range = target_wid <= (n_windows - 1)
    clipped = np.where(in_range, target_wid, 0)
    end_seg = seg.reindex(end_wid).to_numpy()
    target_seg = seg.reindex(clipped).to_numpy()
    valid = in_range & (target_seg == end_seg)
    return valid, target_wid


def load_external_day(day_label):
    day_dir = EXTERNAL_DIR / day_label
    windows = pd.read_csv(day_dir / "temporal_windows.csv")
    windows["window_start"] = pd.to_datetime(windows["window_start"])
    seq_meta = pd.read_csv(day_dir / "sequence_metadata.csv")
    X_scaled = np.load(day_dir / "X_sequences_scaled.npy")
    next_scaled = np.load(day_dir / "next_window_features_scaled.npy")
    with open(day_dir / "prep_report.json", encoding="utf-8") as f:
        prep_report = json.load(f)
    return {"windows": windows, "seq_meta": seq_meta, "X_scaled": X_scaled, "next_scaled": next_scaled, "prep_report": prep_report}


def main():
    parser = argparse.ArgumentParser(description="Feature 16: attack-diverse frozen generalization evaluation.")
    parser.add_argument("--report-dir", default="results/frozen_generalization")
    parser.add_argument("--data-out-dir", default="data/processed/frozen_generalization")
    args = parser.parse_args()
    report_dir = Path(args.report_dir)
    (report_dir / "confusion_matrices").mkdir(parents=True, exist_ok=True)
    data_out_dir = Path(args.data_out_dir)

    print("Recording Feature 1-15 protected file hashes (pre-run) ...")
    hashes_before = hash_files(PROTECTED_FEATURE1_15_FILES)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    for p in [FEATURE_ORDER_PATH, LOGREG_PATH, RF_PATH, LSTM_CHECKPOINT_PATH, CLASSIFIER_PATH]:
        if not p.exists():
            fail(f"Required frozen artifact not found: {p}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]

    print("Loading frozen models (never trained/fit here) ...")
    logreg_model = joblib.load(LOGREG_PATH)
    rf_model = joblib.load(RF_PATH)
    lstm_model, lstm_checkpoint = load_lstm_checkpoint(device)
    classifier = load_frozen_classifier(CLASSIFIER_PATH)

    for day in EXTERNAL_DAYS:
        day_dir = EXTERNAL_DIR / day
        for fname in ["temporal_windows.csv", "sequence_metadata.csv", "X_sequences_scaled.npy", "next_window_features_scaled.npy", "prep_report.json"]:
            if not (day_dir / fname).exists():
                fail(f"Required prepared external artifact missing: {day_dir / fname}. Run src/data/prepare_external_dataset.py first.")

    all_results = {}
    for day in EXTERNAL_DAYS:
        print(f"\n{'='*70}\nEvaluating: {day}\n{'='*70}")
        data = load_external_day(day)
        windows, seq_meta, X_scaled, next_scaled = data["windows"], data["seq_meta"], data["X_scaled"], data["next_scaled"]
        n_seq = len(seq_meta)
        print(f"  {n_seq} sequences, {len(windows)} windows.")

        y_true_k1 = seq_meta["target_window_binary_target"].to_numpy().astype(int)
        labels_k1 = seq_meta["target_window_label"].to_numpy()

        result = {"day": day, "n_sequences": n_seq, "n_windows": len(windows),
                  "attack_prevalence_windows_pct": round(float((windows["binary_target"] == 1).mean() * 100), 4),
                  "training_compatible_view_applicable": day in TRAINING_COMPATIBLE_DAYS}

        if n_seq == 0:
            print(f"  WARNING: 0 valid sequences for {day}; skipping model evaluation for this day.")
            all_results[day] = result
            continue

        # --- Feature 8/9: LogReg + RF baseline (flattened 680-dim, binary anomaly view) ---
        print("  [Baselines] Logistic Regression + Random Forest (frozen, flattened 680-dim input) ...")
        X_flat = X_scaled.reshape(n_seq, SEQUENCE_LENGTH * EXPECTED_FEATURE_COUNT)
        logreg_pred = logreg_model.predict(X_flat)
        logreg_proba = logreg_model.predict_proba(X_flat)[:, list(logreg_model.classes_).index(1)]
        rf_pred = rf_model.predict(X_flat)
        rf_proba = rf_model.predict_proba(X_flat)[:, list(rf_model.classes_).index(1)]
        result["logistic_regression_binary"] = compute_classification_metrics(y_true_k1, logreg_pred, logreg_proba)
        result["random_forest_binary"] = compute_classification_metrics(y_true_k1, rf_pred, rf_proba)

        # --- Feature 10: LSTM one-step regression ---
        print("  [LSTM] One-step next-state regression (frozen) ...")
        rollout_full = batched_recursive_rollout(lstm_model, torch.from_numpy(X_scaled), K_MAX, device).numpy()
        lstm_k1_pred = rollout_full[:, 0, :]
        lstm_metrics = regression_metrics(lstm_k1_pred, next_scaled)
        worst_idx = int(np.argmax(lstm_metrics["per_sample_mse"]))
        result["lstm_one_step_regression"] = {
            "mse": lstm_metrics["mse"], "rmse": lstm_metrics["rmse"], "mae": lstm_metrics["mae"], "n": lstm_metrics["n"],
            "worst_sample_sequence_id": int(seq_meta["sequence_id"].iloc[worst_idx]),
            "worst_sample_mse": float(lstm_metrics["per_sample_mse"][worst_idx]),
            "worst_sample_dominant_feature": feature_order[int(np.argmax((lstm_k1_pred[worst_idx] - next_scaled[worst_idx]) ** 2))],
        }
        per_feature_mse = {feature_order[i]: float(lstm_metrics["per_feature_mse"][i]) for i in range(EXPECTED_FEATURE_COUNT)}
        top10_worst_features = sorted(per_feature_mse.items(), key=lambda x: x[1], reverse=True)[:10]
        result["lstm_one_step_regression"]["top10_hardest_features"] = top10_worst_features

        # --- Feature 11: next-state classifier, oracle + full pipeline (binary anomaly view) ---
        print("  [Feature 11] Next-state classifier: oracle (ground-truth state) + full pipeline (LSTM-predicted state) ...")
        oracle_proba = infiltration_probability(classifier, next_scaled)
        oracle_pred = threshold_predict(oracle_proba)
        pipeline_proba = infiltration_probability(classifier, lstm_k1_pred)
        pipeline_pred = threshold_predict(pipeline_proba)
        result["next_state_classifier_oracle_binary"] = compute_classification_metrics(y_true_k1, oracle_pred, oracle_proba)
        result["next_state_classifier_full_pipeline_binary"] = compute_classification_metrics(y_true_k1, pipeline_pred, pipeline_proba)

        # --- Feature 12: K-step forecasting regression, per horizon ---
        print("  [Feature 12] K-step recursive forecasting regression (K=1,2,3,5) ...")
        horizon_regression = {}
        horizon_pipeline_binary = {}
        for h in HORIZONS:
            valid, target_wid = horizon_validity_external(windows, seq_meta, h)
            n_valid = int(valid.sum())
            if n_valid == 0:
                horizon_regression[h] = {"n": 0, "note": "No valid sequences at this horizon (insufficient continuous segment length)."}
                horizon_pipeline_binary[h] = {"n": 0}
                continue
            pred_h = rollout_full[valid, h - 1, :]
            actual_h = windows.set_index("window_id").loc[target_wid[valid], feature_order].to_numpy(dtype="float32")
            # actual_h above is RAW; but pred_h is SCALED. Need actual in scaled space for a fair comparison -
            # transform actual raw window features via the same fitted pipeline used in preparation.
            horizon_regression[h] = {"__raw_actual_pending_scale__": True}
            horizon_regression[h]["n_valid"] = n_valid
            horizon_regression[h]["target_window_ids"] = target_wid[valid]
            horizon_regression[h]["pred"] = pred_h
            horizon_regression[h]["actual_labels"] = windows.set_index("window_id").loc[target_wid[valid], "label"].to_numpy()
            horizon_regression[h]["actual_binary_target"] = windows.set_index("window_id").loc[target_wid[valid], "binary_target"].to_numpy()

        all_results.setdefault("_tmp_horizon", {})[day] = horizon_regression
        result["_seq_meta"] = seq_meta
        result["_windows"] = windows
        result["_X_scaled"] = X_scaled
        result["_next_scaled"] = next_scaled
        result["_rollout_full"] = rollout_full
        result["_y_true_k1"] = y_true_k1
        result["_labels_k1"] = labels_k1
        result["_pipeline_proba_k1"] = pipeline_proba
        result["_pipeline_pred_k1"] = pipeline_pred

        all_results[day] = result
        print(f"  Done: {day}")

    print("\nSecond pass: finishing K-step forecasting (scale actual targets) and attack progression / MITRE / explainability ...")
    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)

    for day in EXTERNAL_DAYS:
        result = all_results[day]
        if result["n_sequences"] == 0:
            continue
        windows = result["_windows"]
        horizon_data = all_results["_tmp_horizon"][day]
        horizon_final = {}
        for h in HORIZONS:
            hd = horizon_data[h]
            if hd.get("n", None) == 0 or hd.get("n_valid", 0) == 0:
                horizon_final[h] = hd
                continue
            actual_raw = windows.set_index("window_id").loc[hd["target_window_ids"], feature_order]
            actual_scaled = np.asarray(fitted_pipeline.transform(actual_raw), dtype="float32")
            reg = regression_metrics(hd["pred"], actual_scaled)
            horizon_final[h] = {
                "n": reg["n"], "mse": reg["mse"], "rmse": reg["rmse"], "mae": reg["mae"],
            }
            # attack progression probability at this horizon (transfer diagnostic)
            proba_h = infiltration_probability(classifier, hd["pred"])
            pred_h = threshold_predict(proba_h)
            horizon_final[h]["attack_progression_binary_metrics"] = compute_classification_metrics(hd["actual_binary_target"], pred_h, proba_h)
        result["k_step_forecasting"] = horizon_final

        # --- per-attack-family metrics (binary detection recall per family) ---
        labels_k1 = result["_labels_k1"]
        pipeline_pred_k1 = result["_pipeline_pred_k1"]
        families = sorted(set(labels_k1) - {"Benign"})
        per_family = {}
        for fam in families:
            mask = labels_k1 == fam
            n_fam = int(mask.sum())
            n_detected = int((pipeline_pred_k1[mask] == 1).sum()) if n_fam > 0 else 0
            per_family[fam] = {
                "n_sequences": n_fam,
                "detected_as_attack_count": n_detected,
                "detection_recall": round(n_detected / n_fam, 4) if n_fam > 0 else None,
                "note": "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family." if fam != "Infilteration" else "Direct, training-label-compatible detection recall.",
            }
        result["per_attack_family_detection"] = per_family

        # --- lightweight MITRE evidence generation on a deterministic sample (observed evidence only) ---
        sample_idx = np.linspace(0, result["n_sequences"] - 1, min(EXPLAIN_SAMPLE_SIZE, result["n_sequences"])).astype(int)
        seq_meta = result["_seq_meta"]
        windows_idx = windows.set_index("window_id")
        mitre_records = []
        for i in sample_idx:
            row = seq_meta.iloc[i]
            wid = int(row["input_end_window"])
            w = windows_idx.loc[wid]
            oc = float(w["observation_count"])
            totlen_fwd = float(w["TotLen Fwd Pkts"]) if "TotLen Fwd Pkts" in w else None
            totlen_bwd = float(w["TotLen Bwd Pkts"]) if "TotLen Bwd Pkts" in w else None
            iat_mean, iat_std = float(w["Flow IAT Mean"]), float(w["Flow IAT Std"])
            evidence = {
                "dst_port_nunique": None,  # not computed for external data in this feature - see limitations
                "flow_duration_mean_us": float(w["Flow Duration"]),
                "observation_count": oc,
                "avg_bytes_per_flow": (totlen_fwd / oc) if (totlen_fwd is not None and oc > 0) else None,
                "flow_iat_coefficient_of_variation": (iat_std / iat_mean) if iat_mean and iat_mean > 0 else None,
                "tot_fwd_pkts": float(w["Tot Fwd Pkts"]), "tot_bwd_pkts": float(w["Tot Bwd Pkts"]),
                "flow_byts_per_s": float(w["Flow Byts/s"]) if pd.notna(w["Flow Byts/s"]) else None,
                "flow_pkts_per_s": float(w["Flow Pkts/s"]) if pd.notna(w["Flow Pkts/s"]) else None,
                "outbound_inbound_byte_ratio": (totlen_fwd / totlen_bwd) if (totlen_bwd is not None and totlen_bwd > 0) else None,
                "traffic_growth_pct": None,  # requires prior-window baseline; omitted for this lightweight external pass
                "connection_frequency": oc,
                "syn_flag_cnt": float(w["SYN Flag Cnt"]), "ack_flag_cnt": float(w["ACK Flag Cnt"]),
            }
            stage_results = mapper.evaluate_rules(evidence)
            rec = mapper.build_audit_record(f"{day}_seq{row['sequence_id']}_observed_t", stage_results, feature13_probability=None)
            rec["sequence_id"] = int(row["sequence_id"])
            rec["actual_label"] = str(row["target_window_label"])
            mitre_records.append(rec)
        result["mitre_evidence_sample"] = mitre_records

        # --- lightweight explainability (Layer C, exact, deterministic sample) ---
        explain_records = []
        X_scaled_arr = result["_X_scaled"]
        rollout_full = result["_rollout_full"]
        for i in sample_idx:
            pred_state = rollout_full[i, 0, :]
            attr = expl.classifier_attribution(classifier, pred_state, feature_order)
            explain_records.append({
                "sequence_id": int(seq_meta.iloc[i]["sequence_id"]),
                "actual_label": str(seq_meta.iloc[i]["target_window_label"]),
                "predicted_probability": float(result["_pipeline_proba_k1"][i]),
                "top5_contributors": [
                    {"feature": c["feature"], "contribution": c["contribution"], "direction": c["direction"]}
                    for c in attr["contributions"][:5]
                ],
            })
        result["explainability_sample"] = explain_records

        for key in ["_seq_meta", "_windows", "_X_scaled", "_next_scaled", "_rollout_full", "_y_true_k1", "_labels_k1", "_pipeline_proba_k1", "_pipeline_pred_k1"]:
            result.pop(key, None)

    del all_results["_tmp_horizon"]

    # --- post-run integrity ---
    print("\nVerifying Feature 1-15 protected files were not modified ...")
    hashes_after = hash_files(PROTECTED_FEATURE1_15_FILES)
    unchanged = hashes_before == hashes_after
    if not unchanged:
        changed = [k for k in hashes_before if hashes_before.get(k) != hashes_after.get(k)]
        fail(f"Protected Feature 1-15 files were modified: {changed}")
    print(f"  Feature 1-15 artifacts unchanged: {unchanged}")

    write_outputs(all_results, report_dir, data_out_dir, feature_order, lstm_checkpoint, unchanged, device)
    return all_results


def write_outputs(all_results, report_dir, data_out_dir, feature_order, lstm_checkpoint, artifacts_unchanged, device):
    print("\nWriting outputs ...")

    # dataset_summary.csv
    rows = []
    for day, r in all_results.items():
        rows.append({
            "day": day, "n_sequences": r["n_sequences"], "n_windows": r["n_windows"],
            "attack_prevalence_windows_pct": r["attack_prevalence_windows_pct"],
            "training_compatible_view_applicable": r["training_compatible_view_applicable"],
        })
    pd.DataFrame(rows).to_csv(report_dir / "dataset_summary.csv", index=False)

    # binary_attack_metrics.csv
    binary_rows = []
    for day, r in all_results.items():
        for model_key in ["logistic_regression_binary", "random_forest_binary", "next_state_classifier_oracle_binary", "next_state_classifier_full_pipeline_binary"]:
            if model_key not in r:
                continue
            m = r[model_key]
            binary_rows.append({
                "day": day, "model": model_key, "n": m["n_samples"], "n_positive": m["n_positive"], "n_negative": m["n_negative"],
                "attack_prevalence_pct": m["attack_prevalence_pct"], "accuracy": m["accuracy"], "precision": m["precision"],
                "recall": m["recall"], "f1": m["f1"], "roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"], "fpr": m["false_positive_rate"],
            })
    pd.DataFrame(binary_rows).to_csv(report_dir / "binary_attack_metrics.csv", index=False)

    # per_attack_family_metrics.csv
    family_rows = []
    for day, r in all_results.items():
        for fam, m in r.get("per_attack_family_detection", {}).items():
            family_rows.append({"day": day, "attack_family": fam, **m})
    pd.DataFrame(family_rows).to_csv(report_dir / "per_attack_family_metrics.csv", index=False)

    # forecasting_metrics.csv
    fc_rows = []
    for day, r in all_results.items():
        for h, hd in r.get("k_step_forecasting", {}).items():
            row = {"day": day, "horizon": h, "n": hd.get("n", 0), "mse": hd.get("mse"), "rmse": hd.get("rmse"), "mae": hd.get("mae")}
            apm = hd.get("attack_progression_binary_metrics")
            if apm:
                row.update({"ap_precision": apm["precision"], "ap_recall": apm["recall"], "ap_f1": apm["f1"], "ap_roc_auc": apm["roc_auc"], "ap_fpr": apm["false_positive_rate"]})
            fc_rows.append(row)
    pd.DataFrame(fc_rows).to_csv(report_dir / "forecasting_metrics.csv", index=False)

    # prediction_summary.csv (compact, from explainability sample which already carries predictions)
    pred_rows = []
    for day, r in all_results.items():
        for rec in r.get("explainability_sample", []):
            pred_rows.append({"day": day, "sequence_id": rec["sequence_id"], "actual_label": rec["actual_label"], "predicted_probability": rec["predicted_probability"]})
    pd.DataFrame(pred_rows).to_csv(report_dir / "prediction_summary.csv", index=False)

    # confusion matrices
    for day, r in all_results.items():
        cm_payload = {k: r[k]["confusion_matrix"] for k in ["logistic_regression_binary", "random_forest_binary", "next_state_classifier_oracle_binary", "next_state_classifier_full_pipeline_binary"] if k in r}
        (report_dir / "confusion_matrices" / f"{day}.json").write_text(json.dumps(cm_payload, indent=2), encoding="utf-8")

    # config.json
    config = {
        "external_days": EXTERNAL_DAYS, "horizons": HORIZONS, "sequence_length": SEQUENCE_LENGTH, "feature_count": EXPECTED_FEATURE_COUNT,
        "training_compatible_days": sorted(TRAINING_COMPATIBLE_DAYS),
        "model_checkpoint_paths": {"logistic_regression": str(LOGREG_PATH), "random_forest": str(RF_PATH), "lstm": str(LSTM_CHECKPOINT_PATH), "next_state_classifier": str(CLASSIFIER_PATH)},
        "preprocessing_artifact_path": str(FITTED_PIPELINE_PATH), "feature_order_path": str(FEATURE_ORDER_PATH),
        "lstm_architecture": lstm_checkpoint["configuration"], "temporal_aggregation_policy_reused_from": "src/data/build_temporal_windows.py :: build_aggregation_policy()",
        "explainability_sample_size": EXPLAIN_SAMPLE_SIZE, "explainability_sampling_method": "evenly-spaced indices via np.linspace, deterministic",
        "environment": {"python_version": sys.version, "sklearn_version": sklearn.__version__, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
    }
    (report_dir / "config.json").write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")

    # generalization_metrics.json (everything)
    (report_dir / "generalization_metrics.json").write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")

    report_txt = format_text_report(all_results, artifacts_unchanged)
    (report_dir / "generalization_report.txt").write_text(report_txt, encoding="utf-8")

    print(f"Wrote all outputs to {report_dir}")


def format_text_report(all_results, artifacts_unchanged) -> str:
    lines = ["=" * 70, "ATTACK-DIVERSE FROZEN GENERALIZATION EVALUATION (FEATURE 16)", "=" * 70]
    lines.append("\nNo model was trained, retrained, or fit. All external labels were used ONLY for metrics.")
    lines.append(f"\nFeature 1-15 artifact integrity: {'PASS - unchanged' if artifacts_unchanged else 'FAIL - MODIFIED'}")

    for day, r in all_results.items():
        lines.append(f"\n{'-'*70}\n{day}\n{'-'*70}")
        lines.append(f"  Sequences: {r['n_sequences']}  Windows: {r['n_windows']}  Attack prevalence (windows): {r['attack_prevalence_windows_pct']}%")
        lines.append(f"  Training-label-compatible view applicable: {r['training_compatible_view_applicable']}")
        if r["n_sequences"] == 0:
            lines.append("  SKIPPED: no valid sequences.")
            continue
        for key, label in [
            ("logistic_regression_binary", "Logistic Regression (binary anomaly view)"),
            ("random_forest_binary", "Random Forest (binary anomaly view)"),
            ("next_state_classifier_oracle_binary", "Feature 11 classifier - ORACLE (ground-truth state)"),
            ("next_state_classifier_full_pipeline_binary", "Feature 11 classifier - FULL PIPELINE (LSTM-predicted state)"),
        ]:
            m = r[key]
            lines.append(f"  {label}: acc={m['accuracy']} prec={m['precision']} rec={m['recall']} f1={m['f1']} "
                         f"roc_auc={m['roc_auc']} pr_auc={m['pr_auc']} fpr={m['false_positive_rate']} (n={m['n_samples']}, pos={m['n_positive']})")
        lstm = r["lstm_one_step_regression"]
        lines.append(f"  LSTM one-step regression: MSE={lstm['mse']:.4f} RMSE={lstm['rmse']:.4f} MAE={lstm['mae']:.4f}")
        lines.append(f"    Hardest features (top 10 by MSE): {lstm['top10_hardest_features']}")
        lines.append("  K-step forecasting (regression MSE/RMSE/MAE, and attack-progression binary metrics per horizon):")
        for h, hd in r.get("k_step_forecasting", {}).items():
            lines.append(f"    K={h}: n={hd.get('n',0)} mse={hd.get('mse')} rmse={hd.get('rmse')} mae={hd.get('mae')}")
            if "attack_progression_binary_metrics" in hd:
                apm = hd["attack_progression_binary_metrics"]
                lines.append(f"      attack-progression (transfer diagnostic): prec={apm['precision']} rec={apm['recall']} f1={apm['f1']} roc_auc={apm['roc_auc']} fpr={apm['false_positive_rate']}")
        lines.append("  Per-attack-family detection (binary anomaly recall):")
        for fam, m in r.get("per_attack_family_detection", {}).items():
            lines.append(f"    {fam}: n={m['n_sequences']} detected={m['detected_as_attack_count']} recall={m['detection_recall']} - {m['note']}")

    lines.append("\n" + "=" * 70)
    lines.append("SCOPE / HONESTY NOTES")
    lines.append("=" * 70)
    lines.append("- MITRE evidence for external data was generated WITHOUT destination-port diversity or")
    lines.append("  traffic-growth baseline (not computed for this lightweight external pass) - Discovery/")
    lines.append("  Reconnaissance/Impact-growth rules will therefore show reduced or no evidence for this")
    lines.append("  reason alone, not necessarily because the underlying behaviour is absent.")
    lines.append("- No ATT&CK ground truth exists for any external day; no stage accuracy is reported.")
    lines.append("- Explainability and MITRE evidence were computed for a small deterministic sample")
    lines.append(f"  ({EXPLAIN_SAMPLE_SIZE} sequences per day, evenly spaced) for computational cost reasons.")
    lines.append("- Attack-progression-probability results for Wednesday-14/21 are TRANSFER/GENERALIZATION")
    lines.append("  diagnostics of an Infiltration-trained model on unseen attack families, NOT validated")
    lines.append("  probabilities of FTP brute force or DDoS.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
