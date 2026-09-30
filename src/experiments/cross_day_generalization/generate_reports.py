"""
Feature 17 - assembles all final report artifacts from the individual
experiment JSON outputs already on disk. Read-only aggregation; no new
computation, no model access.
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
OUT_DIR = ROOT / "results/cross_day_generalization"


def load(name):
    p = OUT_DIR / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main():
    exp_a = load("experiment_a_frozen_baseline.json")
    fold_files = sorted(OUT_DIR.glob("fold_*_results.json"))
    folds = {f.stem.replace("_results", ""): json.loads(f.read_text(encoding="utf-8")) for f in fold_files}
    leakage = load("leakage_audit.json")

    # ---- dataset_summary.csv ----
    with open(OUT_DIR / "dataset_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["day", "row_count_raw", "row_count_final", "n_windows", "n_sequences",
                    "attack_pct_windows", "num_continuous_segments", "num_gaps", "timestamp_range", "caveat"])
        from common import DAY_REGISTRY
        for day, d in exp_a.items():
            label_dist = d.get("label_distribution_windows", {})
            total_w = sum(label_dist.values()) if label_dist else d.get("n_windows", 0)
            attack_w = total_w - label_dist.get("Benign", 0) if label_dist else None
            attack_pct = round(100 * attack_w / total_w, 2) if (attack_w is not None and total_w) else None
            w.writerow([day, d.get("row_count_raw"), d.get("row_count_final"), d.get("n_windows"), d.get("n_sequences"),
                        attack_pct, d.get("num_continuous_segments"), d.get("num_gaps"),
                        " to ".join(d.get("timestamp_range", ["", ""])), DAY_REGISTRY.get(day, {}).get("caveat", "")])

    # ---- fold_summary.csv ----
    with open(OUT_DIR / "fold_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["fold_name", "train_days", "holdout_day", "n_train_sequences", "n_holdout_sequences", "lstm_epochs_run", "lstm_best_epoch", "lstm_training_seconds"])
        for name, d in folds.items():
            lt = d.get("lstm_training", {})
            w.writerow([name, "|".join(d["train_days"]), d["holdout_day"], d["n_train_sequences"], d["n_holdout_sequences"],
                        lt.get("epochs_run"), lt.get("best_epoch"), round(lt.get("training_seconds", 0), 1)])

    # ---- model_comparison.csv (frozen Thursday-only model vs multi-day model, SAME held-out day) ----
    with open(OUT_DIR / "model_comparison.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["holdout_day", "model", "metric", "frozen_thursday_only", "multi_day_trained", "difference"])
        for name, d in folds.items():
            holdout = d["holdout_day"]
            if holdout not in exp_a:
                continue
            frozen = exp_a[holdout]
            for model_key in ["logistic_regression_binary", "random_forest_binary",
                               "next_state_classifier_oracle_binary", "next_state_classifier_full_pipeline_binary"]:
                if model_key not in d or model_key not in frozen:
                    continue
                for metric in ["accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "pr_auc", "brier_score"]:
                    fv = frozen[model_key].get(metric)
                    mv = d[model_key].get(metric)
                    diff = (mv - fv) if (isinstance(fv, (int, float)) and isinstance(mv, (int, float))) else None
                    w.writerow([holdout, model_key, metric, fv, mv, diff])

    # ---- forecasting_metrics.csv ----
    with open(OUT_DIR / "forecasting_metrics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "day", "horizon", "n", "mse", "rmse", "mae", "median_abs_error", "p95_abs_error", "outlier_dominated_dimensions_count"])
        for day, d in exp_a.items():
            k1 = d.get("lstm_one_step_regression")
            if k1:
                w.writerow(["experiment_a_frozen", day, 1, k1["n"], k1["mse"], k1["rmse"], k1["mae"], k1["median_abs_error"], k1["p95_abs_error"], len(k1["outlier_dominated_dimensions"])])
            for h, hd in d.get("horizons", {}).items():
                reg = hd.get("regression")
                if reg:
                    w.writerow(["experiment_a_frozen", day, h, reg["n"], reg["mse"], reg["rmse"], reg["mae"], reg["median_abs_error"], reg["p95_abs_error"], len(reg["outlier_dominated_dimensions"])])
        for name, d in folds.items():
            k1 = d.get("lstm_one_step_regression")
            if k1:
                w.writerow([name, d["holdout_day"], 1, k1["n"], k1["mse"], k1["rmse"], k1["mae"], k1["median_abs_error"], k1["p95_abs_error"], len(k1["outlier_dominated_dimensions"])])
            for h, hd in d.get("horizons", {}).items():
                reg = hd.get("regression") if isinstance(hd, dict) else None
                if reg:
                    w.writerow([name, d["holdout_day"], h, reg["n"], reg["mse"], reg["rmse"], reg["mae"], reg["median_abs_error"], reg["p95_abs_error"], len(reg["outlier_dominated_dimensions"])])

    # ---- attack_progression_metrics.csv ----
    with open(OUT_DIR / "attack_progression_metrics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "day", "horizon", "n", "precision", "recall", "f1", "roc_auc", "fpr", "brier_score", "degenerate"])
        for day, d in exp_a.items():
            for h, hd in d.get("horizons", {}).items():
                ap = hd.get("attack_progression")
                if ap:
                    w.writerow(["experiment_a_frozen", day, h, ap["n"], ap["precision"], ap["recall"], ap["f1"], ap.get("roc_auc"), ap["fpr"], ap["brier_score"], ap["degenerate_prediction_check"]["degenerate"]])
        for name, d in folds.items():
            for h, hd in d.get("horizons", {}).items():
                ap = hd.get("attack_progression") if isinstance(hd, dict) else None
                if ap:
                    w.writerow([name, d["holdout_day"], h, ap["n"], ap["precision"], ap["recall"], ap["f1"], ap.get("roc_auc"), ap["fpr"], ap["brier_score"], ap["degenerate_prediction_check"]["degenerate"]])

    # ---- confusion_matrices/ ----
    cm_dir = OUT_DIR / "confusion_matrices"
    cm_dir.mkdir(exist_ok=True)
    for day, d in exp_a.items():
        cms = {k: v["confusion_matrix"] for k, v in d.items() if isinstance(v, dict) and "confusion_matrix" in v}
        (cm_dir / f"experiment_a_{day}.json").write_text(json.dumps(cms, indent=2), encoding="utf-8")
    for name, d in folds.items():
        cms = {k: v["confusion_matrix"] for k, v in d.items() if isinstance(v, dict) and "confusion_matrix" in v}
        (cm_dir / f"{name}.json").write_text(json.dumps(cms, indent=2), encoding="utf-8")

    print("Wrote dataset_summary.csv, fold_summary.csv, model_comparison.csv, forecasting_metrics.csv, attack_progression_metrics.csv, confusion_matrices/*.json")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
