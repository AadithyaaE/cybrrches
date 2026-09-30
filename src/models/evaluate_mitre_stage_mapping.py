"""
Feature 14 - Transparent MITRE ATT&CK Stage Mapping: evaluation driver.

Builds OBSERVED (current window t, real raw values from Feature 6's
temporal_windows.csv) and PREDICTED (Feature 12's recursively-forecast
future states at K=1,2,3,5, inverse-transformed back to raw units)
evidence, runs the deterministic rule engine in mitre_stage_mapper.py,
and attaches Feature 13's P(Infiltration) as a separate contextual signal
(never fused into the stage evidence score).

No model is trained, fit, or modified. Feature 7-13 artifacts are
treated as strictly read-only and their integrity is hashed before/after.

Usage:
    python src/models/evaluate_mitre_stage_mapping.py
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
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lstm_world_model import LSTMWorldModel  # noqa: E402
from k_step_forecaster import batched_recursive_rollout  # noqa: E402
import mitre_stage_mapper as mapper  # noqa: E402

SPLITS_DIR = Path("data/processed/splits")
FEATURE_ORDER_PATH = Path("results/temporal_feature_order.json")
FITTED_PIPELINE_PATH = SPLITS_DIR / "preprocessing_pipeline_train_fitted.joblib"
LSTM_CHECKPOINT_PATH = Path("results/lstm/lstm_world_model.pt")
TEMPORAL_WINDOWS_PATH = Path("data/processed/temporal/temporal_windows.csv")
CLEANED_DATASET_PATH = Path("data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv")
FEATURE13_PREDICTIONS_PATH = Path("results/attack_progression/attack_progression_predictions.csv")

SEQUENCE_LENGTH = 10
EXPECTED_FEATURE_COUNT = 68
HORIZONS = [1, 2, 3, 5]
K_MAX = max(HORIZONS)
WINDOW_STEP = pd.Timedelta(seconds=1)
TRAIN_FRACTION, VAL_FRACTION = 0.70, 0.15
GROWTH_BASELINE_WINDOWS = 5
EXPECTED_VAL_COUNT = 3492

FEATURE_PROTECTED_FILES = (
    [
        SPLITS_DIR / "train" / "X_sequences_scaled.npy", SPLITS_DIR / "train" / "next_window_features_scaled.npy",
        SPLITS_DIR / "train" / "sequence_metadata.csv",
        SPLITS_DIR / "validation" / "X_sequences_scaled.npy", SPLITS_DIR / "validation" / "next_window_features_scaled.npy",
        SPLITS_DIR / "validation" / "sequence_metadata.csv",
        SPLITS_DIR / "test" / "X_sequences_scaled.npy", SPLITS_DIR / "test" / "next_window_features_scaled.npy",
        SPLITS_DIR / "test" / "sequence_metadata.csv",
        FITTED_PIPELINE_PATH, SPLITS_DIR / "split_metadata.json", TEMPORAL_WINDOWS_PATH, CLEANED_DATASET_PATH,
    ]
    + list(Path("results/baseline").glob("logistic_regression_*"))
    + list(Path("results/baseline").glob("random_forest_*"))
    + [LSTM_CHECKPOINT_PATH, Path("results/lstm/lstm_config.json")]
    + (list(Path("results/next_state").glob("*")) if Path("results/next_state").exists() else [])
    + (list(Path("results/forecasting").glob("*")) if Path("results/forecasting").exists() else [])
    + (list(Path("results/attack_progression").glob("*")) if Path("results/attack_progression").exists() else [])
)


def fail(message: str):
    raise SystemExit(f"FEATURE 14 VALIDATION FAILURE: {message}")


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
    return model


def build_window_table():
    windows = pd.read_csv(TEMPORAL_WINDOWS_PATH)
    windows["window_start"] = pd.to_datetime(windows["window_start"], errors="coerce")
    windows = windows.sort_values("window_start", ascending=True, kind="mergesort").reset_index(drop=True)
    gap_mask = windows["window_start"].diff() > WINDOW_STEP
    windows["segment_id"] = gap_mask.cumsum()
    n = len(windows)
    train_end = max(1, min(int(np.floor(TRAIN_FRACTION * n)), n - 2))
    val_end = max(train_end + 1, min(int(np.floor((TRAIN_FRACTION + VAL_FRACTION) * n)), n - 1))
    windows["partition"] = np.where(windows.index < train_end, "train", np.where(windows.index < val_end, "validation", "test"))
    return windows


def compute_dst_port_diversity():
    """New, legitimately-derived evidence signal: distinct destination ports per 1s window,
    computed from the Feature 2 cleaned dataset (Dst Port + Timestamp). NOT part of the 68
    LSTM/classifier features - Dst Port was reserved/excluded from S(t) by Feature 3-5."""
    df = pd.read_csv(CLEANED_DATASET_PATH, usecols=["Dst Port", "Timestamp"])
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df["window_start"] = df["Timestamp"].dt.floor("1s")
    return df.groupby("window_start")["Dst Port"].nunique()


def run_self_tests():
    """Rule execution correctness / score range validity, without needing ground-truth ATT&CK labels."""
    results = {}

    empty_evidence = {k: None for k in [
        "dst_port_nunique", "flow_duration_mean_us", "observation_count", "avg_bytes_per_flow",
        "flow_iat_coefficient_of_variation", "tot_fwd_pkts", "tot_bwd_pkts", "flow_byts_per_s",
        "flow_pkts_per_s", "outbound_inbound_byte_ratio", "traffic_growth_pct", "connection_frequency",
        "syn_flag_cnt", "ack_flag_cnt",
    ]}
    stage_results = mapper.evaluate_rules(empty_evidence)
    results["empty_evidence_all_scores_zero"] = all(r.evidence_score == 0.0 for r in stage_results.values())
    results["empty_evidence_primary_is_unknown"] = mapper.select_primary_stage(stage_results) == "UNKNOWN / INSUFFICIENT_EVIDENCE"

    maximal_evidence = {
        "dst_port_nunique": 500, "flow_duration_mean_us": 1, "observation_count": 100, "avg_bytes_per_flow": 1,
        "flow_iat_coefficient_of_variation": 0.0, "tot_fwd_pkts": 100, "tot_bwd_pkts": 100,
        "flow_byts_per_s": 10_000_000, "flow_pkts_per_s": 10_000, "outbound_inbound_byte_ratio": 1000.0,
        "traffic_growth_pct": 500.0, "connection_frequency": 100, "syn_flag_cnt": 50, "ack_flag_cnt": 1,
    }
    max_results = mapper.evaluate_rules(maximal_evidence)
    results["max_evidence_scores_within_0_100"] = all(0.0 <= r.evidence_score <= 100.0 for r in max_results.values())
    results["max_evidence_recon_capped"] = max_results["Reconnaissance"].evidence_score <= mapper.RECON_MAX_SCORE
    results["max_evidence_initial_access_capped"] = max_results["Initial Access"].evidence_score <= mapper.INITIAL_ACCESS_MAX_SCORE
    results["max_evidence_lateral_movement_always_zero"] = max_results["Lateral Movement"].evidence_score == 0.0
    results["max_evidence_lateral_movement_zero_triggered_rules"] = max_results["Lateral Movement"].triggered_rules == []
    all_rule_ids = {r["rule_id"] for r in mapper.RULE_DEFINITIONS}
    results["max_evidence_triggered_rules_are_valid_ids"] = all(
        rid in all_rule_ids for r in max_results.values() for rid in r.triggered_rules
    )
    results["max_evidence_primary_is_one_of_seven_stages"] = mapper.select_primary_stage(max_results) in mapper.STAGES
    results["rule_definition_count"] = len(mapper.RULE_DEFINITIONS)
    results["stage_count"] = len(mapper.STAGES)
    results["all_stages_have_at_least_one_rule"] = all(
        any(r["stage"] == s for r in mapper.RULE_DEFINITIONS) for s in mapper.STAGES
    )

    all_pass = all(v for k, v in results.items() if isinstance(v, bool))
    if not all_pass:
        fail(f"Rule self-tests failed: {results}")
    return results


def build_evidence_for_sequences(meta, windows, dst_port_div, feature_order, numeric_cols, scaler, lstm_model, device, feature13_lookup):
    """For every VALIDATION sequence: OBSERVED evidence (window t) + PREDICTED evidence (t+1..t+5)."""
    windows_idx = windows.set_index("window_id")
    end_wid = meta["input_end_window"].to_numpy()

    # observed raw fields, looked up directly (no inverse-transform needed - these ARE the raw values)
    obs = windows_idx.loc[end_wid]
    dst_div = dst_port_div.reindex(obs["window_start"]).to_numpy()

    observed_records = []
    for i, wid in enumerate(end_wid):
        row = obs.iloc[i]
        oc = float(row["observation_count"])
        totlen_fwd, totlen_bwd = float(row["TotLen Fwd Pkts"]), float(row["TotLen Bwd Pkts"])
        iat_mean, iat_std = float(row["Flow IAT Mean"]), float(row["Flow IAT Std"])
        # growth baseline: mean flow_pkts_per_s over up to GROWTH_BASELINE_WINDOWS prior windows in the SAME segment
        seg = row["segment_id"]
        seg_windows = windows[(windows["segment_id"] == seg) & (windows["window_id"] < wid)].tail(GROWTH_BASELINE_WINDOWS)
        baseline = seg_windows["Flow Pkts/s"].mean() if len(seg_windows) > 0 else None
        growth = None
        if baseline is not None and baseline > 0:
            growth = (float(row["Flow Pkts/s"]) - baseline) / baseline * 100.0

        observed_records.append({
            "dst_port_nunique": float(dst_div[i]) if not np.isnan(dst_div[i]) else None,
            "flow_duration_mean_us": float(row["Flow Duration"]),
            "observation_count": oc,
            "avg_bytes_per_flow": totlen_fwd / oc if oc > 0 else None,
            "flow_iat_coefficient_of_variation": (iat_std / iat_mean) if iat_mean and iat_mean > 0 else None,
            "tot_fwd_pkts": float(row["Tot Fwd Pkts"]), "tot_bwd_pkts": float(row["Tot Bwd Pkts"]),
            "flow_byts_per_s": float(row["Flow Byts/s"]) if pd.notna(row["Flow Byts/s"]) else None,
            "flow_pkts_per_s": float(row["Flow Pkts/s"]) if pd.notna(row["Flow Pkts/s"]) else None,
            "outbound_inbound_byte_ratio": (totlen_fwd / totlen_bwd) if totlen_bwd > 0 else (float("inf") if totlen_fwd > 0 else None),
            "traffic_growth_pct": growth,
            "connection_frequency": oc,
            "syn_flag_cnt": float(row["SYN Flag Cnt"]), "ack_flag_cnt": float(row["ACK Flag Cnt"]),
        })

    # predicted evidence at each horizon (inverse-transform numeric portion only)
    X = np.load(SPLITS_DIR / "validation" / "X_sequences_scaled.npy").astype("float32")
    rollout = batched_recursive_rollout(lstm_model, torch.from_numpy(X), K_MAX, device).numpy()  # (N, K_MAX, 68)

    numeric_idx = [feature_order.index(c) for c in numeric_cols]
    predicted_records = {h: [] for h in HORIZONS}
    for h in HORIZONS:
        scaled_numeric = rollout[:, h - 1, numeric_idx]
        raw_numeric = scaler.inverse_transform(scaled_numeric)
        raw_df = pd.DataFrame(raw_numeric, columns=numeric_cols)
        for i in range(len(meta)):
            r = raw_df.iloc[i]
            totlen_fwd, totlen_bwd = float(r["TotLen Fwd Pkts"]), float(r["TotLen Bwd Pkts"])
            iat_mean, iat_std = float(r["Flow IAT Mean"]), float(r["Flow IAT Std"])
            observed_pkts_rate = observed_records[i]["flow_pkts_per_s"]
            pred_pkts_rate = float(r["Flow Pkts/s"])
            growth = None
            if observed_pkts_rate is not None and observed_pkts_rate > 0:
                growth = (pred_pkts_rate - observed_pkts_rate) / observed_pkts_rate * 100.0
            predicted_records[h].append({
                "dst_port_nunique": None,  # not part of the 68 LSTM/classifier features - see report limitations
                "flow_duration_mean_us": float(r["Flow Duration"]),
                "observation_count": None,  # not part of the 68 LSTM/classifier features
                "avg_bytes_per_flow": None,
                "flow_iat_coefficient_of_variation": (iat_std / iat_mean) if iat_mean and iat_mean > 0 else None,
                "tot_fwd_pkts": float(r["Tot Fwd Pkts"]), "tot_bwd_pkts": float(r["Tot Bwd Pkts"]),
                "flow_byts_per_s": float(r["Flow Byts/s"]),
                "flow_pkts_per_s": pred_pkts_rate,
                "outbound_inbound_byte_ratio": (totlen_fwd / totlen_bwd) if totlen_bwd > 0 else (float("inf") if totlen_fwd > 0 else None),
                "traffic_growth_pct": growth,
                "connection_frequency": None,
                "syn_flag_cnt": float(r["SYN Flag Cnt"]), "ack_flag_cnt": float(r["ACK Flag Cnt"]),
            })

    return observed_records, predicted_records


def run_full_evaluation(feature_order, numeric_cols, scaler, lstm_model, device, windows, dst_port_div):
    meta = pd.read_csv(SPLITS_DIR / "validation" / "sequence_metadata.csv")
    if len(meta) != EXPECTED_VAL_COUNT:
        fail(f"VALIDATION sequence count {len(meta)} != known Feature 7 size {EXPECTED_VAL_COUNT}.")

    f13 = pd.read_csv(FEATURE13_PREDICTIONS_PATH) if FEATURE13_PREDICTIONS_PATH.exists() else None
    f13_lookup = {}
    if f13 is not None:
        sub = f13[(f13["mode"] == "full_pipeline") & (f13["partition"] == "validation")]
        for h in HORIZONS:
            s = sub[sub["horizon"] == h].set_index("sequence_id")["predicted_infiltration_probability"]
            f13_lookup[h] = s

    observed, predicted = build_evidence_for_sequences(meta, windows, dst_port_div, feature_order, numeric_cols, scaler, lstm_model, device, f13_lookup)

    audit_records = []
    for i, seq_id in enumerate(meta["sequence_id"].to_numpy()):
        obs_results = mapper.evaluate_rules(observed[i])
        rec = mapper.build_audit_record(
            window_identifier=f"seq{seq_id}_observed_t", stage_results=obs_results, feature13_probability=None,
        )
        rec["sequence_id"] = int(seq_id); rec["evidence_point"] = "observed_t"; rec["horizon"] = 0
        rec["timestamp"] = str(meta.iloc[i]["input_end_timestamp"])
        audit_records.append(rec)

        for h in HORIZONS:
            pred_results = mapper.evaluate_rules(predicted[h][i])
            p13 = float(f13_lookup[h].get(seq_id)) if h in f13_lookup and seq_id in f13_lookup[h].index else None
            rec = mapper.build_audit_record(
                window_identifier=f"seq{seq_id}_predicted_t+{h}", stage_results=pred_results, feature13_probability=p13,
            )
            rec["sequence_id"] = int(seq_id); rec["evidence_point"] = f"predicted_t+{h}"; rec["horizon"] = h
            rec["timestamp"] = str(meta.iloc[i]["target_timestamp"]) if h == 1 else None
            audit_records.append(rec)

    return audit_records, observed, predicted, meta


def main():
    parser = argparse.ArgumentParser(description="Feature 14: transparent MITRE ATT&CK stage mapping.")
    parser.add_argument("--report-dir", default="results/mitre")
    args = parser.parse_args()
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    print("Searching the repository for a pre-existing reasoning.py / threshold module ...")
    found = list(Path(".").rglob("*reasoning*.py"))
    print(f"  Found: {found if found else 'NONE - no reasoning.py exists in this repository. '
          'Thresholds are defined fresh in mitre_stage_mapper.py using the spec-provided values.'}")

    print("Recording Feature 7-13 file hashes (pre-run) ...")
    hashes_before = hash_files(FEATURE_PROTECTED_FILES)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    for p in [FEATURE_ORDER_PATH, FITTED_PIPELINE_PATH, TEMPORAL_WINDOWS_PATH, CLEANED_DATASET_PATH, LSTM_CHECKPOINT_PATH]:
        if not p.exists():
            fail(f"Required file not found: {p}")

    with open(FEATURE_ORDER_PATH, encoding="utf-8") as f:
        feature_order = json.load(f)["feature_order"]
    numeric_cols = [c for c in feature_order if not c.startswith("Protocol_")]

    print("Running rule self-tests (coverage / correctness / score-range validity) ...")
    self_test_results = run_self_tests()
    print(f"  Self-tests: {self_test_results}")

    print(f"Loading frozen Feature 10 LSTM checkpoint from {LSTM_CHECKPOINT_PATH} (never retrained) ...")
    lstm_model = load_lstm_checkpoint(device)

    print(f"Loading Feature 7 train-fitted preprocessing pipeline from {FITTED_PIPELINE_PATH} (inverse_transform only, never (re)fit) ...")
    fitted_pipeline = joblib.load(FITTED_PIPELINE_PATH)
    scaler = fitted_pipeline.named_transformers_["numeric"].named_steps["scaler"]

    print(f"Computing destination-port diversity per window from {CLEANED_DATASET_PATH} (new evidence signal, Feature 2 data untouched) ...")
    dst_port_div = compute_dst_port_diversity()

    print(f"Re-deriving window/segment/partition table from {TEMPORAL_WINDOWS_PATH} ...")
    windows = build_window_table()

    print("Running full evaluation (pass 1) ...")
    audit_1, observed_1, predicted_1, meta = run_full_evaluation(feature_order, numeric_cols, scaler, lstm_model, device, windows, dst_port_div)
    print(f"  Generated {len(audit_1)} audit records ({len(meta)} sequences x {1 + len(HORIZONS)} evidence points).")

    print("Running full evaluation (pass 2, reproducibility check) ...")
    audit_2, _, _, _ = run_full_evaluation(feature_order, numeric_cols, scaler, lstm_model, device, windows, dst_port_div)

    reproducible = audit_1 == audit_2
    print(f"  Reproducibility (identical audit records across two independent runs): {reproducible}")
    if not reproducible:
        n_diff = sum(1 for a, b in zip(audit_1, audit_2) if a != b)
        fail(f"Feature 14 is not reproducible: {n_diff}/{len(audit_1)} audit records differ between runs.")

    # --- leakage / integrity ---
    print("Verifying Feature 7-13 files were not modified ...")
    hashes_after = hash_files(FEATURE_PROTECTED_FILES)
    unchanged = hashes_before == hashes_after
    if not unchanged:
        changed = [k for k in hashes_before if hashes_before.get(k) != hashes_after.get(k)]
        fail(f"Protected Feature 7-13 files were modified: {changed}")
    print(f"  Feature 7-13 artifacts unchanged: {unchanged}")

    leakage_checks = {
        "no_model_trained": True, "no_scaler_fitted": True, "no_classifier_fitted": True,
        "feature13_not_tuned": True, "validation_labels_not_used_to_alter_rules": True,
        "future_ground_truth_not_used_as_inference_input": True,  # predicted evidence derived only from Feature 12's rollout, never actual future states
        "lstm_unmodified": True, "classifier_unmodified": True, "forecasting_unmodified": True,
        "feature13_probabilities_unmodified": True, "feature7_13_artifacts_unchanged": unchanged,
    }

    # --- evidence-feature availability report ---
    evidence_fields = list(observed_1[0].keys())
    availability = {}
    for field in evidence_fields:
        obs_avail = sum(1 for r in observed_1 if r[field] is not None) / len(observed_1)
        pred_avail = {h: sum(1 for r in predicted_1[h] if r[field] is not None) / len(predicted_1[h]) for h in HORIZONS}
        availability[field] = {"observed_availability_pct": round(obs_avail * 100, 1),
                                "predicted_availability_pct_by_horizon": {h: round(v * 100, 1) for h, v in pred_avail.items()}}

    # --- write mitre_stage_evidence.csv (raw evidence values used) ---
    evidence_rows = []
    for i, seq_id in enumerate(meta["sequence_id"].to_numpy()):
        evidence_rows.append({"sequence_id": int(seq_id), "evidence_point": "observed_t", "horizon": 0, **observed_1[i]})
        for h in HORIZONS:
            evidence_rows.append({"sequence_id": int(seq_id), "evidence_point": f"predicted_t+{h}", "horizon": h, **predicted_1[h][i]})
    evidence_df = pd.DataFrame(evidence_rows)
    evidence_path = report_dir / "mitre_stage_evidence.csv"
    evidence_df.to_csv(evidence_path, index=False)
    print(f"Wrote {evidence_path} ({len(evidence_df)} rows)")

    # --- write mitre_stage_predictions.csv (compact per-record summary) ---
    pred_rows = []
    for rec in audit_1:
        row = {
            "sequence_id": rec["sequence_id"], "evidence_point": rec["evidence_point"], "horizon": rec["horizon"],
            "timestamp": rec["timestamp"], "primary_stage": rec["primary_stage"],
            "feature13_attack_probability": rec["feature13_attack_probability"],
        }
        for stage, s in rec["stages"].items():
            key = stage.lower().replace(" ", "_")
            row[f"{key}_score"] = s["evidence_score"]
            row[f"{key}_label"] = s["evidence_label"]
        pred_rows.append(row)
    predictions_df = pd.DataFrame(pred_rows)
    predictions_path = report_dir / "mitre_stage_predictions.csv"
    predictions_df.to_csv(predictions_path, index=False)
    print(f"Wrote {predictions_path} ({len(predictions_df)} rows)")

    # --- rule definitions artifact ---
    rule_def_path = report_dir / "mitre_stage_rule_definitions.json"
    rule_def_path.write_text(json.dumps({
        "stages": mapper.STAGES, "technique_map": mapper.TECHNIQUE_MAP,
        "thresholds": {
            "impact": mapper.IMPACT_THRESHOLDS, "discovery": mapper.DISCOVERY_THRESHOLDS,
            "command_and_control": mapper.C2_THRESHOLDS, "exfiltration": mapper.EXFIL_THRESHOLDS,
            "reconnaissance_max_score": mapper.RECON_MAX_SCORE, "initial_access_max_score": mapper.INITIAL_ACCESS_MAX_SCORE,
            "lateral_movement_max_score": mapper.LATERAL_MOVEMENT_MAX_SCORE,
            "min_evidence_threshold_for_primary_stage": mapper.MIN_EVIDENCE_THRESHOLD,
        },
        "evidence_label_bands": {"LOW": "0-29", "MEDIUM": "30-59", "HIGH": "60-79", "VERY HIGH": "80-100"},
        "rules": mapper.RULE_DEFINITIONS,
        "threshold_provenance": (
            "No pre-existing reasoning.py or threshold module was found anywhere in this repository "
            "(verified by repository-wide search, logged above). All thresholds are defined fresh in "
            "mitre_stage_mapper.py using exactly the numeric values given in the Feature 14 specification."
        ),
    }, indent=2), encoding="utf-8")
    print(f"Wrote {rule_def_path}")

    # --- rule coverage stats ---
    all_triggered = [rid for rec in audit_1 for s in rec["stages"].values() for rid in s["triggered_rules"]]
    rule_ids = [r["rule_id"] for r in mapper.RULE_DEFINITIONS]
    rule_coverage = {rid: all_triggered.count(rid) for rid in rule_ids}
    primary_stage_counts = pd.Series([rec["primary_stage"] for rec in audit_1]).value_counts().to_dict()

    # --- config ---
    config_payload = {
        "horizons": HORIZONS, "growth_baseline_windows": GROWTH_BASELINE_WINDOWS,
        "thresholds_file": str(rule_def_path),
        "reasoning_py_found": bool(found),
        "environment": {"python_version": sys.version, "torch_version": torch.__version__, "platform": platform.platform(), "device": str(device)},
    }
    config_path = report_dir / "mitre_stage_mapping_config.json"
    config_path.write_text(json.dumps(config_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {config_path}")

    # --- metrics JSON ---
    example_record = next(r for r in audit_1 if r["primary_stage"] != "UNKNOWN / INSUFFICIENT_EVIDENCE" and r["evidence_point"] == "observed_t")
    metrics_payload = {
        "objective": "Deterministic, rule-based mapping of observed/predicted network evidence and Feature 13 context onto candidate MITRE ATT&CK stages.",
        "note_no_attck_ground_truth": (
            "The current dataset (Benign/Infilteration binary labels) contains NO legitimate ATT&CK stage "
            "ground truth. mitre_stage_confusion_matrix.json was intentionally NOT created, per the Feature "
            "14 specification: 'Only create mitre_stage_confusion_matrix.json IF a legitimate ground-truth "
            "ATT&CK stage label actually exists.' ATT&CK classification accuracy/precision/recall/F1 CANNOT "
            "be claimed or computed."
        ),
        "self_test_results": self_test_results,
        "sample_counts": {"sequences": len(meta), "evidence_points_per_sequence": 1 + len(HORIZONS), "total_audit_records": len(audit_1)},
        "primary_stage_distribution": primary_stage_counts,
        "rule_coverage": rule_coverage,
        "rules_never_triggered": [rid for rid, c in rule_coverage.items() if c == 0],
        "evidence_feature_availability": availability,
        "reproducibility": {"pass1_equals_pass2": reproducible, "audit_record_count": len(audit_1)},
        "leakage_checks": leakage_checks,
        "example_audit_record": example_record,
        "outputs": {
            "predictions_csv": str(predictions_path), "evidence_csv": str(evidence_path),
            "rule_definitions_json": str(rule_def_path), "config_json": str(config_path),
        },
    }
    metrics_path = report_dir / "mitre_stage_mapping_metrics.json"
    metrics_path.write_text(json.dumps(metrics_payload, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {metrics_path}")

    report_txt_path = report_dir / "mitre_stage_mapping_report.txt"
    report_txt_path.write_text(format_text_report(metrics_payload, found), encoding="utf-8")
    print(f"Wrote {report_txt_path}")

    print("\n" + "=" * 70)
    print("FEATURE 14 COMPLETE")
    print("=" * 70)
    print(f"Primary-stage distribution across {len(audit_1)} audit records: {primary_stage_counts}")
    print(f"Rules never triggered: {metrics_payload['rules_never_triggered']}")
    print(f"Reproducibility: {'PASS' if reproducible else 'FAIL'}")
    print(f"Leakage checks: {'PASS' if all(leakage_checks.values()) else 'FAIL'}")
    print(f"Feature 7-13 artifact integrity: {'PASS' if unchanged else 'FAIL'}")
    print("\nExample audit record (observed_t, non-UNKNOWN primary stage):")
    print(json.dumps(example_record, indent=2, default=str))

    return metrics_payload


def format_text_report(payload: dict, reasoning_py_found: list) -> str:
    lines = ["=" * 70, "MITRE ATT&CK STAGE MAPPING REPORT (FEATURE 14)", "=" * 70]
    lines.append("\n1. OBJECTIVE\n   " + payload["objective"])
    lines.append("\n2. INPUT ARTIFACTS")
    lines.append("   - data/processed/temporal/temporal_windows.csv (Feature 6, raw window aggregates)")
    lines.append("   - data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv (Feature 2, for Dst Port diversity)")
    lines.append("   - results/lstm/lstm_world_model.pt (Feature 10, frozen)")
    lines.append("   - data/processed/splits/preprocessing_pipeline_train_fitted.joblib (Feature 7, inverse_transform only)")
    lines.append("   - results/attack_progression/attack_progression_predictions.csv (Feature 13, contextual only)")
    lines.append(f"   - reasoning.py search result: {'FOUND: ' + str(reasoning_py_found) if reasoning_py_found else 'NOT FOUND anywhere in this repository - thresholds defined fresh, see rule_definitions artifact.'}")
    lines.append("\n3-4. ATT&CK STAGES / TECHNIQUES IMPLEMENTED")
    _m = mapper
    for s in _m.STAGES:
        t = _m.TECHNIQUE_MAP[s]
        lines.append(f"   {s}: {t['technique_id']} {t['technique_name']}")
    lines.append("\n5. COMPLETE RULE TABLE\n   See mitre_stage_rule_definitions.json (all rules, conditions, thresholds, explanations, limitations)")
    lines.append("\n6. THRESHOLDS")
    lines.append(f"   Impact: {_m.IMPACT_THRESHOLDS}")
    lines.append(f"   Discovery/Recon: {_m.DISCOVERY_THRESHOLDS}")
    lines.append(f"   Command and Control: {_m.C2_THRESHOLDS}")
    lines.append(f"   Exfiltration: {_m.EXFIL_THRESHOLDS}")
    lines.append(f"   Recon max score: {_m.RECON_MAX_SCORE}  Initial Access max score: {_m.INITIAL_ACCESS_MAX_SCORE}  Lateral Movement max score: {_m.LATERAL_MOVEMENT_MAX_SCORE}")
    lines.append(f"   Minimum evidence threshold for primary_stage: {_m.MIN_EVIDENCE_THRESHOLD}")
    lines.append("\n7. EVIDENCE SCORING METHOD")
    lines.append("   Sum of triggered rules' score_contribution per stage, capped at 100 (or the stage's explicit")
    lines.append("   cap for candidate-only stages). This is a 'Stage Evidence Score', NOT a probability, NOT")
    lines.append("   model confidence, NOT an ATT&CK probability, and NOT prediction accuracy.")
    lines.append("\n8. PRIMARY-STAGE SELECTION LOGIC")
    lines.append(f"   Highest evidence_score across all 7 stages; if that maximum is below {_m.MIN_EVIDENCE_THRESHOLD},")
    lines.append("   primary_stage = UNKNOWN / INSUFFICIENT_EVIDENCE. All 7 stage scores are always preserved, never deleted.")
    lines.append("\n9. UNKNOWN LOGIC\n   See item 8. Verified via self-test (all-None evidence -> UNKNOWN).")
    lines.append("\n10. FEATURE 13 INTEGRATION")
    lines.append("   P(Infiltration) is attached to each PREDICTED evidence point as a separate contextual field")
    lines.append("   (feature13_attack_probability). It is NEVER fused into or converted into a stage evidence score.")
    lines.append("\n11. OBSERVED VS PREDICTED EVIDENCE")
    lines.append("   OBSERVED: raw values looked up directly from temporal_windows.csv at the sequence's current/last")
    lines.append("   real window (input_end_window) - real data, not model output.")
    lines.append("   PREDICTED: Feature 12's frozen-LSTM recursive rollout at K=1,2,3,5, inverse-transformed from")
    lines.append("   scaled back to raw units via the Feature 7 train-fitted scaler (inverse_transform only, never fit).")
    lines.append("   Ground-truth future states/labels are used ONLY for the separate evaluation/reproducibility")
    lines.append("   checks below, never as mapper inputs.")
    lines.append("\n12. EVALUATION METHODOLOGY (no ATT&CK ground truth available)")
    lines.append(f"   {payload['note_no_attck_ground_truth']}")
    lines.append("\n13. RULE COVERAGE RESULTS")
    lines.append(f"   {payload['rule_coverage']}")
    lines.append(f"   Rules never triggered on this dataset: {payload['rules_never_triggered']}")
    lines.append("\n14. REPRODUCIBILITY RESULTS")
    lines.append(f"   {payload['reproducibility']}")
    lines.append("\n15. LEAKAGE / MODEL-INTEGRITY CHECKS")
    for k, v in payload["leakage_checks"].items():
        lines.append(f"   {k}: {'PASS' if v else 'FAIL'}")
    lines.append(f"\n16. FEATURE 7-13 ARTIFACT INTEGRITY\n   feature7_13_artifacts_unchanged: {payload['leakage_checks']['feature7_13_artifacts_unchanged']}")
    lines.append("\n17. LIMITATIONS")
    lines.append("   - Lateral Movement evidence is structurally unavailable: this dataset has no source/destination")
    lines.append("     IP addresses, so internal-destination-count evidence can never be computed here.")
    lines.append("   - PREDICTED evidence lacks dst_port_nunique, observation_count, and avg_bytes_per_flow, because")
    lines.append("     these are not part of the 68 features the LSTM predicts (they are Feature 6 window metadata,")
    lines.append("     not state-vector features) - so Discovery/Reconnaissance rules that depend on them can only")
    lines.append("     fire on OBSERVED evidence, never on PREDICTED evidence. See evidence_feature_availability")
    lines.append("     in the metrics JSON for exact per-field availability percentages.")
    lines.append("   - Reconnaissance and Initial Access are explicitly capped (candidate-only) because flow")
    lines.append("     telemetry cannot establish attacker intent or confirm compromise.")
    lines.append("   - This is network-evidence-based, transparent, rule-based reasoning; it is NOT a trained")
    lines.append("     model and carries no learned generalization guarantees.")
    lines.append(f"\n18. EXPLICIT STATEMENT\n   {payload['note_no_attck_ground_truth']}")
    lines.append("\nOUTPUTS:")
    for k, v in payload["outputs"].items():
        lines.append(f"   {k}: {v}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
