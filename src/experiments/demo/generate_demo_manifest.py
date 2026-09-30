"""
Feature 18 - End-to-End Research Demo: manifest generator.

Selects ONE deterministic sequence from the EXISTING Feature 15
explainability artifact (results/explainability/explanation_examples.json)
and records its full provenance trail (Observe -> Identify -> Predict ->
Explain -> MITRE) for the frontend /demo page to consume. This script does
NOT compute anything new: every value it records is read, unchanged, from
an existing frozen Feature 1-17 artifact. It performs no training, no
fitting, no model inference, and modifies nothing under results/ other
than results/demo/.

Mitigation and verification outputs are NOT computed here - Frontend
Features 10/11's existing pure TypeScript engines
(mitigationPolicy.ts/mitigationSimulation.ts/verificationEngine.ts) compute
those, client-side, from the SAME selected example this script records.
This script's job is only to pick the example and expose its trail; the
mitigation/verification simulation itself is deliberately left to the
existing, already-validated frontend code (not duplicated here).

SELECTION RULE (deterministic, documented, never random):
    The FIRST example, in results/explainability/explanation_examples.json's
    own existing array order (itself already a fixed, deterministic sample
    - see Feature 15), whose prediction is "Infiltration" (i.e. an actual
    attack case, more illustrative for a 7-stage demo than a Benign one)
    AND whose MITRE primary_stage is not "UNKNOWN / INSUFFICIENT_EVIDENCE"
    (i.e. has a real, mapped/candidate MITRE stage to show).
Running this script twice against the same (unmodified) artifact always
selects the same sequence - verified in tests/test_demo.py.
"""

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
EXPLANATION_EXAMPLES_PATH = ROOT / "results/explainability/explanation_examples.json"
TEMPORAL_WINDOWS_PATH = ROOT / "data/processed/temporal/temporal_windows.csv"
CROSS_DAY_REPORT_PATH = ROOT / "results/cross_day_generalization/cross_day_metrics.json"
OUT_DIR = ROOT / "results/demo"

SPLIT_PARTITION_DIRS = {
    "train": ROOT / "data/processed/splits/train/sequence_metadata.csv",
    "validation": ROOT / "data/processed/splits/validation/sequence_metadata.csv",
    "test": ROOT / "data/processed/splits/test/sequence_metadata.csv",
}


def select_demo_example() -> dict:
    with open(EXPLANATION_EXAMPLES_PATH, encoding="utf-8") as f:
        examples = json.load(f)
    for ex in examples:
        if ex["prediction"] == "Infiltration" and ex["mitre_evidence"]["primary_stage"] != "UNKNOWN / INSUFFICIENT_EVIDENCE":
            return ex
    raise SystemExit("FEATURE 18 FAILURE: no example in explanation_examples.json satisfies the selection rule.")


def find_sequence_partition_and_meta(sequence_id: int) -> tuple:
    for partition, path in SPLIT_PARTITION_DIRS.items():
        df = pd.read_csv(path)
        row = df[df["sequence_id"] == sequence_id]
        if len(row) == 1:
            return partition, row.iloc[0].to_dict()
    raise SystemExit(f"FEATURE 18 FAILURE: sequence_id {sequence_id} not found in any partition's sequence_metadata.csv.")


def load_ten_window_history(input_start_window: int, input_end_window: int) -> list:
    df = pd.read_csv(TEMPORAL_WINDOWS_PATH)
    sub = df[(df["window_id"] >= input_start_window) & (df["window_id"] <= input_end_window)].sort_values("window_id")
    cols = ["window_id", "window_start", "window_end", "observation_count",
            "Tot Fwd Pkts", "Tot Bwd Pkts", "Flow Duration", "Flow Byts/s", "Flow Pkts/s"]
    return sub[cols].to_dict(orient="records")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    example = select_demo_example()
    sequence_id = example["sequence_id"]
    print(f"Selected demo sequence_id={sequence_id} (prediction={example['prediction']}, "
          f"mitre_stage={example['mitre_evidence']['primary_stage']}) per the documented selection rule.")

    partition, seq_meta = find_sequence_partition_and_meta(sequence_id)
    print(f"  Found in partition='{partition}': input_window=[{seq_meta['input_start_window']},{seq_meta['input_end_window']}], "
          f"target_window={seq_meta['target_window']}, target_label={seq_meta['target_window_label']}")

    ten_window_history = load_ten_window_history(int(seq_meta["input_start_window"]), int(seq_meta["input_end_window"]))
    print(f"  Loaded {len(ten_window_history)} windows of real 10-second temporal history from Feature 6's temporal_windows.csv.")

    cross_day_summary = None
    if CROSS_DAY_REPORT_PATH.exists():
        with open(CROSS_DAY_REPORT_PATH, encoding="utf-8") as f:
            cross_day_summary = json.load(f)

    manifest = {
        "feature": "Feature 18 - CyberChess End-to-End Research Demo",
        "label": "OFFLINE RESEARCH DEMONSTRATION",
        "selected_sequence": {
            "sequence_id": sequence_id,
            "partition": partition,
            "selection_rule": (
                "First example (in the existing, already-fixed Feature 15 explanation_examples.json array order) "
                "whose prediction is 'Infiltration' AND whose MITRE primary_stage is not "
                "'UNKNOWN / INSUFFICIENT_EVIDENCE'. Deterministic - re-running this script against the same "
                "unmodified artifact always selects the same sequence_id."
            ),
            "input_start_window": int(seq_meta["input_start_window"]),
            "input_end_window": int(seq_meta["input_end_window"]),
            "target_window": int(seq_meta["target_window"]),
            "input_start_timestamp": str(seq_meta["input_start_timestamp"]),
            "input_end_timestamp": str(seq_meta["input_end_timestamp"]),
            "target_timestamp": str(seq_meta["target_timestamp"]),
            "target_window_label": str(seq_meta["target_window_label"]),
            "target_window_target": int(seq_meta["target_window_target"]),
        },
        "source_artifacts": {
            "observe_ten_window_history": "data/processed/temporal/temporal_windows.csv (Feature 6, unmodified, read-only)",
            "identify_attack_probability": "results/explainability/explanation_examples.json :: attack_probability / feature_13_probability (Feature 13, unmodified)",
            "predict_k_step_forecast": "results/explainability/explanation_examples.json :: feature_13_probability['1'/'2'/'3'/'5'] (Feature 12/13, unmodified)",
            "explain_attribution": "results/explainability/explanation_examples.json :: top_contributors / temporal_summary (Feature 15, unmodified)",
            "mitre_mapping": "results/explainability/explanation_examples.json :: mitre_evidence (Feature 14, unmodified)",
            "mitigate_and_verify": "computed CLIENT-SIDE by the existing, unmodified frontend engines "
                                     "(src/services/mitigation/{mitigationPolicy,mitigationSimulation}.ts, "
                                     "src/services/verification/verificationEngine.ts) from this same selected example - "
                                     "NOT computed or duplicated by this Python script.",
            "cross_day_generalization_summary": "results/cross_day_generalization/cross_day_metrics.json (Feature 17, unmodified)",
        },
        "observe": {"ten_window_history": ten_window_history},
        "identify": {
            "attack_probability": example["attack_probability"],
            "predicted_class": example["prediction"],
            "prediction_source": example["prediction_source"],
        },
        "predict": {"feature_13_probability_by_horizon": example["feature_13_probability"]},
        "explain": {
            "top_contributors": example["top_contributors"],
            "temporal_summary": example["temporal_summary"],
            "feature_group_summary": example["feature_group_summary"],
            "classifier_attribution_note": example["classifier_attribution_note"],
        },
        "mitre": {
            "primary_stage": example["mitre_evidence"]["primary_stage"],
            "stage_scores": example["mitre_evidence"]["stage_scores"],
            "stage_labels": example["mitre_evidence"]["stage_labels"],
        },
        "limitations": example["limitations"],
        "cross_day_generalization_summary": cross_day_summary,
    }

    (OUT_DIR / "demo_manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {OUT_DIR / 'demo_manifest.json'}")
    return manifest


if __name__ == "__main__":
    main()
