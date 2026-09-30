"""
Feature L2.5 - generates the results/pcap_validation/ output artifacts.
Read-only w.r.t. every existing Feature 1-16 / Feature L1 / Feature L2
artifact; only ever writes under results/pcap_validation/. Does not
overwrite results/pcap/ (Feature L2's own output area).
"""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap_validation.feature_validation import (  # noqa: E402
    load_clean_df, run_cross_feature_checks, build_validation_matrix, CLEAN_CSV,
)

OUT_DIR = ROOT / "results/pcap_validation"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading real training CSV: {CLEAN_CSV.name} ...")
    df = load_clean_df()
    print(f"  {len(df)} rows.")

    print("Running cross-feature self-consistency checks ...")
    cross = run_cross_feature_checks(df)

    print("Building 65-feature validation matrix ...")
    matrix = build_validation_matrix(cross)
    assert len(matrix) == 65, f"Expected 65 rows, got {len(matrix)}"

    status_counts = Counter(r["status"] for r in matrix)
    classification_counts = Counter(r["classification"] for r in matrix)

    # ---- feature_validation_matrix.csv ----
    import csv
    csv_path = OUT_DIR / "feature_validation_matrix.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(matrix[0].keys()))
        writer.writeheader()
        writer.writerows(matrix)

    # ---- feature_validation_config.json ----
    config = {
        "evidence_sources": [
            "results/feature_inventory.csv",
            "results/feature_selection_report.json / .txt",
            "results/state_schema.json",
            "results/model_feature_list.json",
            "data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv (real CICFlowMeter output, cross-feature self-consistency only)",
        ],
        "evidence_sources_not_used": [
            "No CICFlowMeter reference tool (none available in this environment - see results/pcap/tool_availability_report.json)",
            "No external/web documentation of CICFlowMeter's Java source",
        ],
        "status_values": ["VALIDATED", "PARTIALLY_VALIDATED", "UNVALIDATED", "NOT_REPRODUCIBLE"],
        "classification_values": {
            "A": "Definition validated from project/training artifacts",
            "B": "Strongly derivable from packet/flow information but definition still needs empirical reference comparison",
            "C": "Approximation/simplification",
            "D": "Not sufficiently validated",
        },
        "training_csv_row_count": len(df),
    }
    (OUT_DIR / "feature_validation_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    # ---- validation_summary.json ----
    summary = {
        "total_features": len(matrix),
        "status_counts": dict(status_counts),
        "classification_counts": dict(classification_counts),
        "features_by_status": {
            status: sorted(r["feature"] for r in matrix if r["status"] == status)
            for status in ["VALIDATED", "PARTIALLY_VALIDATED", "UNVALIDATED", "NOT_REPRODUCIBLE"]
        },
        "cross_feature_check_results": cross,
        "semantic_compatibility_verdict": "NOT ESTABLISHED - see feature_validation_report.txt section 13",
    }

    def _default(o):
        import numpy as np
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        if isinstance(o, (np.bool_,)):
            return bool(o)
        raise TypeError(f"not serializable: {type(o)}")

    (OUT_DIR / "validation_summary.json").write_text(json.dumps(summary, indent=2, default=_default), encoding="utf-8")

    # ---- feature_validation_report.txt ----
    lines = []
    lines.append("=" * 70)
    lines.append("FEATURE L2.5 - PCAP FEATURE DEFINITION VALIDATION REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total features audited: {len(matrix)}")
    lines.append(f"VALIDATED: {status_counts.get('VALIDATED', 0)}")
    lines.append(f"PARTIALLY_VALIDATED: {status_counts.get('PARTIALLY_VALIDATED', 0)}")
    lines.append(f"UNVALIDATED: {status_counts.get('UNVALIDATED', 0)}")
    lines.append(f"NOT_REPRODUCIBLE: {status_counts.get('NOT_REPRODUCIBLE', 0)}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("PER-FEATURE DETAIL")
    lines.append("-" * 70)
    for r in sorted(matrix, key=lambda x: (x["status"], x["feature"])):
        lines.append(f"\n[{r['status']} / class {r['classification']}] {r['feature']}")
        lines.append(f"  formula: {r['formula']}")
        lines.append(f"  reason: {r['reason']}")
    report_text = "\n".join(lines)
    (OUT_DIR / "feature_validation_report.txt").write_text(report_text, encoding="utf-8")

    print(f"\nWrote reports to {OUT_DIR}:")
    for p in sorted(OUT_DIR.glob("*")):
        print(f"  {p.name}")
    print(f"\nStatus counts: {dict(status_counts)}")


if __name__ == "__main__":
    main()
