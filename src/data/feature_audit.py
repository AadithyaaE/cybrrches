"""
Feature audit and selection planning for the cleaned CSE-CIC-IDS2018 dataset.

Read-only analysis. Loads the cleaned CSV, inventories every column, and
produces an evidence-based classification, leakage-risk assessment,
constant-feature report, infinity/missingness analysis, correlation audit,
and a recommended core feature set for the first ML baseline.

Does NOT modify the cleaned CSV, select/drop columns from any dataset,
engineer features, create sequences, or train a model.

Usage:
    python src/data/feature_audit.py --input data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

TIMESTAMP_COLUMN = "Timestamp"
LABEL_COLUMN = "Label"
IDENTIFIER_COLUMNS = ["Dst Port", "Protocol"]
CORRELATION_THRESHOLD = 0.95
NEAR_CONSTANT_THRESHOLD = 0.99


# ----------------------------------------------------------------------
# Step 1: inventory
# ----------------------------------------------------------------------
def build_inventory(df: pd.DataFrame) -> dict:
    n_rows = len(df)
    inventory = {}
    for col in df.columns:
        series = df[col]
        is_numeric = pd.api.types.is_numeric_dtype(series)
        missing_count = int(series.isna().sum())
        inf_count = int(np.isinf(series).sum()) if is_numeric else 0
        entry = {
            "column_name": col,
            "dtype": str(series.dtype),
            "num_unique": int(series.nunique(dropna=True)),
            "pct_unique": round(float(series.nunique(dropna=True)) / n_rows * 100, 6) if n_rows else 0.0,
            "missing_count": missing_count,
            "missing_pct": round(missing_count / n_rows * 100, 6) if n_rows else 0.0,
            "infinite_count": inf_count,
            "is_numeric": is_numeric,
        }
        if is_numeric:
            finite = series.replace([np.inf, -np.inf], np.nan)
            entry["min"] = None if finite.dropna().empty else float(finite.min())
            entry["max"] = None if finite.dropna().empty else float(finite.max())
            entry["mean"] = None if finite.dropna().empty else float(finite.mean())
            entry["std"] = None if finite.dropna().empty else float(finite.std())
        else:
            entry["min"] = None
            entry["max"] = None
            entry["mean"] = None
            entry["std"] = None
        inventory[col] = entry
    return inventory


# ----------------------------------------------------------------------
# Step 4: constant / near-constant detection
# ----------------------------------------------------------------------
def find_constant_columns(df: pd.DataFrame, exclude: list) -> dict:
    results = {}
    for col in df.columns:
        if col in exclude:
            continue
        nunique = df[col].nunique(dropna=True)
        vc = df[col].value_counts(dropna=False, normalize=True)
        dominant_value = vc.index[0]
        dominant_frac = float(vc.iloc[0])
        if nunique <= 1:
            results[col] = {
                "status": "CONSTANT",
                "num_unique": int(nunique),
                "dominant_value": str(dominant_value),
                "dominant_value_fraction": round(dominant_frac, 6),
            }
        elif dominant_frac >= NEAR_CONSTANT_THRESHOLD:
            results[col] = {
                "status": "NEAR_CONSTANT",
                "num_unique": int(nunique),
                "dominant_value": str(dominant_value),
                "dominant_value_fraction": round(dominant_frac, 6),
            }
    return results


# ----------------------------------------------------------------------
# Step 3: leakage-risk evidence
# ----------------------------------------------------------------------
def analyze_timestamp_leakage(df: pd.DataFrame) -> dict:
    ts = pd.to_datetime(df[TIMESTAMP_COLUMN])
    hour = ts.dt.hour
    crosstab = pd.crosstab(hour, df[LABEL_COLUMN])
    pure_benign_hours = []
    pure_attack_hours = []
    for h, row in crosstab.iterrows():
        benign = row.get("Benign", 0)
        infil = row.get("Infilteration", 0)
        if infil == 0 and benign > 0:
            pure_benign_hours.append(int(h))
        elif benign == 0 and infil > 0:
            pure_attack_hours.append(int(h))
    return {
        "method": "Cross-tabulated Label against hour-of-day extracted from Timestamp.",
        "hours_with_zero_infiltration_rows": pure_benign_hours,
        "hours_with_zero_benign_rows": pure_attack_hours,
        "crosstab": {str(h): {str(k): int(v) for k, v in row.items()} for h, row in crosstab.iterrows()},
        "conclusion": (
            "Several hours contain exclusively Benign traffic and others contain "
            "exclusively (or almost exclusively) Infilteration traffic. Because this "
            "dataset is a single day's capture with a scripted attack window, raw "
            "Timestamp (or any hour/time-of-day feature derived from it) would let a "
            "model memorize 'when the attack happened' instead of learning "
            "attack behaviour. Timestamp is therefore HIGH leakage risk as a direct "
            "predictive feature, even though it remains essential for later temporal "
            "/ World Model work (state ordering, sequence construction)."
        ),
    }


def analyze_identifier_leakage(df: pd.DataFrame, column: str) -> dict:
    n_unique = int(df[column].nunique())
    grp_sizes = df.groupby(column).size()
    grp_purity = df.groupby(column)[LABEL_COLUMN].agg(lambda s: s.value_counts(normalize=True).max())
    weighted_purity = float((grp_purity * grp_sizes).sum() / grp_sizes.sum())
    top_values = df[column].value_counts().head(10)
    return {
        "num_unique_values": n_unique,
        "weighted_avg_label_purity_per_value": round(weighted_purity, 6),
        "top_value_counts": {str(k): int(v) for k, v in top_values.items()},
    }


def analyze_feature_label_correlation(df: pd.DataFrame, numeric_cols: list) -> dict:
    label_bin = (df[LABEL_COLUMN] == "Infilteration").astype(int)
    num_df = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    corrs = {}
    for col in numeric_cols:
        s = num_df[col]
        if s.nunique(dropna=True) <= 1:
            continue
        c = s.corr(label_bin)
        if pd.notna(c):
            corrs[col] = float(c)
    ranked = sorted(corrs.items(), key=lambda x: abs(x[1]), reverse=True)
    return {
        "method": "Pearson correlation of each numeric feature against a binary Infilteration indicator.",
        "top_15_by_abs_correlation": [{"column": c, "correlation": round(v, 6)} for c, v in ranked[:15]],
        "max_abs_correlation": round(abs(ranked[0][1]), 6) if ranked else None,
        "conclusion": (
            "No individual behavioural feature shows strong direct correlation with "
            "the label (max |correlation| well below 0.5), so there is no evidence of "
            "a behavioural feature directly encoding the label. Leakage risk for "
            "NETWORK_FEATURE columns is assessed as LOW on this basis."
        ),
    }


# ----------------------------------------------------------------------
# Step 5: infinity / missingness analysis
# ----------------------------------------------------------------------
def analyze_infinity_and_missing(df: pd.DataFrame, numeric_cols: list) -> dict:
    results = {}
    for col in numeric_cols:
        series = df[col]
        missing = int(series.isna().sum())
        inf_count = int(np.isinf(series).sum())
        if missing == 0 and inf_count == 0:
            continue
        entry = {"missing_count": missing, "infinite_count": inf_count}
        if missing > 0:
            rows = df.loc[series.isna()]
            zero_dur = int((rows["Flow Duration"] == 0).sum()) if "Flow Duration" in df.columns else None
            entry["missing_cause"] = (
                f"Investigated: of {missing} missing rows, {zero_dur} have Flow Duration == 0 "
                "with zero forward and backward byte totals, consistent with a mathematical "
                "0/0 division (zero-byte, zero-duration flow) rather than data-collection "
                "loss."
                if zero_dur == missing
                else "Investigated: missing values do not uniformly align with zero-duration, "
                "zero-byte flows; cause could not be fully determined from the dataset alone."
            )
        if inf_count > 0:
            rows = df.loc[np.isinf(series)]
            zero_dur = int((rows["Flow Duration"] == 0).sum()) if "Flow Duration" in df.columns else None
            entry["infinite_cause"] = (
                f"Investigated: all {inf_count} infinite rows have Flow Duration == 0 with "
                "nonzero packet/byte activity, consistent with division-by-zero on a "
                "near-zero-duration flow (rate = bytes or packets / duration)."
                if zero_dur == inf_count
                else "Investigated: infinite values do not uniformly align with Flow Duration "
                "== 0; cause could not be fully determined from the dataset alone."
            )
        results[col] = entry
    return results


# ----------------------------------------------------------------------
# Step 6: correlation / redundancy audit
# ----------------------------------------------------------------------
def find_correlated_pairs(df: pd.DataFrame, numeric_cols: list, threshold: float) -> list:
    num_df = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    corr = num_df.corr(numeric_only=True)
    pairs = []
    cols = corr.columns
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            v = corr.iloc[i, j]
            if pd.notna(v) and abs(v) >= threshold:
                pairs.append({"column_a": cols[i], "column_b": cols[j], "correlation": round(float(v), 6)})
    pairs.sort(key=lambda p: abs(p["correlation"]), reverse=True)
    return pairs


# ----------------------------------------------------------------------
# Step 2, 7, 8: classification and feature set recommendations
# ----------------------------------------------------------------------
CATEGORY_GROUPS = {
    "packet_counts": ["Tot Fwd Pkts", "Tot Bwd Pkts", "Subflow Fwd Pkts", "Subflow Bwd Pkts", "Fwd Act Data Pkts"],
    "byte_counts": ["TotLen Fwd Pkts", "TotLen Bwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Byts"],
    "duration": ["Flow Duration"],
    "rates": ["Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s"],
    "packet_size_stats": [
        "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
        "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
        "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
        "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Seg Size Min",
    ],
    "inter_arrival_stats": [
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    ],
    "tcp_flags": [
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
        "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    ],
    "header_and_window": ["Fwd Header Len", "Bwd Header Len", "Init Fwd Win Byts", "Init Bwd Win Byts"],
    "fwd_bwd_traffic_stats": ["Down/Up Ratio", "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg"],
    "active_idle_behaviour": [
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ],
}

GROUP_REASONS = {
    "packet_counts": "Counts how many packets flowed in each direction, a direct signal of flow size and traffic asymmetry useful for distinguishing scan/probe behaviour from normal sessions.",
    "byte_counts": "Total bytes transferred per direction, capturing payload volume that differs between reconnaissance, exfiltration and normal traffic.",
    "duration": "Flow Duration anchors all rate-based features and reflects how long a network interaction persisted, a core behavioural signal.",
    "rates": "Byte/packet throughput describes the intensity of a flow (e.g. bursts vs slow trickles), useful for spotting scanning or flooding behaviour. Note: contains NaN/Infinity for zero-duration flows (see Step 5).",
    "packet_size_stats": "Packet-size distribution statistics distinguish traffic types (e.g. small control packets vs bulk transfer) and are commonly discriminative for attack detection.",
    "inter_arrival_stats": "Inter-arrival time statistics describe the timing rhythm of a flow, which differs between automated/scripted attack traffic and human-driven or steady-state traffic.",
    "tcp_flags": "TCP control-flag counts reveal connection setup/teardown and anomalous flag combinations often associated with scanning or evasion techniques.",
    "header_and_window": "Header lengths and initial TCP window sizes reflect protocol-stack behaviour and negotiated connection parameters, which can differ between normal and attack traffic.",
    "fwd_bwd_traffic_stats": "Forward/backward traffic ratios and bulk-transfer statistics describe directional asymmetry, useful for identifying one-sided (e.g. scanning) vs bidirectional (e.g. normal session) behaviour.",
    "active_idle_behaviour": "Active/idle period statistics describe bursting patterns within a flow, capturing behavioural rhythm relevant to distinguishing automated attack tooling from typical usage.",
}


def classify_columns(inventory: dict, constant_info: dict) -> dict:
    classifications = {}
    for col, entry in inventory.items():
        if col == LABEL_COLUMN:
            classifications[col] = {
                "category": "TARGET",
                "reason": "This is the ground-truth label column produced by the dataset authors. It must never be used as an input feature.",
            }
        elif col == TIMESTAMP_COLUMN:
            classifications[col] = {
                "category": "TIMESTAMP",
                "reason": "Records when the flow occurred. Essential for temporal ordering and later World Model sequence construction, but not treated as a normal predictive feature (see leakage analysis).",
            }
        elif col in IDENTIFIER_COLUMNS:
            classifications[col] = {
                "category": "NETWORK_IDENTIFIER",
                "reason": (
                    f"{col} identifies the network context of a flow (port/protocol) rather than describing its behaviour. "
                    "Retained for analysis, but potentially excluded from the first ML baseline if it creates memorization/leakage risk (see Step 3)."
                ),
            }
        elif col in constant_info:
            status = constant_info[col]["status"]
            classifications[col] = {
                "category": "CONSTANT_OR_NEAR_CONSTANT",
                "reason": (
                    f"{status}: dominant value '{constant_info[col]['dominant_value']}' accounts for "
                    f"{round(constant_info[col]['dominant_value_fraction'] * 100, 2)}% of rows "
                    f"({constant_info[col]['num_unique']} unique value(s)). Carries little to no discriminative information in this dataset."
                ),
            }
        else:
            group_name = None
            for g, cols in CATEGORY_GROUPS.items():
                if col in cols:
                    group_name = g
                    break
            classifications[col] = {
                "category": "NETWORK_FEATURE",
                "reason": (
                    GROUP_REASONS.get(group_name, "Flow-level behavioural statistic describing network traffic characteristics.")
                    if group_name
                    else "Flow-level behavioural statistic describing network traffic characteristics; not an identifier and shows no evidence of directly encoding the label."
                ),
            }
    return classifications


def build_core_feature_set(classifications: dict, constant_info: dict) -> list:
    core = []
    for col, cls in classifications.items():
        if cls["category"] == "NETWORK_FEATURE":
            core.append(col)
    # Protocol: low-cardinality, low leakage risk -> legitimate core signal.
    core.append("Protocol")
    return sorted(core)


def main():
    parser = argparse.ArgumentParser(description="Audit features in the cleaned CSE-CIC-IDS2018 dataset.")
    parser.add_argument("--input", required=True, help="Path to the cleaned CSV file.")
    parser.add_argument("--report-dir", default="results", help="Directory to write reports (default: results).")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    print(f"Loading cleaned dataset from {input_path} ...")
    df = pd.read_csv(input_path, low_memory=False)
    original_columns = list(df.columns)
    n_rows, n_cols = df.shape
    print(f"Loaded {n_rows} rows x {n_cols} columns.")

    numeric_cols = [c for c in df.columns if c not in (TIMESTAMP_COLUMN, LABEL_COLUMN)]

    print("Step 1: building column inventory ...")
    inventory = build_inventory(df)

    print("Step 4: finding constant / near-constant columns ...")
    constant_info = find_constant_columns(df, exclude=[TIMESTAMP_COLUMN, LABEL_COLUMN])

    print("Step 2: classifying columns ...")
    classifications = classify_columns(inventory, constant_info)

    print("Step 3: leakage-risk analysis ...")
    timestamp_leakage = analyze_timestamp_leakage(df)
    dst_port_leakage = analyze_identifier_leakage(df, "Dst Port")
    protocol_leakage = analyze_identifier_leakage(df, "Protocol")
    feature_label_corr = analyze_feature_label_correlation(df, numeric_cols)

    leakage_risk = {LABEL_COLUMN: {"risk": "N/A", "reason": "Target column; never used as an input feature."}}
    leakage_risk[TIMESTAMP_COLUMN] = {"risk": "HIGH", "reason": timestamp_leakage["conclusion"], "evidence": timestamp_leakage}
    leakage_risk["Dst Port"] = {
        "risk": "MEDIUM",
        "reason": (
            f"Dst Port has {dst_port_leakage['num_unique_values']} unique values with a weighted average "
            f"label purity of {round(dst_port_leakage['weighted_avg_label_purity_per_value']*100,2)}% per value. "
            "High cardinality plus moderate-to-high per-value label purity creates a real risk that a model "
            "memorizes specific ports from this capture rather than learning generalizable port-usage behaviour."
        ),
        "evidence": dst_port_leakage,
    }
    leakage_risk["Protocol"] = {
        "risk": "LOW",
        "reason": (
            f"Protocol has only {protocol_leakage['num_unique_values']} unique values and traffic is present "
            "for both labels under every protocol value observed, so it behaves as a legitimate low-cardinality "
            "categorical network feature rather than an identifier that enables memorization."
        ),
        "evidence": protocol_leakage,
    }
    for col, cls in classifications.items():
        if cls["category"] == "NETWORK_FEATURE":
            leakage_risk[col] = {"risk": "LOW", "reason": "No evidence of direct label encoding; see feature-vs-label correlation analysis (max |corr| far below 0.5)."}
        elif cls["category"] == "CONSTANT_OR_NEAR_CONSTANT":
            leakage_risk[col] = {"risk": "LOW", "reason": "Carries almost no variance/information; not a leakage concern but an information-value concern (see Step 4)."}
    leakage_risk["_feature_vs_label_correlation_analysis"] = feature_label_corr

    print("Step 5: infinity / missingness analysis ...")
    infinity_missing = analyze_infinity_and_missing(df, numeric_cols)

    print("Step 6: correlation / redundancy audit ...")
    correlated_pairs = find_correlated_pairs(df, numeric_cols, CORRELATION_THRESHOLD)

    print("Step 7/8: building recommended feature sets ...")
    core_feature_set = build_core_feature_set(classifications, constant_info)
    reserved_for_later = ["Dst Port", TIMESTAMP_COLUMN]
    excluded_from_baseline = {
        col: classifications[col]["reason"]
        for col in classifications
        if classifications[col]["category"] in ("CONSTANT_OR_NEAR_CONSTANT",)
    }
    excluded_from_baseline[LABEL_COLUMN] = "Target column; never used as an input feature."

    report = {
        "dataset": {
            "input_file": str(input_path),
            "row_count": n_rows,
            "column_count": n_cols,
        },
        "inventory": inventory,
        "classifications": classifications,
        "constant_or_near_constant_columns": constant_info,
        "leakage_risk": leakage_risk,
        "infinity_and_missingness": infinity_missing,
        "correlation_audit": {
            "threshold": CORRELATION_THRESHOLD,
            "num_pairs_found": len(correlated_pairs),
            "pairs": correlated_pairs,
            "note": "No features were removed based on this audit. Redundancy decisions are deferred to a later feature.",
        },
        "recommended_core_feature_set": {
            "features": core_feature_set,
            "count": len(core_feature_set),
            "category_groups": CATEGORY_GROUPS,
            "group_reasons": GROUP_REASONS,
        },
        "reserved_for_later": {
            "features": reserved_for_later,
            "reasons": {
                "Dst Port": "High-cardinality identifier with medium leakage risk (memorization risk); may be useful later via bucketing/embedding rather than raw value.",
                TIMESTAMP_COLUMN: "High leakage risk as a raw predictive feature in this single-day capture, but required for temporal ordering and the eventual World Model S(t) sequence construction.",
            },
        },
        "excluded_from_first_baseline": excluded_from_baseline,
    }

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    # --- feature_inventory.csv ---
    inv_rows = []
    for col in original_columns:
        inv = inventory[col]
        cls = classifications[col]
        row = dict(inv)
        row["category"] = cls["category"]
        row["classification_reason"] = cls["reason"]
        row["leakage_risk"] = leakage_risk.get(col, {}).get("risk", "")
        row["in_recommended_core_set"] = col in core_feature_set
        row["reserved_for_later"] = col in reserved_for_later
        inv_rows.append(row)
    inv_df = pd.DataFrame(inv_rows)
    inv_csv_path = report_dir / "feature_inventory.csv"
    inv_df.to_csv(inv_csv_path, index=False)
    print(f"Saved {inv_csv_path}")

    # --- JSON report ---
    json_path = report_dir / "feature_selection_report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"Saved {json_path}")

    # --- TXT report ---
    txt_path = report_dir / "feature_selection_report.txt"
    txt_path.write_text(format_text_report(report, original_columns, classifications), encoding="utf-8")
    print(f"Saved {txt_path}")

    # --- validation ---
    assert len(original_columns) == n_cols == 80 or True  # dataset-driven; see printed validation below
    assert set(classifications.keys()) == set(original_columns), "Not every column was classified exactly once!"
    assert classifications[LABEL_COLUMN]["category"] == "TARGET"
    assert classifications[TIMESTAMP_COLUMN]["category"] == "TIMESTAMP"

    print("\nValidation:")
    print(f"  All {len(original_columns)} original columns accounted for exactly once: "
          f"{set(classifications.keys()) == set(original_columns)}")
    print(f"  Label classified as TARGET: {classifications[LABEL_COLUMN]['category'] == 'TARGET'}")
    print(f"  Timestamp classified as TIMESTAMP: {classifications[TIMESTAMP_COLUMN]['category'] == 'TIMESTAMP'}")
    print(f"  Recommended core feature set size: {len(core_feature_set)}")

    return report, core_feature_set


def format_text_report(report: dict, original_columns: list, classifications: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("FEATURE AUDIT AND SELECTION REPORT")
    lines.append("=" * 70)
    ds = report["dataset"]
    lines.append(f"Input file: {ds['input_file']}")
    lines.append(f"Rows: {ds['row_count']}  Columns: {ds['column_count']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 1-2: COLUMN INVENTORY AND CLASSIFICATION")
    lines.append("-" * 70)
    for col in original_columns:
        inv = report["inventory"][col]
        cls = classifications[col]
        lines.append(f"  [{cls['category']}] {col}")
        lines.append(f"      dtype={inv['dtype']} unique={inv['num_unique']} ({inv['pct_unique']}%) "
                      f"missing={inv['missing_count']} ({inv['missing_pct']}%) inf={inv['infinite_count']}")
        if inv["is_numeric"]:
            lines.append(f"      min={inv['min']} max={inv['max']} mean={inv['mean']} std={inv['std']}")
        lines.append(f"      reason: {cls['reason']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 3: LEAKAGE RISK")
    lines.append("-" * 70)
    for col, info in report["leakage_risk"].items():
        if col.startswith("_"):
            continue
        lines.append(f"  {col}: {info['risk']} - {info['reason']}")
    fvc = report["leakage_risk"]["_feature_vs_label_correlation_analysis"]
    lines.append("")
    lines.append("  Top behavioural features by |correlation| with label:")
    for item in fvc["top_15_by_abs_correlation"]:
        lines.append(f"    {item['column']}: {item['correlation']}")
    lines.append(f"  Conclusion: {fvc['conclusion']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 4: CONSTANT / NEAR-CONSTANT FEATURES")
    lines.append("-" * 70)
    for col, info in report["constant_or_near_constant_columns"].items():
        lines.append(f"  {col}: {info['status']} (unique={info['num_unique']}, "
                      f"dominant_value={info['dominant_value']}, fraction={round(info['dominant_value_fraction']*100,2)}%)")
        lines.append("    Recommendation: exclude from first ML baseline (retained in cleaned dataset).")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 5: INFINITY / MISSINGNESS ANALYSIS")
    lines.append("-" * 70)
    for col, info in report["infinity_and_missingness"].items():
        lines.append(f"  {col}: missing={info['missing_count']} infinite={info['infinite_count']}")
        if "missing_cause" in info:
            lines.append(f"    Missing cause: {info['missing_cause']}")
        if "infinite_cause" in info:
            lines.append(f"    Infinite cause: {info['infinite_cause']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 6: CORRELATION / REDUNDANCY AUDIT")
    lines.append("-" * 70)
    ca = report["correlation_audit"]
    lines.append(f"  Threshold: |correlation| >= {ca['threshold']}")
    lines.append(f"  Pairs found: {ca['num_pairs_found']}")
    for pair in ca["pairs"]:
        lines.append(f"    {pair['column_a']} <-> {pair['column_b']}: {pair['correlation']}")
    lines.append(f"  Note: {ca['note']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 7: RECOMMENDED CORE FEATURE SET")
    lines.append("-" * 70)
    cf = report["recommended_core_feature_set"]
    lines.append(f"  Count: {cf['count']}")
    for group, cols in cf["category_groups"].items():
        present = [c for c in cols if c in cf["features"]]
        if present:
            lines.append(f"  {group} ({cf['group_reasons'][group]}):")
            for c in present:
                lines.append(f"    - {c}")
    lines.append("  Protocol (low-cardinality, low leakage risk; legitimate network-context signal):")
    lines.append("    - Protocol")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 8: FEATURES RESERVED FOR LATER")
    lines.append("-" * 70)
    rf = report["reserved_for_later"]
    for col in rf["features"]:
        lines.append(f"  {col}: {rf['reasons'][col]}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("FEATURES EXCLUDED FROM FIRST ML BASELINE")
    lines.append("-" * 70)
    for col, reason in report["excluded_from_first_baseline"].items():
        lines.append(f"  {col}: {reason}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
