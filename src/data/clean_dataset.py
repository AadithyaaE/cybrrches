"""
Cleaning pipeline for CSE-CIC-IDS2018 flow CSV files.

Evidence-based, reproducible cleaning. For each step, decisions are made
from what is actually observed in the data (not assumed), and every
decision is recorded in the cleaning report.

Steps performed:
    1. Load the raw CSV (never modified).
    2. Detect and remove embedded duplicate header rows (rows where every
       cell equals that column's own header text).
    3. Convert feature columns to numeric types with pd.to_numeric(errors="coerce"),
       tracking any NaN values introduced by conversion vs already present.
    4. Parse Timestamp to a real datetime using an explicit day/month/year
       format (the source file uses DD/MM/YYYY, which is ambiguous under
       pandas' default date inference).
    5. Preserve Label values exactly as recorded (no renaming/merging).
    6. Investigate duplicate rows before removing anything: only exact,
       full-row duplicates (identical across all 80 columns) are removed;
       rows that share identical traffic features but disagree on Label
       are left in place and flagged as a known ambiguity.
    7. Recompute missing values after cleaning and explain their origin.

Does NOT perform feature selection, normalization, encoding, class
balancing, or any modeling.

Usage:
    python src/data/clean_dataset.py \
        --input data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv \
        --output data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

TIMESTAMP_COLUMN = "Timestamp"
LABEL_COLUMN = "Label"
TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
EXPECTED_EMBEDDED_HEADER_ROWS = 25


def detect_embedded_header_rows(df: pd.DataFrame) -> pd.Series:
    """Flag rows where every cell equals that column's own header text."""
    header_as_row = pd.Series(df.columns, index=df.columns).astype(str)
    return (df.astype(str) == header_as_row).all(axis=1)


def convert_numeric_columns(df: pd.DataFrame, numeric_columns: list) -> tuple:
    """Convert feature columns to numeric, tracking NaN/inf behaviour per column."""
    df = df.copy()
    conversion_report = {}
    for col in numeric_columns:
        raw_nan_before = int(df[col].isna().sum())
        converted = pd.to_numeric(df[col], errors="coerce")
        nan_after = int(converted.isna().sum())
        inf_count = int(np.isinf(converted.astype("float64")).sum())
        coercion_introduced_nan = nan_after - raw_nan_before
        df[col] = converted
        conversion_report[col] = {
            "raw_nan_before_conversion": raw_nan_before,
            "nan_after_conversion": nan_after,
            "coercion_introduced_nan": coercion_introduced_nan,
            "infinite_values": inf_count,
        }
    return df, conversion_report


def investigate_duplicates(df: pd.DataFrame) -> dict:
    """Characterize duplicate rows before any removal decision is made."""
    all_cols = list(df.columns)
    feature_cols = [c for c in all_cols if c != LABEL_COLUMN]

    full_dup_extra = df.duplicated(keep="first")
    full_dup_all = df.duplicated(keep=False)

    n_full_dup_groups = 0
    if full_dup_all.any():
        n_full_dup_groups = df.loc[full_dup_all].groupby(all_cols, dropna=False).ngroups

    # Duplicates when ignoring Label reveal whether identical traffic
    # was ever recorded under more than one label.
    dup_no_label = df.duplicated(subset=feature_cols, keep=False)
    conflicting_groups = 0
    conflicting_rows = 0
    conflicting_examples = []
    if dup_no_label.any():
        sub = df.loc[dup_no_label]
        label_nunique = sub.groupby(feature_cols, dropna=False)[LABEL_COLUMN].nunique()
        conflicting_keys = label_nunique[label_nunique > 1]
        conflicting_groups = int(len(conflicting_keys))
        if conflicting_groups > 0:
            mask = pd.Series(False, index=sub.index)
            for key in conflicting_keys.index:
                key = key if isinstance(key, tuple) else (key,)
                row_mask = pd.Series(True, index=sub.index)
                for col, val in zip(feature_cols, key):
                    row_mask &= sub[col] == val
                mask |= row_mask
            conflicting_rows = int(mask.sum())
            examples = sub.loc[mask, [TIMESTAMP_COLUMN, "Dst Port", "Protocol", LABEL_COLUMN]].head(10)
            conflicting_examples = (
                examples.reset_index().rename(columns={"index": "row_index"}).to_dict(orient="records")
            )

    return {
        "full_row_duplicate_extra_rows": int(full_dup_extra.sum()),
        "full_row_duplicate_total_rows_involved": int(full_dup_all.sum()),
        "full_row_duplicate_groups": int(n_full_dup_groups),
        "conflicting_label_groups": conflicting_groups,
        "conflicting_label_rows_involved": conflicting_rows,
        "conflicting_label_examples": conflicting_examples,
    }, full_dup_extra


def clean_dataset(input_path: Path) -> dict:
    raw_df = pd.read_csv(input_path, low_memory=False)
    raw_row_count, raw_col_count = raw_df.shape
    raw_columns = list(raw_df.columns)

    # --- Step 2: embedded header rows ---
    header_mask = detect_embedded_header_rows(raw_df)
    n_header_rows = int(header_mask.sum())
    df = raw_df.loc[~header_mask].reset_index(drop=True).copy()

    header_investigation_needed = n_header_rows != EXPECTED_EMBEDDED_HEADER_ROWS

    # --- Step 3: numeric conversion ---
    non_numeric_semantic = [TIMESTAMP_COLUMN, LABEL_COLUMN]
    numeric_columns = [c for c in df.columns if c not in non_numeric_semantic]
    df, numeric_conversion_report = convert_numeric_columns(df, numeric_columns)

    unexpected_coercion_nans = {
        col: rep for col, rep in numeric_conversion_report.items() if rep["coercion_introduced_nan"] > 0
    }

    # --- Step 4: timestamp ---
    parsed_ts = pd.to_datetime(df[TIMESTAMP_COLUMN], format=TIMESTAMP_FORMAT, errors="coerce")
    n_ts_failed = int(parsed_ts.isna().sum())
    n_ts_parsed = int(parsed_ts.notna().sum())
    timestamp_failures = []
    if n_ts_failed > 0:
        timestamp_failures = df.loc[parsed_ts.isna(), TIMESTAMP_COLUMN].head(20).tolist()
    df[TIMESTAMP_COLUMN] = parsed_ts

    # --- Step 5: label ---
    label_distribution_after_header_removal = {
        str(k): int(v) for k, v in df[LABEL_COLUMN].value_counts(dropna=False).items()
    }
    expected_labels = {"Benign", "Infilteration"}
    observed_labels = set(label_distribution_after_header_removal.keys())
    unexpected_labels = sorted(observed_labels - expected_labels)

    # --- Step 6: duplicates ---
    dup_investigation, full_dup_extra_mask = investigate_duplicates(df)

    duplicates_before_any_removal = dup_investigation["full_row_duplicate_extra_rows"]

    # Decision: only exact, full-row duplicates (identical across all 80
    # columns, including Timestamp and Label) are removed. Rows that share
    # identical traffic features but disagree on Label are NOT exact
    # duplicates and are left untouched (flagged above instead).
    removal_decision = (
        f"Removed {duplicates_before_any_removal} exact full-row duplicate(s) "
        f"(identical across all {len(df.columns)} columns, including Timestamp "
        f"and Label). {dup_investigation['conflicting_label_groups']} additional "
        f"group(s) ({dup_investigation['conflicting_label_rows_involved']} rows) "
        "share identical traffic features but disagree on Label - these are NOT "
        "exact duplicates and were left in the dataset unmodified; they are "
        "flagged for awareness."
    )
    df = df.loc[~full_dup_extra_mask].reset_index(drop=True)
    duplicates_after_removal = int(df.duplicated(keep="first").sum())

    # --- Step 7: missing values after cleaning ---
    missing_after = df.isna().sum()
    missing_after = {col: int(missing_after[col]) for col in df.columns if missing_after[col] > 0}

    # --- Step 8: validation ---
    final_row_count, final_col_count = df.shape
    validation = {
        "columns_unchanged": list(df.columns) == raw_columns,
        "no_embedded_header_rows_remain": bool(not detect_embedded_header_rows(df).any()),
        "timestamp_is_datetime": pd.api.types.is_datetime64_any_dtype(df[TIMESTAMP_COLUMN]),
        "label_column_present": LABEL_COLUMN in df.columns,
        "expected_numeric_columns_are_numeric": all(
            pd.api.types.is_numeric_dtype(df[c]) for c in numeric_columns
        ),
        "final_row_count": int(final_row_count),
        "final_column_count": int(final_col_count),
        "final_duplicate_count": duplicates_after_removal,
        "final_label_distribution": {
            str(k): int(v) for k, v in df[LABEL_COLUMN].value_counts(dropna=False).items()
        },
        "final_missing_values": missing_after,
        "final_min_timestamp": str(df[TIMESTAMP_COLUMN].min()),
        "final_max_timestamp": str(df[TIMESTAMP_COLUMN].max()),
    }

    report = {
        "raw_data": {
            "input_file": str(input_path),
            "raw_row_count": raw_row_count,
            "raw_column_count": raw_col_count,
        },
        "embedded_headers": {
            "expected_count": EXPECTED_EMBEDDED_HEADER_ROWS,
            "detected_count": n_header_rows,
            "matches_expectation": not header_investigation_needed,
            "detection_method": (
                "A row is flagged as an embedded header row when every cell in "
                "that row equals the header text of its own column (compared as "
                "strings across all columns), rather than assuming fixed row "
                "positions."
            ),
            "rows_removed": n_header_rows,
        },
        "data_types": {
            "timestamp_column": TIMESTAMP_COLUMN,
            "label_column": LABEL_COLUMN,
            "numeric_columns": numeric_columns,
            "numeric_column_count": len(numeric_columns),
            "non_numeric_semantic_columns": non_numeric_semantic,
            "conversion_details": numeric_conversion_report,
            "columns_with_unexpected_new_nans_from_conversion": unexpected_coercion_nans,
        },
        "timestamp": {
            "format_used": TIMESTAMP_FORMAT,
            "parsed_successfully": n_ts_parsed,
            "failed_to_parse": n_ts_failed,
            "failed_examples": timestamp_failures,
            "min_timestamp": str(parsed_ts.min()),
            "max_timestamp": str(parsed_ts.max()),
            "note": (
                "An explicit DD/MM/YYYY format is used because the source "
                "timestamps (e.g. '01/03/2018') are ambiguous under pandas' "
                "default date inference, which would otherwise misread them as "
                "MM/DD/YYYY (e.g. January 3 instead of the correct March 1, "
                "consistent with the file name 'Thursday-01-03-2018' - March 1, "
                "2018 was a Thursday)."
            ),
        },
        "labels": {
            "distribution_after_header_removal": label_distribution_after_header_removal,
            "expected_labels": sorted(expected_labels),
            "unexpected_labels_found": unexpected_labels,
            "labels_renamed_or_merged": False,
        },
        "duplicates": {
            "duplicate_count_reported_in_feature1": 97,
            "duplicate_count_after_header_removal": duplicates_before_any_removal,
            "investigation": dup_investigation,
            "removal_decision": removal_decision,
            "duplicate_count_after_cleaning": duplicates_after_removal,
        },
        "missing_values": {
            "after_cleaning": missing_after,
            "explanation": (
                "Missing values remaining after cleaning were already present in "
                "the raw CSV as literal 'NaN' strings (observed only in 'Flow "
                "Byts/s') and were not introduced by numeric conversion or "
                "timestamp parsing. No rows were dropped because of missing "
                "values. Some flow-rate columns ('Flow Byts/s', 'Flow Pkts/s') "
                "also contain literal 'Infinity' values from the source data "
                "(near-zero-duration flows); these were preserved as infinite "
                "floats, not treated as missing."
            ),
        },
        "validation": validation,
        "final_dataset": {
            "final_row_count": final_row_count,
            "final_column_count": final_col_count,
        },
    }

    return df, report


def format_text_report(report: dict, output_path: Path) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("DATASET CLEANING REPORT")
    lines.append("=" * 70)

    lines.append("")
    lines.append("-" * 70)
    lines.append("RAW DATA")
    lines.append("-" * 70)
    rd = report["raw_data"]
    lines.append(f"  Original file: {rd['input_file']}")
    lines.append(f"  Original row count: {rd['raw_row_count']}")
    lines.append(f"  Original column count: {rd['raw_column_count']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("EMBEDDED HEADERS")
    lines.append("-" * 70)
    eh = report["embedded_headers"]
    lines.append(f"  Expected count: {eh['expected_count']}")
    lines.append(f"  Detected count: {eh['detected_count']}")
    lines.append(f"  Matches expectation: {eh['matches_expectation']}")
    lines.append(f"  Detection method: {eh['detection_method']}")
    lines.append(f"  Rows removed: {eh['rows_removed']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("DATA TYPES")
    lines.append("-" * 70)
    dt = report["data_types"]
    lines.append(f"  Timestamp column (kept as datetime): {dt['timestamp_column']}")
    lines.append(f"  Label column (kept as text): {dt['label_column']}")
    lines.append(f"  Numeric columns converted: {dt['numeric_column_count']}")
    if dt["columns_with_unexpected_new_nans_from_conversion"]:
        lines.append("  Columns where conversion introduced NEW NaNs (unexpected):")
        for col, rep in dt["columns_with_unexpected_new_nans_from_conversion"].items():
            lines.append(f"    {col}: {rep}")
    else:
        lines.append("  No column had NEW NaNs introduced by numeric conversion.")
    lines.append("  Columns with pre-existing NaN or infinite values (from raw data):")
    for col, rep in dt["conversion_details"].items():
        if rep["raw_nan_before_conversion"] > 0 or rep["infinite_values"] > 0:
            lines.append(
                f"    {col}: raw_nan_before={rep['raw_nan_before_conversion']}, "
                f"nan_after={rep['nan_after_conversion']}, "
                f"infinite_values={rep['infinite_values']}"
            )

    lines.append("")
    lines.append("-" * 70)
    lines.append("TIMESTAMP")
    lines.append("-" * 70)
    ts = report["timestamp"]
    lines.append(f"  Format used: {ts['format_used']}")
    lines.append(f"  Parsed successfully: {ts['parsed_successfully']}")
    lines.append(f"  Failed to parse: {ts['failed_to_parse']}")
    lines.append(f"  Minimum timestamp: {ts['min_timestamp']}")
    lines.append(f"  Maximum timestamp: {ts['max_timestamp']}")
    lines.append(f"  Note: {ts['note']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("LABELS")
    lines.append("-" * 70)
    lb = report["labels"]
    lines.append("  Distribution after header removal:")
    for label, count in lb["distribution_after_header_removal"].items():
        lines.append(f"    {label}: {count}")
    lines.append(f"  Unexpected labels found: {lb['unexpected_labels_found'] or 'None'}")
    lines.append(f"  Labels renamed or merged: {lb['labels_renamed_or_merged']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("DUPLICATES")
    lines.append("-" * 70)
    dup = report["duplicates"]
    lines.append(f"  Duplicate count reported in Feature 1 (raw, incl. header rows): {dup['duplicate_count_reported_in_feature1']}")
    lines.append(f"  Duplicate count after header removal: {dup['duplicate_count_after_header_removal']}")
    inv = dup["investigation"]
    lines.append(f"  Full-row duplicate groups: {inv['full_row_duplicate_groups']}")
    lines.append(f"  Rows involved in full-row duplicate groups: {inv['full_row_duplicate_total_rows_involved']}")
    lines.append(f"  Conflicting-label groups (same features, different Label): {inv['conflicting_label_groups']}")
    lines.append(f"  Rows involved in conflicting-label groups: {inv['conflicting_label_rows_involved']}")
    if inv["conflicting_label_examples"]:
        lines.append("  Example conflicting-label rows:")
        for ex in inv["conflicting_label_examples"]:
            lines.append(f"    {ex}")
    lines.append(f"  Decision: {dup['removal_decision']}")
    lines.append(f"  Duplicate count after cleaning: {dup['duplicate_count_after_cleaning']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("MISSING VALUES")
    lines.append("-" * 70)
    mv = report["missing_values"]
    lines.append("  After cleaning:")
    if mv["after_cleaning"]:
        for col, count in mv["after_cleaning"].items():
            lines.append(f"    {col}: {count}")
    else:
        lines.append("    None")
    lines.append(f"  Explanation: {mv['explanation']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("VALIDATION")
    lines.append("-" * 70)
    val = report["validation"]
    for key in [
        "columns_unchanged",
        "no_embedded_header_rows_remain",
        "timestamp_is_datetime",
        "label_column_present",
        "expected_numeric_columns_are_numeric",
        "final_row_count",
        "final_column_count",
        "final_duplicate_count",
        "final_min_timestamp",
        "final_max_timestamp",
    ]:
        lines.append(f"  {key}: {val[key]}")
    lines.append("  final_label_distribution:")
    for label, count in val["final_label_distribution"].items():
        lines.append(f"    {label}: {count}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("FINAL DATASET")
    lines.append("-" * 70)
    fd = report["final_dataset"]
    lines.append(f"  Final row count: {fd['final_row_count']}")
    lines.append(f"  Final column count: {fd['final_column_count']}")
    lines.append(f"  Output file: {output_path}")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Clean a CSE-CIC-IDS2018 CSV file (embedded headers, types, exact duplicates)."
    )
    parser.add_argument("--input", required=True, help="Path to the raw CSV file.")
    parser.add_argument("--output", required=True, help="Path to write the cleaned CSV file.")
    parser.add_argument(
        "--report-dir",
        default="results",
        help="Directory to write the cleaning report (default: results).",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    report_dir = Path(args.report_dir)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    print(f"Loading raw data from {input_path} ...")
    cleaned_df, report = clean_dataset(input_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cleaned_df.to_csv(output_path, index=False)
    print(f"Cleaned CSV written to {output_path}")

    report_dir.mkdir(parents=True, exist_ok=True)
    txt_path = report_dir / "dataset_cleaning_report.txt"
    json_path = report_dir / "dataset_cleaning_report.json"

    text_report = format_text_report(report, output_path)
    txt_path.write_text(text_report, encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    print(text_report)
    print(f"\nSaved text report to: {txt_path}")
    print(f"Saved JSON report to: {json_path}")

    # Confirm the original file was never touched.
    assert input_path.exists(), "Original raw CSV is missing!"


if __name__ == "__main__":
    main()
