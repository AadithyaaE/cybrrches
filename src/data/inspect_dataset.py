"""
Dataset inspector for CSE-CIC-IDS2018 CSV files.

Read-only inspection tool: reports structure, types, missing values,
duplicates, and basic statistics for a given CSV file. Does not modify,
clean, or transform the input file in any way.

Usage:
    python src/data/inspect_dataset.py --file data/raw/example.csv
"""

import argparse
import json
from pathlib import Path

import pandas as pd

# Candidate column names to check when guessing the label column.
LABEL_NAME_CANDIDATES = ["label", "class", "attack", "attack_type", "category"]

# Candidate column names to check when guessing the timestamp column.
TIMESTAMP_NAME_CANDIDATES = ["timestamp", "time", "date", "flow start", "starttime"]


def find_label_column(columns):
    """Identify the most likely label column by exact/substring name match."""
    lower_map = {col: col.strip().lower() for col in columns}

    # Exact match first.
    for col, lower in lower_map.items():
        if lower in LABEL_NAME_CANDIDATES:
            return col

    # Substring match next.
    for col, lower in lower_map.items():
        if any(candidate in lower for candidate in LABEL_NAME_CANDIDATES):
            return col

    return None


def find_timestamp_column(columns):
    """Identify the most likely timestamp column by exact/substring name match."""
    lower_map = {col: col.strip().lower() for col in columns}

    for col, lower in lower_map.items():
        if lower in TIMESTAMP_NAME_CANDIDATES:
            return col

    for col, lower in lower_map.items():
        if any(candidate in lower for candidate in TIMESTAMP_NAME_CANDIDATES):
            return col

    return None


def inspect_csv(file_path: Path) -> dict:
    df = pd.read_csv(file_path, low_memory=False)

    n_rows, n_cols = df.shape
    columns = list(df.columns)

    dtypes = {col: str(df[col].dtype) for col in columns}

    missing_counts = df.isna().sum()
    missing_percentages = (missing_counts / n_rows * 100) if n_rows > 0 else missing_counts

    duplicate_rows = int(df.duplicated().sum())

    numeric_columns = list(df.select_dtypes(include="number").columns)
    non_numeric_columns = [col for col in columns if col not in numeric_columns]

    label_column = find_label_column(columns)
    label_distribution = None
    if label_column is not None:
        label_distribution = {
            str(k): int(v) for k, v in df[label_column].value_counts(dropna=False).items()
        }

    timestamp_column = find_timestamp_column(columns)
    min_timestamp = None
    max_timestamp = None
    if timestamp_column is not None:
        parsed_ts = pd.to_datetime(df[timestamp_column], errors="coerce")
        valid_ts = parsed_ts.dropna()
        if len(valid_ts) > 0:
            min_timestamp = str(valid_ts.min())
            max_timestamp = str(valid_ts.max())

    numeric_stats = {}
    if numeric_columns:
        desc = df[numeric_columns].describe().to_dict()
        for col, stats in desc.items():
            numeric_stats[col] = {stat: (None if pd.isna(v) else v) for stat, v in stats.items()}

    report = {
        "file_name": file_path.name,
        "file_path": str(file_path),
        "num_rows": int(n_rows),
        "num_columns": int(n_cols),
        "column_names": columns,
        "dtypes": dtypes,
        "missing_value_counts": {col: int(missing_counts[col]) for col in columns},
        "missing_value_percentages": {
            col: round(float(missing_percentages[col]), 4) for col in columns
        },
        "num_duplicate_rows": duplicate_rows,
        "numeric_columns": numeric_columns,
        "non_numeric_columns": non_numeric_columns,
        "label_column": label_column,
        "label_column_confident": label_column is not None,
        "label_distribution": label_distribution,
        "timestamp_column": timestamp_column,
        "timestamp_column_confident": timestamp_column is not None,
        "min_timestamp": min_timestamp,
        "max_timestamp": max_timestamp,
        "numeric_column_statistics": numeric_stats,
    }

    return report


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("DATASET INSPECTION REPORT")
    lines.append("=" * 70)
    lines.append(f"File name: {report['file_name']}")
    lines.append(f"File path: {report['file_path']}")
    lines.append(f"Number of rows: {report['num_rows']}")
    lines.append(f"Number of columns: {report['num_columns']}")
    lines.append(f"Number of duplicate rows: {report['num_duplicate_rows']}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("COLUMN NAMES")
    lines.append("-" * 70)
    for col in report["column_names"]:
        lines.append(f"  - {col}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("DATA TYPES")
    lines.append("-" * 70)
    for col, dtype in report["dtypes"].items():
        lines.append(f"  {col}: {dtype}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("MISSING VALUES (count / percentage)")
    lines.append("-" * 70)
    for col in report["column_names"]:
        count = report["missing_value_counts"][col]
        pct = report["missing_value_percentages"][col]
        lines.append(f"  {col}: {count} ({pct}%)")
    lines.append("")

    lines.append("-" * 70)
    lines.append("NUMERIC COLUMNS")
    lines.append("-" * 70)
    lines.append(f"  Count: {len(report['numeric_columns'])}")
    for col in report["numeric_columns"]:
        lines.append(f"  - {col}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("NON-NUMERIC COLUMNS")
    lines.append("-" * 70)
    lines.append(f"  Count: {len(report['non_numeric_columns'])}")
    for col in report["non_numeric_columns"]:
        lines.append(f"  - {col}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("LABEL COLUMN")
    lines.append("-" * 70)
    if report["label_column"]:
        lines.append(f"  Identified label column: {report['label_column']}")
        lines.append("  Label distribution:")
        for label, count in report["label_distribution"].items():
            lines.append(f"    {label}: {count}")
    else:
        lines.append("  Could NOT confidently identify a label column.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TIMESTAMP COLUMN")
    lines.append("-" * 70)
    if report["timestamp_column"]:
        lines.append(f"  Identified timestamp column: {report['timestamp_column']}")
        lines.append(f"  Min timestamp: {report['min_timestamp']}")
        lines.append(f"  Max timestamp: {report['max_timestamp']}")
    else:
        lines.append("  Could NOT confidently identify a timestamp column.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("BASIC STATISTICS FOR NUMERIC COLUMNS")
    lines.append("-" * 70)
    for col, stats in report["numeric_column_statistics"].items():
        lines.append(f"  {col}:")
        for stat_name, stat_value in stats.items():
            lines.append(f"    {stat_name}: {stat_value}")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Inspect a CSE-CIC-IDS2018 CSV file (read-only, no modifications)."
    )
    parser.add_argument("--file", required=True, help="Path to the CSV file to inspect.")
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory to write the inspection report (default: results).",
    )
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        raise SystemExit(f"File not found: {file_path}")

    print(f"Inspecting {file_path} ...")
    report = inspect_csv(file_path)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    txt_path = output_dir / "dataset_inspection.txt"
    json_path = output_dir / "dataset_inspection.json"

    text_report = format_text_report(report)
    txt_path.write_text(text_report, encoding="utf-8")

    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    print(text_report)
    print(f"\nSaved text report to: {txt_path}")
    print(f"Saved JSON report to: {json_path}")


if __name__ == "__main__":
    main()
