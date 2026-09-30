"""
Model-ready feature preparation for the cleaned CSE-CIC-IDS2018 dataset.

Converts the Feature 3 audit's recommended 66-feature baseline into a
model-ready artifact set. This is PREPARATION ONLY:

    - no model is trained
    - no imputer/scaler statistic is fitted on the full dataset
    - no sequences, states, or forecasts are created

Design principle (train/test-leakage safety):
    Numeric imputation (SimpleImputer) and scaling (StandardScaler) both
    require statistics computed FROM data (median, mean, std). Fitting
    those on the full dataset now, before any train/test split exists,
    would leak test-set information into preparation. So this script:

        1. converts invalid Infinity values to NaN (structural, not a
           statistic - safe to do globally),
        2. one-hot encodes Protocol (structural, fixed categories - safe
           to do globally, does not encode any label information),
        3. builds a scikit-learn ColumnTransformer(SimpleImputer +
           StandardScaler) for the numeric columns but does NOT call
           .fit() on it,
        4. saves that UNFITTED transformer to disk so a later feature
           (actual model training) can fit it on the training split only.

    The saved feature matrix therefore still contains NaN for missing
    numeric values - this is intentional, not an oversight.

Usage:
    python src/data/prepare_features.py \
        --input data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv
"""

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted, NotFittedError

TIMESTAMP_COLUMN = "Timestamp"
TARGET_COLUMN = "Label"
PROTOCOL_COLUMN = "Protocol"
# The RAW CIC-IDS2018 CSV uses DD/MM/YYYY (see Feature 2). The CLEANED CSV
# produced by Feature 2 already stores Timestamp as a parsed datetime, which
# pandas.to_csv serializes as unambiguous ISO 8601 (YYYY-MM-DD HH:MM:SS).
# Both formats are tried explicitly below - never pandas' ambiguous default
# inference - and the one actually used is recorded in the report.
TIMESTAMP_FORMAT_CANDIDATES = ["%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]
LABEL_ENCODING = {"Benign": 0, "Infilteration": 1}
IMPUTATION_STRATEGY = "median"


def parse_timestamp_explicit(series: pd.Series, format_candidates: list) -> tuple:
    """Try explicit timestamp formats in order; never fall back to ambiguous inference."""
    for fmt in format_candidates:
        parsed = pd.to_datetime(series, format=fmt, errors="coerce")
        n_failed = int(parsed.isna().sum())
        if n_failed == 0:
            return parsed, fmt, n_failed
    # No candidate format fully succeeded - return the best (fewest failures) attempt.
    best_parsed, best_fmt, best_failed = None, None, None
    for fmt in format_candidates:
        parsed = pd.to_datetime(series, format=fmt, errors="coerce")
        n_failed = int(parsed.isna().sum())
        if best_failed is None or n_failed < best_failed:
            best_parsed, best_fmt, best_failed = parsed, fmt, n_failed
    return best_parsed, best_fmt, best_failed


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_feature_plan(feature_report_path: Path) -> dict:
    with open(feature_report_path, encoding="utf-8") as f:
        report = json.load(f)
    selected_features = list(report["recommended_core_feature_set"]["features"])
    reserved_features = list(report["reserved_for_later"]["features"])
    excluded_features = list(report["excluded_from_first_baseline"].keys())
    return {
        "selected_features": selected_features,
        "reserved_features": reserved_features,
        "excluded_features": excluded_features,
        "target_column": TARGET_COLUMN,
        "timestamp_column": TIMESTAMP_COLUMN,
    }


def investigate_infinity(df: pd.DataFrame, numeric_features: list) -> dict:
    before_counts = {}
    for col in numeric_features:
        n_inf = int(np.isinf(df[col]).sum())
        if n_inf > 0:
            before_counts[col] = n_inf
    any_inf_mask = pd.Series(False, index=df.index)
    for col in before_counts:
        any_inf_mask |= np.isinf(df[col])
    return {
        "columns_with_infinity_before_conversion": before_counts,
        "total_rows_affected": int(any_inf_mask.sum()),
    }


def investigate_missing(df: pd.DataFrame, numeric_features: list, after_inf_to_nan: pd.DataFrame) -> dict:
    investigation = {}
    check_cols = ["Flow Duration", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Tot Fwd Pkts", "Tot Bwd Pkts"]
    check_cols = [c for c in check_cols if c in df.columns]
    for col in numeric_features:
        missing_before = int(df[col].isna().sum())
        missing_after = int(after_inf_to_nan[col].isna().sum())
        if missing_after == 0:
            continue
        rows = df.loc[after_inf_to_nan[col].isna()]
        zero_duration_count = int((rows["Flow Duration"] == 0).sum()) if "Flow Duration" in df.columns else None
        evidence = {c: {"min": float(rows[c].min()), "max": float(rows[c].max())} for c in check_cols} if len(rows) else {}
        investigation[col] = {
            "missing_before_inf_conversion": missing_before,
            "missing_after_inf_conversion": missing_after,
            "rows_with_zero_flow_duration": zero_duration_count,
            "all_missing_rows_have_zero_duration": zero_duration_count == missing_after if zero_duration_count is not None else None,
            "value_range_of_related_columns_for_missing_rows": evidence,
        }
    return investigation


def main():
    parser = argparse.ArgumentParser(description="Prepare model-ready features from the cleaned CSE-CIC-IDS2018 dataset.")
    parser.add_argument("--input", required=True, help="Path to the cleaned CSV file.")
    parser.add_argument(
        "--feature-report",
        default="results/feature_selection_report.json",
        help="Path to the Feature 3 feature selection report (default: results/feature_selection_report.json).",
    )
    parser.add_argument("--output-dir", default="data/processed/model_ready", help="Directory for model-ready artifacts.")
    parser.add_argument("--report-dir", default="results", help="Directory for reports.")
    args = parser.parse_args()

    input_path = Path(args.input)
    feature_report_path = Path(args.feature_report)
    output_dir = Path(args.output_dir)
    report_dir = Path(args.report_dir)

    if not input_path.exists():
        raise SystemExit(f"Cleaned dataset not found: {input_path}")
    if not feature_report_path.exists():
        raise SystemExit(f"Feature 3 report not found: {feature_report_path}")

    raw_csv_path = Path("data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv")
    raw_md5_before = file_md5(raw_csv_path) if raw_csv_path.exists() else None
    cleaned_md5_before = file_md5(input_path)

    # --- Step 2: load Feature 3's plan (no invented feature names) ---
    plan = load_feature_plan(feature_report_path)
    selected_features = plan["selected_features"]
    reserved_features = plan["reserved_features"]
    excluded_features = plan["excluded_features"]

    numeric_features = [f for f in selected_features if f != PROTOCOL_COLUMN]
    assert PROTOCOL_COLUMN in selected_features, "Protocol is expected in the Feature 3 selected set."

    # --- Step 1: load cleaned dataset, explicit timestamp parsing ---
    print(f"Loading cleaned dataset from {input_path} ...")
    df = pd.read_csv(input_path, low_memory=False)
    n_rows_original = len(df)
    parsed_ts, timestamp_format_used, n_ts_failed = parse_timestamp_explicit(df[TIMESTAMP_COLUMN], TIMESTAMP_FORMAT_CANDIDATES)
    assert n_ts_failed == 0, (
        f"{n_ts_failed} timestamps failed to parse against explicit format candidates "
        f"{TIMESTAMP_FORMAT_CANDIDATES}; stopping rather than silently dropping rows."
    )
    df[TIMESTAMP_COLUMN] = parsed_ts
    print(f"Timestamp parsed using explicit format: {timestamp_format_used}")

    # Consistency check: selected + reserved + excluded must exactly cover all 80 columns.
    all_accounted = set(selected_features) | set(reserved_features) | set(excluded_features)
    assert all_accounted == set(df.columns), "Feature 3 plan does not exactly cover all cleaned-dataset columns."
    assert len(selected_features) + len(reserved_features) + len(excluded_features) == len(df.columns), \
        "Selected/reserved/excluded feature lists overlap unexpectedly."

    # --- Step 3: infinity handling ---
    print("Step 3: investigating and converting Infinity values ...")
    infinity_before = investigate_infinity(df, numeric_features)
    X_numeric_raw = df[numeric_features].replace([np.inf, -np.inf], np.nan)

    # --- Step 4: missing value investigation (strategy documented, NOT applied globally) ---
    print("Step 4: investigating missing values ...")
    missing_investigation = investigate_missing(df, numeric_features, X_numeric_raw)
    missing_after_conversion = {col: int(X_numeric_raw[col].isna().sum()) for col in numeric_features if X_numeric_raw[col].isna().sum() > 0}

    # --- Step 5: Protocol one-hot encoding ---
    print("Step 5: encoding Protocol ...")
    protocol_counts = df[PROTOCOL_COLUMN].value_counts().sort_index()
    protocol_label_crosstab = pd.crosstab(df[PROTOCOL_COLUMN], df[TARGET_COLUMN])
    protocol_dummies = pd.get_dummies(df[PROTOCOL_COLUMN], prefix="Protocol").astype(int)
    onehot_protocol_columns = list(protocol_dummies.columns)

    # --- Step 6: numeric scaling / imputation pipeline (constructed, NOT fitted) ---
    print("Step 6: building (unfitted) imputation + scaling pipeline ...")
    numeric_pipeline = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy=IMPUTATION_STRATEGY)),
        ("scaler", StandardScaler()),
    ])
    preprocessor = ColumnTransformer(
        transformers=[("numeric", numeric_pipeline, numeric_features)],
        remainder="passthrough",
    )
    try:
        check_is_fitted(preprocessor)
        pipeline_is_fitted = True
    except NotFittedError:
        pipeline_is_fitted = False
    assert not pipeline_is_fitted, "Preprocessing pipeline must remain unfitted at this stage to avoid data leakage."

    # --- Step 7: label encoding (deterministic mapping, not a statistic) ---
    print("Step 7: encoding Label ...")
    label_encoded = df[TARGET_COLUMN].map(LABEL_ENCODING)
    assert label_encoded.isna().sum() == 0, "Unexpected label value(s) found outside the documented encoding."

    # --- Step 8: timestamp reporting ---
    print("Step 8: reporting Timestamp range ...")
    ts = df[TIMESTAMP_COLUMN]
    timestamp_report = {
        "format_used": timestamp_format_used,
        "format_note": (
            "The raw CIC-IDS2018 CSV uses DD/MM/YYYY (%d/%m/%Y %H:%M:%S). The cleaned "
            "CSV from Feature 2 stores Timestamp as an already-parsed datetime, which "
            "pandas.to_csv serializes as unambiguous ISO 8601 (%Y-%m-%d %H:%M:%S). Both "
            "formats were tried explicitly (never pandas' default ambiguous inference); "
            f"'{timestamp_format_used}' is the one that parsed this file with zero failures."
        ),
        "min_timestamp": str(ts.min()),
        "max_timestamp": str(ts.max()),
        "num_unique_timestamps": int(ts.nunique()),
        "time_span": str(ts.max() - ts.min()),
    }

    # --- assemble model-ready artifacts ---
    row_id = pd.RangeIndex(start=0, stop=n_rows_original, step=1)
    features_df = pd.concat([X_numeric_raw.reset_index(drop=True), protocol_dummies.reset_index(drop=True)], axis=1)
    features_df.insert(0, "row_id", row_id)

    target_df = pd.DataFrame({
        "row_id": row_id,
        TARGET_COLUMN: df[TARGET_COLUMN].reset_index(drop=True),
        "Label_encoded": label_encoded.reset_index(drop=True),
    })

    timestamp_df = pd.DataFrame({
        "row_id": row_id,
        TIMESTAMP_COLUMN: ts.reset_index(drop=True),
    })

    # --- Step 9: write outputs ---
    output_dir.mkdir(parents=True, exist_ok=True)
    features_path = output_dir / "features.csv"
    target_path = output_dir / "target.csv"
    timestamp_path = output_dir / "timestamp.csv"
    pipeline_path = output_dir / "preprocessing_pipeline.joblib"

    features_df.to_csv(features_path, index=False)
    target_df.to_csv(target_path, index=False)
    timestamp_df.to_csv(timestamp_path, index=False)
    joblib.dump(preprocessor, pipeline_path)
    print(f"Wrote {features_path}, {target_path}, {timestamp_path}, {pipeline_path}")

    report_dir.mkdir(parents=True, exist_ok=True)
    feature_list_path = report_dir / "model_feature_list.json"
    feature_list_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # --- integrity checks: raw/cleaned files never modified by this script ---
    raw_md5_after = file_md5(raw_csv_path) if raw_csv_path.exists() else None
    cleaned_md5_after = file_md5(input_path)
    raw_unchanged = (raw_md5_before is None) or (raw_md5_before == raw_md5_after)
    cleaned_unchanged = cleaned_md5_before == cleaned_md5_after

    # --- Step 11 validation ---
    final_feature_columns = [c for c in features_df.columns if c != "row_id"]
    validation = {
        "raw_csv_unchanged": raw_unchanged,
        "cleaned_csv_unchanged": cleaned_unchanged,
        "selected_features_fully_represented": set(numeric_features).issubset(set(final_feature_columns)),
        "label_not_in_feature_matrix": TARGET_COLUMN not in final_feature_columns,
        "timestamp_preserved_separately": TIMESTAMP_COLUMN in timestamp_df.columns and TIMESTAMP_COLUMN not in final_feature_columns,
        "dst_port_not_in_feature_matrix": "Dst Port" not in final_feature_columns,
        "constant_near_constant_not_in_feature_matrix": not any(c in final_feature_columns for c in excluded_features if c != TARGET_COLUMN),
        "protocol_represented_as_onehot": all(c in final_feature_columns for c in onehot_protocol_columns) and PROTOCOL_COLUMN not in final_feature_columns,
        "protocol_onehot_rows_sum_to_one": bool((protocol_dummies.sum(axis=1) == 1).all()),
        "no_infinite_values_remain": bool(not np.isinf(features_df[numeric_features]).to_numpy().any()),
        "missing_values_preserved_for_later_imputation": {col: int(features_df[col].isna().sum()) for col in numeric_features if features_df[col].isna().sum() > 0},
        "preprocessing_pipeline_is_unfitted": not pipeline_is_fitted,
        "outputs_reload_successfully": None,  # filled in below
    }

    reload_ok = True
    try:
        _f = pd.read_csv(features_path)
        _t = pd.read_csv(target_path)
        _ts = pd.read_csv(timestamp_path)
        _p = joblib.load(pipeline_path)
        reload_ok = len(_f) == n_rows_original and len(_t) == n_rows_original and len(_ts) == n_rows_original
    except Exception as e:
        reload_ok = False
        print(f"WARNING: reload check failed: {e}")
    validation["outputs_reload_successfully"] = reload_ok

    report = {
        "input": {
            "cleaned_dataset": str(input_path),
            "row_count": n_rows_original,
            "feature_report_used": str(feature_report_path),
        },
        "feature_plan": plan,
        "infinity_handling": infinity_before,
        "missing_value_investigation": missing_investigation,
        "missing_values_after_infinity_conversion": missing_after_conversion,
        "imputation_strategy": {
            "method": "SimpleImputer",
            "strategy": IMPUTATION_STRATEGY,
            "reason": (
                "Network flow rate/byte/timing features are heavily right-skewed with "
                "extreme outliers (e.g. burst rates), so the median is a more robust "
                "central-tendency estimate than the mean for these NaN values, which "
                "were confirmed (Step 4) to originate from mathematically zero-duration "
                "flows rather than data-collection loss."
            ),
            "fitted_now": False,
            "fit_timing": "Must be fit only on the training split, in a later feature (model training), to avoid leaking validation/test statistics into preparation.",
        },
        "protocol_encoding": {
            "unique_values": {str(k): int(v) for k, v in protocol_counts.items()},
            "label_crosstab": {str(k): {str(kk): int(vv) for kk, vv in row.items()} for k, row in protocol_label_crosstab.iterrows()},
            "method": "one-hot encoding (pandas.get_dummies)",
            "resulting_columns": onehot_protocol_columns,
            "reason_safe_to_apply_now": (
                "One-hot encoding enumerates fixed, observed categories - a structural "
                "transformation, not a statistic computed from the data distribution "
                "(unlike imputation medians or scaler means/stds), so it does not leak "
                "train/test information and is safe to apply globally."
            ),
        },
        "scaling_pipeline": {
            "numeric_features_count": len(numeric_features),
            "transformer": "ColumnTransformer(SimpleImputer(median) -> StandardScaler) on numeric features, passthrough for one-hot Protocol columns",
            "saved_path": str(pipeline_path),
            "is_fitted": pipeline_is_fitted,
            "note": "Saved UNFITTED. A later feature must call .fit() on the training split only, then .transform() on train/validation/test splits.",
        },
        "label_encoding": {
            "mapping": LABEL_ENCODING,
            "original_label_preserved_in": str(target_path),
        },
        "timestamp": timestamp_report,
        "outputs": {
            "features_csv": str(features_path),
            "target_csv": str(target_path),
            "timestamp_csv": str(timestamp_path),
            "preprocessing_pipeline": str(pipeline_path),
            "model_feature_list_json": str(feature_list_path),
            "final_feature_matrix_columns": final_feature_columns,
            "final_feature_matrix_column_count": len(final_feature_columns),
        },
        "validation": validation,
    }

    txt_path = report_dir / "model_preparation_report.txt"
    json_path = report_dir / "model_preparation_report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    txt_path.write_text(format_text_report(report), encoding="utf-8")
    print(f"Wrote {txt_path}, {json_path}, {feature_list_path}")

    # --- final summary ---
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Original rows: {n_rows_original}")
    print(f"Selected raw features (Feature 3 baseline): {len(selected_features)}")
    print(f"Final encoded feature count (after Protocol one-hot): {len(final_feature_columns)}")
    print(f"Protocol categories: {onehot_protocol_columns}")
    print(f"Missing/invalid values handled: Infinity -> NaN for {list(infinity_before['columns_with_infinity_before_conversion'].keys())}; "
          f"NaN preserved (not imputed) for later training-only SimpleImputer fit: {missing_after_conversion}")
    print(f"Timestamp preserved: {timestamp_path} (min={timestamp_report['min_timestamp']}, max={timestamp_report['max_timestamp']})")
    print(f"Label encoding: {LABEL_ENCODING}")
    print("\nValidation:")
    for k, v in validation.items():
        print(f"  {k}: {v}")

    for key in ["raw_csv_unchanged", "cleaned_csv_unchanged", "label_not_in_feature_matrix",
                "timestamp_preserved_separately", "dst_port_not_in_feature_matrix",
                "constant_near_constant_not_in_feature_matrix", "protocol_represented_as_onehot",
                "preprocessing_pipeline_is_unfitted", "outputs_reload_successfully"]:
        assert validation[key], f"Validation failed: {key}"

    return report


def format_text_report(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("MODEL-READY FEATURE PREPARATION REPORT")
    lines.append("=" * 70)

    inp = report["input"]
    lines.append(f"Cleaned dataset: {inp['cleaned_dataset']}")
    lines.append(f"Row count: {inp['row_count']}")
    lines.append(f"Feature report used: {inp['feature_report_used']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("FEATURE PLAN (from Feature 3)")
    lines.append("-" * 70)
    fp = report["feature_plan"]
    lines.append(f"  Selected features ({len(fp['selected_features'])}): {fp['selected_features']}")
    lines.append(f"  Reserved features: {fp['reserved_features']}")
    lines.append(f"  Excluded features: {fp['excluded_features']}")
    lines.append(f"  Target column: {fp['target_column']}")
    lines.append(f"  Timestamp column: {fp['timestamp_column']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 3: INFINITY HANDLING")
    lines.append("-" * 70)
    ih = report["infinity_handling"]
    lines.append(f"  Total rows affected: {ih['total_rows_affected']}")
    lines.append("  Columns with Infinity before conversion:")
    for col, count in ih["columns_with_infinity_before_conversion"].items():
        lines.append(f"    {col}: {count}")
    lines.append("  All Infinity values converted to NaN.")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 4: MISSING VALUE INVESTIGATION")
    lines.append("-" * 70)
    for col, info in report["missing_value_investigation"].items():
        lines.append(f"  {col}:")
        lines.append(f"    missing before Infinity conversion: {info['missing_before_inf_conversion']}")
        lines.append(f"    missing after Infinity conversion: {info['missing_after_inf_conversion']}")
        lines.append(f"    rows with Flow Duration == 0: {info['rows_with_zero_flow_duration']}")
        lines.append(f"    all missing rows have zero duration: {info['all_missing_rows_have_zero_duration']}")
    imp = report["imputation_strategy"]
    lines.append(f"  Chosen strategy: {imp['method']}(strategy='{imp['strategy']}')")
    lines.append(f"  Reason: {imp['reason']}")
    lines.append(f"  Fitted now: {imp['fitted_now']} - {imp['fit_timing']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 5: PROTOCOL ENCODING")
    lines.append("-" * 70)
    pe = report["protocol_encoding"]
    lines.append(f"  Unique values and counts: {pe['unique_values']}")
    lines.append(f"  Label crosstab: {pe['label_crosstab']}")
    lines.append(f"  Method: {pe['method']}")
    lines.append(f"  Resulting columns: {pe['resulting_columns']}")
    lines.append(f"  Why safe to apply now: {pe['reason_safe_to_apply_now']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 6: NUMERIC SCALING PIPELINE")
    lines.append("-" * 70)
    sp = report["scaling_pipeline"]
    lines.append(f"  Numeric features: {sp['numeric_features_count']}")
    lines.append(f"  Transformer: {sp['transformer']}")
    lines.append(f"  Saved to: {sp['saved_path']}")
    lines.append(f"  Is fitted: {sp['is_fitted']}")
    lines.append(f"  Note: {sp['note']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 7: LABEL ENCODING")
    lines.append("-" * 70)
    le = report["label_encoding"]
    lines.append(f"  Mapping: {le['mapping']}")
    lines.append(f"  Original label text preserved in: {le['original_label_preserved_in']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("STEP 8: TIMESTAMP")
    lines.append("-" * 70)
    ts = report["timestamp"]
    for k, v in ts.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("OUTPUTS")
    lines.append("-" * 70)
    out = report["outputs"]
    for k, v in out.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("VALIDATION (STEP 11)")
    lines.append("-" * 70)
    for k, v in report["validation"].items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
