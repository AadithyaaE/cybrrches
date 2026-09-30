"""
Feature L1 - Parity and safety tests for src/data/prepare_unlabeled_state.py.

Standalone script (no pytest dependency - this project has no existing
test framework installed, so this follows the project's existing
validation-script convention: plain assertions + a PASS/FAIL summary,
non-zero exit on failure).

Run with:
    python3 tests/test_unlabeled_state_pipeline.py

What this proves, using the known-good labeled Thursday-01-03-2018
dataset already used throughout Features 1-16:
  1. The LABELED path (prepare_external_dataset.py, completely unmodified)
     and the new UNLABELED path (prepare_unlabeled_state.py) produce
     IDENTICAL window IDs, timestamps, segment IDs, observation counts,
     raw feature values, scaled feature values, sequence IDs, sequence
     window pointers, sequence timestamps, and X_sequences/
     next_window_features arrays.
  2. The ONLY differences are the label-derived metadata columns/fields,
     which are explicitly absent (windows) or None (sequence metadata) in
     the unlabeled path - never fabricated.
  3. No Label column is required, read, or required to exist anywhere in
     the unlabeled path.
  4. No .fit()/.fit_transform() call exists in the new module (grep-verified).
  5. The frozen preprocessing pipeline is used via .transform() only.
  6. No Feature 1-16 artifact (results/, data/processed/splits/,
     data/processed/Thursday-01-03-2018_..._clean.csv) is modified.
  7. The unlabeled path is deterministic across two independent runs.
"""

import ast
import hashlib
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "data"))

from prepare_external_dataset import (  # noqa: E402
    load_reference_artifacts, build_model_ready_table, build_states, build_windows, build_sequences,
)
from prepare_unlabeled_state import (  # noqa: E402
    build_model_ready_table_unlabeled, build_states_unlabeled, build_windows_unlabeled,
    build_sequences_unlabeled, transform_unlabeled_windows,
)

CLEAN_CSV = ROOT / "data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv"
NEW_MODULE_PATH = ROOT / "src/data/prepare_unlabeled_state.py"

PROTECTED_DIRS = [
    ROOT / "data/processed/splits",
    ROOT / "results",
]
PROTECTED_FILES = [CLEAN_CSV]


def fail(message: str):
    raise SystemExit(f"FEATURE L1 TEST FAILURE: {message}")


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_protected_state() -> dict:
    paths = list(PROTECTED_FILES)
    for d in PROTECTED_DIRS:
        if d.exists():
            paths.extend(p for p in d.rglob("*") if p.is_file())
    return {str(p): file_md5(p) for p in paths}


def main():
    if not CLEAN_CSV.exists():
        fail(f"Known-good labeled dataset not found: {CLEAN_CSV}")

    print(f"Loading known-good labeled dataset: {CLEAN_CSV.name} ...")
    clean_df = pd.read_csv(CLEAN_CSV)
    clean_df["Timestamp"] = pd.to_datetime(clean_df["Timestamp"])
    print(f"  {len(clean_df)} rows, {len(clean_df.columns)} columns, Label present: {'Label' in clean_df.columns}")

    print("Hashing protected Feature 1-16 artifacts (pre-run) ...")
    protected_before = hash_protected_state()

    feature_order, numeric_features, onehot_protocol_columns, fitted_pipeline = load_reference_artifacts()
    print(f"Loaded feature_order ({len(feature_order)} features), fitted preprocessing pipeline.")

    # ---------------- LABELED PATH (existing prepare_external_dataset.py, completely unmodified) ----------------
    print("\nRunning LABELED path (prepare_external_dataset.py, unmodified functions) ...")
    model_ready_l, target_df_l, timestamp_df_l, _ = build_model_ready_table(clean_df, numeric_features, onehot_protocol_columns)
    states_l = build_states(model_ready_l, target_df_l, timestamp_df_l, feature_order)
    windows_l = build_windows(states_l, feature_order)
    X_l, next_l, seq_meta_l = build_sequences(windows_l, feature_order)
    windows_scaled_l = np.asarray(fitted_pipeline.transform(windows_l[feature_order]), dtype="float64")
    print(f"  {len(windows_l)} windows, {len(seq_meta_l)} sequences.")

    # ---------------- UNLABELED PATH (new, Feature L1) ----------------
    print("Running UNLABELED path (prepare_unlabeled_state.py, new functions) ...")
    clean_df_unlabeled = clean_df.drop(columns=["Label"])
    if "Label" in clean_df_unlabeled.columns:
        fail("Test setup error: Label column still present after drop().")

    model_ready_u, timestamp_df_u, prep_meta_u = build_model_ready_table_unlabeled(clean_df_unlabeled, numeric_features, onehot_protocol_columns)
    states_u = build_states_unlabeled(model_ready_u, timestamp_df_u, feature_order)
    windows_u = build_windows_unlabeled(states_u, feature_order)
    X_u, next_u, seq_meta_u = build_sequences_unlabeled(windows_u, feature_order)
    windows_scaled_u = transform_unlabeled_windows(windows_u, feature_order, fitted_pipeline)
    print(f"  {len(windows_u)} windows, {len(seq_meta_u)} sequences.")

    checks = {}

    # --- structural: no label required anywhere in the unlabeled path's input ---
    checks["unlabeled_input_has_no_label_column"] = "Label" not in clean_df_unlabeled.columns
    checks["prep_meta_reports_label_unavailable"] = prep_meta_u.get("label_available") is False

    # --- feature schema parity ---
    checks["feature_order_length_is_68"] = len(feature_order) == 68
    checks["feature_order_same_object_used_both_paths"] = True  # both paths loaded feature_order once, from the same call

    # --- window-level parity (IDs, timestamps, structure) ---
    checks["window_count_identical"] = len(windows_l) == len(windows_u)
    checks["window_ids_identical"] = list(windows_l["window_id"]) == list(windows_u["window_id"])
    checks["window_start_identical"] = list(windows_l["window_start"]) == list(windows_u["window_start"])
    checks["window_end_identical"] = list(windows_l["window_end"]) == list(windows_u["window_end"])
    checks["observation_count_identical"] = list(windows_l["observation_count"]) == list(windows_u["observation_count"])
    checks["segment_id_identical"] = list(windows_l["segment_id"]) == list(windows_u["segment_id"])

    # --- numeric state VALUES parity (the actual 68-dim feature content) ---
    raw_l = windows_l[feature_order].to_numpy(dtype="float64")
    raw_u = windows_u[feature_order].to_numpy(dtype="float64")
    max_abs_diff_raw = float(np.nanmax(np.abs(raw_l - raw_u))) if raw_l.size else 0.0
    checks["raw_window_feature_values_identical"] = bool(np.allclose(raw_l, raw_u, equal_nan=True, atol=0, rtol=0))
    checks["scaled_window_feature_values_identical"] = bool(np.allclose(windows_scaled_l, windows_scaled_u, equal_nan=True, atol=0, rtol=0))

    # --- sequence-level parity ---
    checks["sequence_count_identical"] = len(seq_meta_l) == len(seq_meta_u)
    checks["sequence_ids_identical"] = list(seq_meta_l["sequence_id"]) == list(seq_meta_u["sequence_id"])
    checks["sequence_input_start_window_identical"] = list(seq_meta_l["input_start_window"]) == list(seq_meta_u["input_start_window"])
    checks["sequence_input_end_window_identical"] = list(seq_meta_l["input_end_window"]) == list(seq_meta_u["input_end_window"])
    checks["sequence_target_window_identical"] = list(seq_meta_l["target_window"]) == list(seq_meta_u["target_window"])
    checks["sequence_timestamps_identical"] = (
        list(seq_meta_l["input_start_timestamp"]) == list(seq_meta_u["input_start_timestamp"])
        and list(seq_meta_l["input_end_timestamp"]) == list(seq_meta_u["input_end_timestamp"])
        and list(seq_meta_l["target_timestamp"]) == list(seq_meta_u["target_timestamp"])
    )
    checks["X_sequences_array_identical"] = bool(np.array_equal(X_l, X_u, equal_nan=True))
    checks["next_window_features_array_identical"] = bool(np.array_equal(next_l, next_u, equal_nan=True))
    checks["X_sequences_shape_is_(N,10,68)"] = X_u.shape[1:] == (10, 68)

    # --- documented expected differences: label-derived metadata absent/None, never fabricated ---
    label_derived_cols = ["label", "binary_target", "attack_ratio", "benign_count", "attack_count", "dominant_label"]
    checks["unlabeled_windows_have_no_label_derived_columns"] = not any(c in windows_u.columns for c in label_derived_cols)
    checks["unlabeled_seq_meta_target_label_is_none"] = bool(seq_meta_u["target_window_label"].isna().all()) if len(seq_meta_u) else True
    checks["unlabeled_seq_meta_target_binary_is_none"] = bool(seq_meta_u["target_window_binary_target"].isna().all()) if len(seq_meta_u) else True
    checks["labeled_seq_meta_target_label_is_populated"] = bool(seq_meta_l["target_window_label"].notna().all()) if len(seq_meta_l) else True

    # --- determinism: run the unlabeled path a second, independent time ---
    print("Re-running UNLABELED path a second time (determinism check) ...")
    model_ready_u2, timestamp_df_u2, _ = build_model_ready_table_unlabeled(clean_df_unlabeled, numeric_features, onehot_protocol_columns)
    states_u2 = build_states_unlabeled(model_ready_u2, timestamp_df_u2, feature_order)
    windows_u2 = build_windows_unlabeled(states_u2, feature_order)
    X_u2, next_u2, seq_meta_u2 = build_sequences_unlabeled(windows_u2, feature_order)
    windows_scaled_u2 = transform_unlabeled_windows(windows_u2, feature_order, fitted_pipeline)

    checks["determinism_raw_window_values_identical"] = bool(np.array_equal(raw_u, windows_u2[feature_order].to_numpy(dtype="float64"), equal_nan=True))
    checks["determinism_scaled_window_values_identical"] = bool(np.array_equal(windows_scaled_u, windows_scaled_u2, equal_nan=True))
    checks["determinism_X_sequences_identical"] = bool(np.array_equal(X_u, X_u2, equal_nan=True))
    checks["determinism_next_window_features_identical"] = bool(np.array_equal(next_u, next_u2, equal_nan=True))
    checks["determinism_seq_meta_identical"] = seq_meta_u.equals(seq_meta_u2)

    # --- leakage / safety checks ---
    # AST-based (not text/regex-based) so this cannot be fooled by docstring
    # mentions of ".fit(" (this module's own docstrings discuss .fit()/
    # .fit_transform() by name) and cannot miss a real call via formatting.
    new_module_source = NEW_MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(new_module_source, filename=str(NEW_MODULE_PATH))
    real_fit_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "fit_transform")
    ]
    checks["no_fit_call_in_new_module"] = len(real_fit_calls) == 0

    from sklearn.utils.validation import check_is_fitted
    try:
        check_is_fitted(fitted_pipeline)
        checks["preprocessing_pipeline_was_already_fitted_before_use"] = True
    except Exception:
        checks["preprocessing_pipeline_was_already_fitted_before_use"] = False

    print("Hashing protected Feature 1-16 artifacts (post-run) ...")
    protected_after = hash_protected_state()
    unchanged = protected_before == protected_after
    checks["feature_1_16_protected_artifacts_unchanged"] = unchanged
    if not unchanged:
        changed = [p for p in protected_before if protected_before.get(p) != protected_after.get(p)]
        print(f"  CHANGED FILES: {changed}")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE L1 - PARITY / SAFETY CHECK RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")

    print(f"\nWindow count: labeled={len(windows_l)} unlabeled={len(windows_u)}")
    print(f"Sequence count: labeled={len(seq_meta_l)} unlabeled={len(seq_meta_u)}")
    print(f"Max abs diff, raw window feature values (labeled vs unlabeled): {max_abs_diff_raw}")
    print(f"Labeled windows columns NOT present in unlabeled windows: {sorted(set(windows_l.columns) - set(windows_u.columns))}")
    print(f"Unlabeled windows columns NOT present in labeled windows: {sorted(set(windows_u.columns) - set(windows_l.columns))}")

    if not all_pass:
        fail("One or more parity/safety checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L1 PARITY AND SAFETY CHECKS PASSED.")


if __name__ == "__main__":
    main()
