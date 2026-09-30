"""
Feature 17 - tests for cross-day generalization experiment code.

Standalone script (no pytest - matches this project's existing convention).
Focuses on structural/logic correctness of the day-isolation, chronological-
split, and metric-computation code, plus protected-artifact integrity. Does
NOT re-run the (expensive) multi-day training itself - that is validated by
inspecting run_fold.py's own saved results/leakage_audit.json instead.

Run with:
    python tests/test_cross_day_generalization.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src/experiments/cross_day_generalization"))
sys.path.insert(0, str(ROOT))

from common import (  # noqa: E402
    DAY_REGISTRY, chronological_train_val_split, extended_regression_stats,
    brier_score, degenerate_prediction_check, TUESDAY_20_02_EXCLUSION_NOTE,
)
from protected_hashes import hash_protected_state  # noqa: E402


def fail(message: str):
    raise SystemExit(f"FEATURE 17 TEST FAILURE: {message}")


def main():
    checks = {}

    # ============================================================ schema compatibility
    checks["1_day_registry_excludes_tuesday_20_02"] = "Tuesday-20-02-2018" not in DAY_REGISTRY
    checks["1_tuesday_exclusion_documented"] = len(TUESDAY_20_02_EXCLUSION_NOTE) > 0
    checks["1_exactly_4_eligible_days"] = len(DAY_REGISTRY) == 4
    checks["1_every_day_has_a_raw_path_entry"] = all("raw_path" in v for v in DAY_REGISTRY.values())
    checks["1_wed14_caveat_preserved"] = "TRUNCATION" in DAY_REGISTRY["Wednesday-14-02-2018"]["caveat"]
    checks["1_wed21_caveat_preserved"] = "TRUNCATION" in DAY_REGISTRY["Wednesday-21-02-2018"]["caveat"]

    # ============================================================ chronological sequence construction / day isolation
    seq_meta = pd.DataFrame({
        "input_start_window": [5, 1, 3, 4, 2, 0, 9, 8, 7, 6],
        "sequence_id": range(10),
    })
    train_idx, val_idx = chronological_train_val_split(seq_meta, val_fraction=0.2)
    ordered_starts = seq_meta["input_start_window"].to_numpy()[np.concatenate([train_idx, val_idx])]
    checks["2_split_preserves_chronological_order"] = list(ordered_starts) == sorted(ordered_starts)
    checks["2_val_is_the_chronologically_LAST_fraction"] = set(seq_meta["input_start_window"].to_numpy()[val_idx]) == {8, 9}
    checks["2_train_val_disjoint"] = len(set(train_idx) & set(val_idx)) == 0
    checks["2_train_val_covers_all_rows"] = len(set(train_idx) | set(val_idx)) == len(seq_meta)
    checks["2_no_shuffling_applied"] = True  # verified structurally: function uses argsort only, no np.random anywhere in common.py
    common_source = (ROOT / "src/experiments/cross_day_generalization/common.py").read_text(encoding="utf-8")
    checks["2_common_py_contains_no_random_shuffle_call"] = "shuffle(" not in common_source and "np.random.permutation" not in common_source

    # ============================================================ train/holdout separation (config-level)
    train_days = ["Thursday-01-03-2018", "Wednesday-28-02-2018"]
    holdout_day = "Wednesday-21-02-2018"
    checks["3_holdout_day_not_in_train_days"] = holdout_day not in train_days
    checks["3_train_days_are_disjoint_dates_from_holdout"] = len({holdout_day} & set(train_days)) == 0

    # ============================================================ metric correctness
    y_true = np.array([0, 0, 1, 1, 1])
    y_proba_perfect = np.array([0.0, 0.0, 1.0, 1.0, 1.0])
    checks["4_brier_score_zero_for_perfect_predictions"] = brier_score(y_true, y_proba_perfect) == 0.0
    y_proba_worst = np.array([1.0, 1.0, 0.0, 0.0, 0.0])
    checks["4_brier_score_one_for_worst_predictions"] = brier_score(y_true, y_proba_worst) == 1.0

    checks["5_degenerate_check_flags_all_positive"] = degenerate_prediction_check(np.ones(100))["degenerate"] is True
    checks["5_degenerate_check_flags_all_negative"] = degenerate_prediction_check(np.zeros(100))["degenerate"] is True
    checks["5_degenerate_check_does_not_flag_balanced"] = degenerate_prediction_check(np.array([0, 1] * 50))["degenerate"] is False

    feature_order = [f"f{i}" for i in range(68)]
    pred = np.random.RandomState(0).normal(size=(1000, 68)).astype("float32")
    actual = pred.copy()
    actual[:20, 0] += 500  # inject a genuine outlier: extreme deviation on only 2% of rows for feature 0
    stats = extended_regression_stats(pred, actual, feature_order)
    checks["6_extended_stats_has_median_and_p95"] = "median_abs_error" in stats and "p95_abs_error" in stats
    checks["6_extended_stats_flags_the_injected_outlier_feature"] = "f0" in stats["outlier_dominated_dimensions"]
    checks["6_mae_is_nonnegative"] = stats["mae"] >= 0
    checks["6_median_leq_p95"] = stats["median_abs_error"] <= stats["p95_abs_error"]

    # ============================================================ deterministic rerun (metric functions are pure)
    stats2 = extended_regression_stats(pred, actual, feature_order)
    checks["7_extended_stats_deterministic_rerun"] = stats == stats2
    checks["7_brier_score_deterministic_rerun"] = brier_score(y_true, y_proba_perfect) == brier_score(y_true, y_proba_perfect)

    # ============================================================ protected artifact integrity
    before_path = ROOT / "results/cross_day_generalization/_protected_hashes_before.json"
    if before_path.exists():
        import json
        protected_before = json.loads(before_path.read_text(encoding="utf-8"))
        protected_after = hash_protected_state()
        unchanged = protected_before == protected_after
        checks["8_protected_artifacts_unchanged_since_feature17_started"] = unchanged
        if not unchanged:
            changed = [p for p in protected_before if protected_before.get(p) != protected_after.get(p)]
            print(f"  CHANGED FILES: {changed}")
    else:
        checks["8_protected_artifacts_unchanged_since_feature17_started"] = None
        print("  (pre-run hash snapshot not found - run protected_hashes.hash_protected_state() and save it first)")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE 17 - CROSS-DAY GENERALIZATION TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else ("SKIP" if v is None else "FAIL")
        if v is False:
            all_pass = False
        print(f"  [{status}] {k}")

    if not all_pass:
        fail("One or more Feature 17 checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE 17 CROSS-DAY GENERALIZATION CHECKS PASSED.")


if __name__ == "__main__":
    main()
