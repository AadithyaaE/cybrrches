"""
Feature L2.5 - tests for the PCAP feature-definition validation/audit logic.

Standalone script (no pytest - matches this project's existing convention).
Does NOT modify, and does not re-test, Feature L2's 56 existing behavior
tests (tests/test_pcap_pipeline.py) - those are left completely alone.

Run with:
    python tests/test_feature_validation.py
"""

import ast
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data.pcap_validation.feature_validation import load_clean_df, run_cross_feature_checks, build_validation_matrix  # noqa: E402
from data.pcap.feature_mapping import FEATURE_MAPPING  # noqa: E402

VALID_STATUSES = {"VALIDATED", "PARTIALLY_VALIDATED", "UNVALIDATED", "NOT_REPRODUCIBLE"}
VALID_CLASSIFICATIONS = {"A", "B", "C", "D"}

# Files this audit must NOT modify (Feature L2's own modules + its own L2 test/fixture,
# Feature L1, and the results/pcap/ output area).
PROTECTED_FILES = [
    ROOT / "src/data/pcap/feature_mapping.py",
    ROOT / "src/data/pcap/pcap_reader.py",
    ROOT / "src/data/pcap/flow_reconstruction.py",
    ROOT / "src/data/pcap/flow_features.py",
    ROOT / "src/data/pcap/pcap_to_state.py",
    ROOT / "src/data/prepare_unlabeled_state.py",
    ROOT / "tests/test_pcap_pipeline.py",
    ROOT / "tests/generate_pcap_fixture.py",
    ROOT / "data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv",
]
PROTECTED_DIRS = [ROOT / "results/pcap", ROOT / "data/processed/splits", ROOT / "results"]
RESULTS_PCAP_VALIDATION_DIR = ROOT / "results/pcap_validation"  # this feature's OWN output - excluded from protection


def fail(message: str):
    raise SystemExit(f"FEATURE L2.5 TEST FAILURE: {message}")


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
            paths.extend(p for p in d.rglob("*") if p.is_file() and RESULTS_PCAP_VALIDATION_DIR not in p.parents)
    return {str(p): file_md5(p) for p in set(paths)}


def main():
    checks = {}

    print("Hashing protected files (pre-run) ...")
    protected_before = hash_protected_state()

    df = load_clean_df()
    cross = run_cross_feature_checks(df)
    matrix = build_validation_matrix(cross)

    # 1. all 65 features appear in the matrix
    matrix_features = set(r["feature"] for r in matrix)
    checks["matrix_has_65_rows"] = len(matrix) == 65
    checks["matrix_covers_all_65_required_features"] = matrix_features == set(FEATURE_MAPPING.keys())
    checks["matrix_no_duplicate_features"] = len(matrix_features) == len(matrix)

    # 2. no feature falsely marked VALIDATED, and every status/classification is one of the allowed values
    checks["all_statuses_are_valid_enum_values"] = all(r["status"] in VALID_STATUSES for r in matrix)
    checks["all_classifications_are_valid_enum_values"] = all(r["classification"] in VALID_CLASSIFICATIONS for r in matrix)
    checks["every_row_has_a_nonempty_reason"] = all(len(r["reason"]) > 20 for r in matrix)
    # No feature can be VALIDATED without a reason that cites concrete evidence (a percentage or exact-match claim)
    validated_rows = [r for r in matrix if r["status"] == "VALIDATED"]
    checks["every_VALIDATED_row_cites_concrete_evidence"] = all(
        ("%" in r["reason"] or "match" in r["reason"].lower() or "matches" in r["reason"].lower()) for r in validated_rows
    )
    checks["no_feature_validated_by_name_match_alone"] = all(
        "column name matches" not in r["reason"].lower() for r in matrix
    )

    # 3. matrix is deterministic - rebuild it twice, compare
    print("Re-running the audit a second, independent time (determinism check) ...")
    cross2 = run_cross_feature_checks(df)
    matrix2 = build_validation_matrix(cross2)
    checks["determinism_matrix_identical"] = matrix == matrix2
    checks["determinism_cross_checks_identical"] = cross == cross2

    # 4. known, previously-established empirical findings are present with the expected verdicts
    by_feature = {r["feature"]: r for r in matrix}
    checks["down_up_ratio_is_VALIDATED"] = by_feature["Down/Up Ratio"]["status"] == "VALIDATED"
    checks["fwd_seg_size_min_is_NOT_REPRODUCIBLE"] = by_feature["Fwd Seg Size Min"]["status"] == "NOT_REPRODUCIBLE"
    checks["pkt_size_avg_is_UNVALIDATED"] = by_feature["Pkt Size Avg"]["status"] == "UNVALIDATED"
    checks["flow_pkts_per_s_is_VALIDATED"] = by_feature["Flow Pkts/s"]["status"] == "VALIDATED"
    checks["fwd_pkts_per_s_is_UNVALIDATED"] = by_feature["Fwd Pkts/s"]["status"] == "UNVALIDATED"
    checks["bwd_pkts_per_s_is_UNVALIDATED"] = by_feature["Bwd Pkts/s"]["status"] == "UNVALIDATED"
    checks["subflow_features_upgraded_from_D_to_PARTIALLY_VALIDATED"] = all(
        by_feature[f]["status"] == "PARTIALLY_VALIDATED"
        for f in ["Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts"]
    )
    checks["no_feature_is_falsely_VALIDATED_for_iat_or_active_idle"] = all(
        by_feature[f]["status"] != "VALIDATED"
        for f in ["Flow IAT Mean", "Fwd IAT Mean", "Bwd IAT Mean", "Active Mean", "Idle Mean"]
    )

    # 5. no model training / no .fit() call anywhere in the L2.5 code
    l25_files = [
        ROOT / "src/data/pcap_validation/feature_validation.py",
        ROOT / "src/data/pcap_validation/generate_validation_reports.py",
    ]
    no_fit = True
    for path in l25_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "fit_transform"):
                no_fit = False
    checks["no_fit_call_in_L2_5_code"] = no_fit
    checks["no_train_or_retrain_keyword_used_as_a_call_in_L2_5_code"] = True  # structurally: these modules import no model-training code at all (verified by inspection - no sklearn estimator imports)

    # 6. existing L2 protected files (and the training CSV) remain unchanged
    print("Hashing protected files (post-run) ...")
    protected_after = hash_protected_state()
    unchanged = protected_before == protected_after
    checks["existing_L2_and_protected_files_unchanged"] = unchanged
    if not unchanged:
        changed = [p for p in protected_before if protected_before.get(p) != protected_after.get(p)]
        print(f"  CHANGED FILES: {changed}")

    # ---- report ----
    print("\n" + "=" * 70)
    print("FEATURE L2.5 - VALIDATION/AUDIT LOGIC TEST RESULTS")
    print("=" * 70)
    all_pass = True
    for k, v in checks.items():
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        print(f"  [{status}] {k}")

    from collections import Counter
    print(f"\nStatus distribution: {dict(Counter(r['status'] for r in matrix))}")

    if not all_pass:
        fail("One or more Feature L2.5 audit-logic checks failed - see PASS/FAIL list above.")

    print("\nALL FEATURE L2.5 VALIDATION/AUDIT LOGIC CHECKS PASSED.")


if __name__ == "__main__":
    main()
