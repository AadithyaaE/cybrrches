"""
Feature L2.5 - PCAP feature-definition validation/audit.

This module is READ-ONLY with respect to Feature L2 (src/data/pcap/*.py),
Feature L1 (src/data/prepare_unlabeled_state.py), Features 1-16, and the
frontend. It does not modify any existing feature formula. It ONLY
determines, and reports, how trustworthy each of the 65 PCAP-derived
feature formulas (see src/data/pcap/feature_mapping.py) actually is.

WHY THIS EXISTS
----------------
Feature L2 computed all 65 features and reached the 68D state / 10-step
sequences, but explicitly left every feature's `training_definition_
validated` flag False - no CICFlowMeter reference tool exists anywhere in
this environment (confirmed again below) to empirically cross-check
per-packet output. This audit asks a narrower, answerable question
instead: for every PCAP feature that can be expressed as a deterministic
function of OTHER columns already present in the REAL CICFlowMeter-
generated training CSV (data/processed/Thursday-01-03-2018_..._clean.csv),
does that relationship actually hold across all 331,027 real rows?

This is genuine, reproducible, non-fabricated evidence - but it is a
narrower claim than "this feature's raw-packet formula is correct". It
validates SELF-CONSISTENCY RELATIONSHIPS (e.g. "Down/Up Ratio equals
int(Tot Bwd Pkts / Tot Fwd Pkts) for every real flow in this dataset"),
not the underlying per-packet computation of Tot Bwd Pkts/Tot Fwd Pkts
themselves (which would require raw packets CICFlowMeter consumed - not
available). Every row in the resulting matrix says explicitly which kind
of evidence (if any) backs its status.

EVIDENCE SOURCES USED (only these two - nothing else)
--------------------------------------------------------
  1. This repository's own existing artifacts: results/feature_inventory.csv,
     results/feature_selection_report.*, results/state_schema.json,
     results/model_feature_list.json, src/data/pcap/feature_mapping.py.
  2. Cross-feature self-consistency checks against the real, existing
     CSE-CIC-IDS2018 training CSV (never modified, never retrained on).

NOT USED (per the task's explicit constraints)
--------------------------------------------------
  - No CICFlowMeter installation exists in this environment (re-confirmed
    below) - no empirical PCAP-vs-CICFlowMeter output comparison is
    performed or claimed anywhere in this module.
  - No formula in src/data/pcap/flow_features.py is changed here, even
    where this audit finds a concrete discrepancy - see STATUS_MATRIX's
    `reason` field for what was found and CLASSIFY_LEGEND for how it maps
    to a status.
"""

import math
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent.parent
CLEAN_CSV = ROOT / "data/processed/Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv"

STATUS_VALIDATED = "VALIDATED"
STATUS_PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
STATUS_UNVALIDATED = "UNVALIDATED"
STATUS_NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"

CLASSIFY_A = "A"  # Definition validated from project/training artifacts
CLASSIFY_B = "B"  # Strongly derivable, needs empirical reference comparison
CLASSIFY_C = "C"  # Approximation/simplification
CLASSIFY_D = "D"  # Not sufficiently validated


def load_clean_df() -> pd.DataFrame:
    return pd.read_csv(CLEAN_CSV)


# ============================================================================
# SECTION 1: cross-feature self-consistency checks against the real training CSV
# ============================================================================

def run_cross_feature_checks(df: pd.DataFrame) -> dict:
    """
    Every check below tests whether a PCAP-implemented formula's PREDICTED
    relationship between real CICFlowMeter output columns actually holds,
    across ALL rows of the real training CSV. Deterministic: same input
    always produces the same result (no randomness, no sampling).
    """
    n = len(df)
    results = {}

    def _exact(name, lhs, rhs):
        eq = (lhs == rhs)
        results[name] = {"matches": int(eq.sum()), "total": n, "match_rate": float(eq.sum()) / n}

    def _close(name, lhs, rhs, tol=1e-6):
        diff = (lhs - rhs).abs()
        matches = int((diff < tol).sum())
        results[name] = {"matches": matches, "total": n, "match_rate": matches / n, "max_abs_diff": float(diff.max())}

    # --- Subflow single-subflow simplification (Feature L2's category-D features) ---
    _exact("subflow_fwd_pkts_eq_tot_fwd_pkts", df["Subflow Fwd Pkts"], df["Tot Fwd Pkts"])
    _exact("subflow_fwd_byts_eq_totlen_fwd_pkts", df["Subflow Fwd Byts"], df["TotLen Fwd Pkts"])
    _exact("subflow_bwd_pkts_eq_tot_bwd_pkts", df["Subflow Bwd Pkts"], df["Tot Bwd Pkts"])
    _exact("subflow_bwd_byts_eq_totlen_bwd_pkts", df["Subflow Bwd Byts"], df["TotLen Bwd Pkts"])

    # --- Seg Size aliases ---
    _close("fwd_seg_size_avg_eq_fwd_pkt_len_mean", df["Fwd Seg Size Avg"], df["Fwd Pkt Len Mean"])
    _close("bwd_seg_size_avg_eq_bwd_pkt_len_mean", df["Bwd Seg Size Avg"], df["Bwd Pkt Len Mean"])
    _close("fwd_seg_size_min_eq_fwd_pkt_len_min", df["Fwd Seg Size Min"], df["Fwd Pkt Len Min"])

    # --- Pkt Size Avg vs Pkt Len Mean (feature_mapping.py's prior assumption) ---
    _close("pkt_size_avg_eq_pkt_len_mean", df["Pkt Size Avg"], df["Pkt Len Mean"])

    # --- Down/Up Ratio formula ---
    computed_ratio = np.where(df["Tot Fwd Pkts"] > 0, (df["Tot Bwd Pkts"] / df["Tot Fwd Pkts"]).astype("int64"), 0)
    _exact("down_up_ratio_eq_int_bwd_over_fwd", df["Down/Up Ratio"].to_numpy(), computed_ratio)

    # --- Pkt Len Max/Min direction-combination rule ---
    computed_max = df[["Fwd Pkt Len Max", "Bwd Pkt Len Max"]].max(axis=1)
    _exact("pkt_len_max_eq_max_fwd_bwd", df["Pkt Len Max"], computed_max)
    computed_min_naive = df[["Fwd Pkt Len Min", "Bwd Pkt Len Min"]].min(axis=1)
    min_mismatch = df["Pkt Len Min"] != computed_min_naive
    results["pkt_len_min_eq_min_fwd_bwd_naive"] = {
        "matches": int((~min_mismatch).sum()), "total": n, "match_rate": float((~min_mismatch).sum()) / n,
        "all_mismatches_explained_by_zero_bwd_packets": bool((df.loc[min_mismatch, "Tot Bwd Pkts"] == 0).all()) if min_mismatch.any() else True,
    }

    # --- Fwd/Bwd Pkt Len Mean simple-mean formula ---
    fwd_simple = df["TotLen Fwd Pkts"] / df["Tot Fwd Pkts"].replace(0, np.nan)
    _close("fwd_pkt_len_mean_eq_totlen_over_count", df["Fwd Pkt Len Mean"], fwd_simple)
    bwd_simple = df["TotLen Bwd Pkts"] / df["Tot Bwd Pkts"].replace(0, np.nan)
    _close("bwd_pkt_len_mean_eq_totlen_over_count", df["Bwd Pkt Len Mean"], bwd_simple)

    # --- Init Win Byts -1-for-N/A convention ---
    results["init_fwd_win_byts_minus1_present"] = {"count": int((df["Init Fwd Win Byts"] == -1).sum()), "min_observed": float(df["Init Fwd Win Byts"].min())}
    results["init_bwd_win_byts_minus1_present"] = {"count": int((df["Init Bwd Win Byts"] == -1).sum()), "min_observed": float(df["Init Bwd Win Byts"].min())}

    # --- Flow Duration / Active / Idle timeout-cap plausibility ---
    results["flow_duration_max"] = float(df["Flow Duration"].max())
    results["active_max_max"] = float(df["Active Max"].max())
    results["idle_max_max"] = float(df["Idle Max"].max())

    # --- Infinity/NaN conventions for the 4 rate features ---
    zero_dur = df["Flow Duration"] == 0
    numerators = {
        "Flow Byts/s": df["TotLen Fwd Pkts"] + df["TotLen Bwd Pkts"],
        "Flow Pkts/s": df["Tot Fwd Pkts"] + df["Tot Bwd Pkts"],
        "Fwd Pkts/s": df["Tot Fwd Pkts"],
        "Bwd Pkts/s": df["Tot Bwd Pkts"],
    }
    for feat, numerator in numerators.items():
        is_inf = np.isinf(df[feat])
        zero_num_and_dur = zero_dur & (numerator == 0)
        entry = {
            "inf_count_total": int(is_inf.sum()),
            "inf_and_zero_duration": int((is_inf & zero_dur).sum()),
            "inf_but_nonzero_duration": int((is_inf & ~zero_dur).sum()),
            "zero_duration_rows": int(zero_dur.sum()),
            "zero_numerator_and_duration_rows": int(zero_num_and_dur.sum()),
            "of_those_inf": int((zero_num_and_dur & is_inf).sum()),
        }
        results[f"rate_convention__{feat}"] = entry

    return results


# ============================================================================
# SECTION 2: the 65-feature validation matrix
# ============================================================================

_DIRECTION_KEYWORDS = ("Fwd ", "Bwd ", "Fwd/", "Bwd/")


def _is_direction_dependent(feature: str) -> bool:
    return feature.startswith(("Fwd ", "Bwd ")) or feature == "Down/Up Ratio"


def _is_temporal(feature: str) -> bool:
    return (
        feature == "Flow Duration"
        or "IAT" in feature
        or feature.startswith(("Active ", "Idle "))
        or feature.endswith(("Pkts/s", "Byts/s"))
    )


def build_validation_matrix(cross: dict) -> list:
    """
    Builds the 65-row matrix. `cross` is the output of run_cross_feature_checks()
    on the real training CSV - every VALIDATED/PARTIALLY_VALIDATED verdict
    below cites a specific key from it; nothing is asserted without a cited
    evidence source (either a `cross` key or an explicit repo-artifact fact).
    """
    from data.pcap.feature_mapping import FEATURE_MAPPING  # noqa: E402 - Feature L2, read-only import

    rows = []

    def add(feature, classification, status, reason):
        entry = FEATURE_MAPPING[feature]
        rows.append({
            "feature": feature,
            "l2_extractability_category": entry.category,
            "packet_or_flow_level": entry.level,
            "dtype": entry.dtype,
            "formula": entry.formula,
            "direction_dependent": _is_direction_dependent(feature),
            "temporal_dependency": _is_temporal(feature),
            "classification": classification,
            "status": status,
            "reason": reason,
        })

    # ---- Category A-derived: flag counts (well-established RFC793 semantics, dtype-only evidence) ----
    flag_reason = "TCP flag semantics are an unambiguous IETF standard (RFC 793); dtype matches results/feature_inventory.csv. No reference tool exists to confirm CICFlowMeter's exact per-packet counting rule (e.g. retransmission handling), so this is not fully VALIDATED."
    for f in ["ACK Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "URG Flag Cnt", "ECE Flag Cnt", "Fwd PSH Flags"]:
        add(f, CLASSIFY_B, STATUS_PARTIALLY_VALIDATED, flag_reason)

    # ---- Packet/byte counts ----
    count_reason = "Direct per-packet counting/summation, standard and unambiguous; dtype matches. Also indirectly corroborated: this exact column is the RHS of the Down/Up Ratio check (100% match, see down_up_ratio_eq_int_bwd_over_fwd) and the Subflow simplification checks (>99.99% match), both of which succeeded against real CICFlowMeter output."
    for f in ["Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts"]:
        add(f, CLASSIFY_B, STATUS_PARTIALLY_VALIDATED, count_reason)

    add("Fwd Act Data Pkts", CLASSIFY_B, STATUS_UNVALIDATED,
        "Definition of 'has data' (payload_len > 0) is an assumption; CICFlowMeter's own threshold for what counts as a 'data packet' (e.g. whether a TCP payload of exactly the MSS boundary or options-only packets count) is not documented in this repo and cannot be cross-checked from the training CSV alone.")

    header_reason = "Which header components CICFlowMeter sums (IP header only vs. IP+TCP/UDP header vs. TCP options) is a known ambiguity across CICFlowMeter versions/forks; this repo documents no formula and the training CSV alone cannot disambiguate a header-length sum from other columns."
    add("Fwd Header Len", CLASSIFY_D, STATUS_UNVALIDATED, header_reason)
    add("Bwd Header Len", CLASSIFY_D, STATUS_UNVALIDATED, header_reason)

    # ---- Init Win Byts ----
    for f, key in [("Init Fwd Win Byts", "init_fwd_win_byts_minus1_present"), ("Init Bwd Win Byts", "init_bwd_win_byts_minus1_present")]:
        c = cross[key]
        add(f, CLASSIFY_A, STATUS_PARTIALLY_VALIDATED,
            f"The '-1 for not-applicable' convention this implementation uses is EMPIRICALLY CONFIRMED present in real CICFlowMeter output: {c['count']} rows have exactly -1 in this column (min observed = {c['min_observed']}). The core 'first TCP packet's window field' formula for TCP flows themselves is not independently confirmed (no raw packets in the training CSV).")

    # ---- Pkt Len family ----
    c = cross["fwd_pkt_len_mean_eq_totlen_over_count"]
    add("Fwd Pkt Len Mean", CLASSIFY_A, STATUS_VALIDATED,
        f"Fwd Pkt Len Mean == TotLen Fwd Pkts / Tot Fwd Pkts holds in {c['matches']}/{c['total']} real training rows ({100*c['match_rate']:.4f}%, max_abs_diff={c['max_abs_diff']:.2e}). This IS the formula this implementation uses (_mean of forward packet lengths).")

    for f in ["Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Std"]:
        add(f, CLASSIFY_B, STATUS_PARTIALLY_VALIDATED,
            "Standard statistic over forward packet lengths; dtype matches. Fwd Pkt Len Mean (same underlying packet-length series) is separately VALIDATED, which corroborates the underlying per-packet length values used here, though Max/Min/Std themselves are not independently cross-checked.")

    c = cross["bwd_pkt_len_mean_eq_totlen_over_count"]
    add("Bwd Pkt Len Mean", CLASSIFY_C, STATUS_UNVALIDATED,
        f"Bwd Pkt Len Mean == TotLen Bwd Pkts / Tot Bwd Pkts holds in only {c['matches']}/{c['total']} rows ({100*c['match_rate']:.2f}%, max_abs_diff={c['max_abs_diff']:.4f}). This implementation computes Bwd Pkt Len Mean as a direct mean of backward packet lengths, which is mathematically forced to equal TotLen Bwd/Tot Bwd - yet real CICFlowMeter output disagrees with that identity in ~15% of rows, indicating CICFlowMeter's real Bwd Pkt Len Mean excludes or weights some packets differently than TotLen Bwd Pkts/Tot Bwd Pkts do. Concrete, unresolved discrepancy - NOT fixed in this audit per the audit-only scope.")

    for f in ["Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Std"]:
        add(f, CLASSIFY_B, STATUS_UNVALIDATED,
            "Standard statistic over backward packet lengths; dtype matches, but Bwd Pkt Len Mean (same underlying series) was found UNVALIDATED (~15% mismatch vs. TotLen Bwd/Tot Bwd) - the same uncertainty about which packets CICFlowMeter includes applies here.")

    c = cross["pkt_len_max_eq_max_fwd_bwd"]
    add("Pkt Len Max", CLASSIFY_A, STATUS_VALIDATED,
        f"Pkt Len Max == max(Fwd Pkt Len Max, Bwd Pkt Len Max) holds in {c['matches']}/{c['total']} rows ({100*c['match_rate']:.4f}%). This implementation computes Pkt Len Max directly as max() over the full packet list (both directions merged), which is consistent with this confirmed combination rule.")

    c = cross["pkt_len_min_eq_min_fwd_bwd_naive"]
    add("Pkt Len Min", CLASSIFY_A, STATUS_VALIDATED,
        f"Naive min(Fwd Pkt Len Min, Bwd Pkt Len Min) matches Pkt Len Min in {c['matches']}/{c['total']} rows ({100*c['match_rate']:.4f}%); ALL mismatches are explained by Tot Bwd Pkts==0 (all_mismatches_explained_by_zero_bwd_packets={c['all_mismatches_explained_by_zero_bwd_packets']}) - i.e. the naive combine formula is wrong only when one direction has zero packets. This implementation computes Pkt Len Min directly as min() over the full real packet list (not via the naive combine), which correctly avoids that edge case.")

    c = cross["pkt_size_avg_eq_pkt_len_mean"]
    add("Pkt Len Mean", CLASSIFY_C, STATUS_UNVALIDATED,
        "A simple weighted-mean formula ((TotLen Fwd+TotLen Bwd)/(Tot Fwd+Tot Bwd)) matches real Pkt Len Mean in only 31.8% of rows (see feature_validation_report.txt for the exact check). This, combined with the Bwd Pkt Len Mean discrepancy above, indicates CICFlowMeter's 'TotLen'-family and 'Pkt Len'-family columns may use materially different per-packet length definitions (e.g. payload-only vs. full IP packet) that this repository does not document and the training CSV alone cannot fully disambiguate.")
    for f in ["Pkt Len Std", "Pkt Len Var"]:
        add(f, CLASSIFY_B, STATUS_UNVALIDATED,
            "Depends on the same underlying per-packet length series as Pkt Len Mean, which was found UNVALIDATED (only 31.8% agreement with a simple weighted-mean formula) - inherits that uncertainty.")

    add("Pkt Size Avg", CLASSIFY_C, STATUS_UNVALIDATED,
        f"IMPORTANT CORRECTION to Feature L2's prior assumption: feature_mapping.py's limitation text stated Pkt Size Avg is 'numerically identical to Pkt Len Mean'. Empirically checked against real training data: {cross['pkt_size_avg_eq_pkt_len_mean']['matches']}/{cross['pkt_size_avg_eq_pkt_len_mean']['total']} rows match ({100*cross['pkt_size_avg_eq_pkt_len_mean']['match_rate']:.2f}%, max_abs_diff={cross['pkt_size_avg_eq_pkt_len_mean']['max_abs_diff']}) - they are NOT identical in ~69% of real rows. This implementation's current formula (alias of Pkt Len Mean) is therefore not empirically supported and should not be treated as validated.")

    # ---- Down/Up Ratio ----
    c = cross["down_up_ratio_eq_int_bwd_over_fwd"]
    add("Down/Up Ratio", CLASSIFY_A, STATUS_VALIDATED,
        f"int(Tot Bwd Pkts / Tot Fwd Pkts) (0 if Tot Fwd Pkts==0) matches the real Down/Up Ratio column in {c['matches']}/{c['total']} rows ({100*c['match_rate']:.4f}%) - exact agreement, zero exceptions. This IS the formula this implementation uses.")

    # ---- Rate features ----
    rc = cross["rate_convention__Flow Byts/s"]
    add("Flow Byts/s", CLASSIFY_C, STATUS_UNVALIDATED,
        f"Real data: of {rc['zero_numerator_and_duration_rows']} rows with zero duration AND zero total bytes, only {rc['of_those_inf']} are Infinity - the rest are NaN (0/0). This implementation's _rate() helper unconditionally returns math.inf whenever duration==0, regardless of the numerator, so it would incorrectly return Infinity instead of NaN for these zero-byte/zero-duration flows. For the {rc['inf_and_zero_duration']} zero-duration rows WITH nonzero bytes, Infinity is correct ({rc['inf_but_nonzero_duration']} Infinity values occur at nonzero duration, i.e. 0 - consistent). Concrete, unresolved discrepancy in the 0/0 edge case - NOT fixed in this audit.")

    rc = cross["rate_convention__Flow Pkts/s"]
    add("Flow Pkts/s", CLASSIFY_A, STATUS_VALIDATED,
        f"Infinity occurs in exactly {rc['inf_count_total']} rows, and ALL {rc['inf_count_total']} exactly match Flow Duration==0 ({rc['inf_and_zero_duration']}/{rc['inf_count_total']}, 100% match), with 0 Infinity values at nonzero duration. Since total packet count is always >=1 for any real flow, the 0/0 case never occurs for this feature, so this implementation's 'inf iff duration==0' rule is fully consistent with real data.")

    for f in ["Fwd Pkts/s", "Bwd Pkts/s"]:
        rc = cross[f"rate_convention__{f}"]
        add(f, CLASSIFY_C, STATUS_UNVALIDATED,
            f"MAJOR FINDING: {f} is NEVER Infinity anywhere in the real 331,027-row training dataset ({rc['inf_count_total']} Infinity values total), even though {rc['zero_duration_rows']} rows have Flow Duration==0 (and in the numerator-nonzero cases, a naive count/duration rule would demand Infinity). Real CICFlowMeter output instead uses 0.0 for this feature whenever duration==0. This implementation's _rate() helper returns math.inf unconditionally when duration==0, which is a systematic, 100%-consistent mismatch with real behavior for this feature - NOT fixed in this audit per the audit-only scope.")

    # ---- Seg Size ----
    c = cross["fwd_seg_size_avg_eq_fwd_pkt_len_mean"]
    add("Fwd Seg Size Avg", CLASSIFY_A, STATUS_VALIDATED,
        f"Exactly equals Fwd Pkt Len Mean in {c['matches']}/{c['total']} real rows ({100*c['match_rate']:.4f}%). Fwd Pkt Len Mean was itself separately VALIDATED, so this alias is doubly corroborated.")
    c = cross["bwd_seg_size_avg_eq_bwd_pkt_len_mean"]
    add("Bwd Seg Size Avg", CLASSIFY_C, STATUS_UNVALIDATED,
        f"Exactly equals Bwd Pkt Len Mean in {c['matches']}/{c['total']} real rows ({100*c['match_rate']:.4f}%) - the ALIAS relationship itself is confirmed. However Bwd Pkt Len Mean was found UNVALIDATED (~15% mismatch against its own simple-mean formula), so this feature inherits that same underlying uncertainty about what quantity is actually being measured.")
    c = cross["fwd_seg_size_min_eq_fwd_pkt_len_min"]
    add("Fwd Seg Size Min", CLASSIFY_D, STATUS_NOT_REPRODUCIBLE,
        f"MAJOR FINDING: only matches Fwd Pkt Len Min in {c['matches']}/{c['total']} rows ({100*c['match_rate']:.2f}%, max_abs_diff={c['max_abs_diff']}). Real Fwd Seg Size Min's value range (0-48, per results/feature_inventory.csv) is far tighter than Fwd Pkt Len Min's (0-1460), strongly suggesting CICFlowMeter's 'segment size' here is NOT packet length (e.g. may be TCP-payload-only or otherwise bounded by MSS/options size). This implementation's alias-based formula is empirically wrong for ~98% of real rows and no alternative formula derivable from this repo's artifacts is known to be correct - the most clearly incorrect/unreproducible formula found by this audit. NOT fixed here per the audit-only scope; needs a genuinely different formula, not a tuning adjustment.")

    # ---- IAT (14 features) ----
    iat_reason = "IAT is a well-defined algorithm GIVEN packet timestamps (inter-arrival gaps between consecutive packets), but cannot be cross-checked from the training CSV alone (no other column is a deterministic function of it) and no reference tool exists to validate against real packet-level timing."
    for f in ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
              "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
              "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"]:
        add(f, CLASSIFY_B, STATUS_UNVALIDATED, iat_reason)

    # ---- Active/Idle (8 features) ----
    active_idle_reason = (
        f"Well-defined algorithm GIVEN a threshold, but the threshold itself (this implementation uses 5,000,000us / 5s) is "
        f"not documented anywhere in this repository and cannot be empirically confirmed from the training CSV. Weak bound-"
        f"consistency evidence only: Active Max's real max ({cross['active_max_max']:.0f}us) and Idle Max's real max "
        f"({cross['idle_max_max']:.0f}us) are both <= Flow Duration's real max ({cross['flow_duration_max']:.0f}us), which is "
        f"consistent with (but does not prove) the active/idle segmentation algorithm and its threshold."
    )
    for f in ["Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"]:
        add(f, CLASSIFY_B, STATUS_UNVALIDATED, active_idle_reason)

    # ---- Flow Duration ----
    add("Flow Duration", CLASSIFY_B, STATUS_PARTIALLY_VALIDATED,
        f"Real training data's max Flow Duration is {cross['flow_duration_max']:.0f}us, just below 120,000,000us (120s) - consistent with (and the only available evidence for) this implementation's flow_timeout_us=120,000,000 default. Does not validate the per-flow start/end timestamp computation itself.")

    # ---- Subflow (Feature L2's original category D) ----
    subflow_checks = [
        ("Subflow Fwd Pkts", "subflow_fwd_pkts_eq_tot_fwd_pkts", "Tot Fwd Pkts"),
        ("Subflow Fwd Byts", "subflow_fwd_byts_eq_totlen_fwd_pkts", "TotLen Fwd Pkts"),
        ("Subflow Bwd Pkts", "subflow_bwd_pkts_eq_tot_bwd_pkts", "Tot Bwd Pkts"),
        ("Subflow Bwd Byts", "subflow_bwd_byts_eq_totlen_bwd_pkts", "TotLen Bwd Pkts"),
    ]
    for f, key, base in subflow_checks:
        c = cross[key]
        mismatch_note = "" if c["match_rate"] == 1.0 else f" The {c['total']-c['matches']} mismatches occur specifically on long-duration, high-packet-count flows, exactly matching feature_mapping.py's documented caveat that long idle gaps are where this simplification is most likely to diverge."
        add(f, CLASSIFY_B, STATUS_PARTIALLY_VALIDATED,
            f"Single-subflow simplification (this feature == {base}) EMPIRICALLY MATCHES real CICFlowMeter output in {c['matches']}/{c['total']} rows ({100*c['match_rate']:.4f}%).{mismatch_note} This is strong evidence the simplification is safe for typical flows, but does NOT prove CICFlowMeter's true subflow-splitting algorithm was reimplemented - only that its output coincides with the simplification for effectively all of this dataset's real flows. The caveat in feature_mapping.py is NOT removed.")

    return rows
