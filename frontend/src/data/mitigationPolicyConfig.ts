import type { MitigationPolicyConfig } from "../types/mitigation";

/**
 * CyberChess demonstration policy thresholds (Frontend Feature 10).
 *
 * These are NOT scientifically optimal and are NOT calibrated for
 * production deployment. Every value below is documented with its
 * rationale, source, and limitation. Probability thresholds are anchored to
 * REAL, already-published Feature 13 statistics (the K=1 full-pipeline
 * VALIDATION probability trajectory from
 * results/attack_progression/attack_progression_trajectory_summary.csv /
 * attack_progression_report.txt: mean=0.4999693036079407,
 * p90=0.5575703978538513, n=3492) so they are grounded in real observed
 * distribution shape rather than arbitrary round numbers - but they were
 * chosen for this demonstration, not tuned against Feature 16 (external
 * generalization) outcomes to make results look better.
 */
export const MITIGATION_POLICY_CONFIG: MitigationPolicyConfig = {
  probabilityThresholds: {
    elevated: {
      name: "Elevated probability threshold",
      value: 0.52,
      rationale: "Just above the real K=1 full-pipeline VALIDATION mean probability (0.4999...) - a reading above the population's own average.",
      source: "results/attack_progression/attack_progression_trajectory_summary.csv (horizon=1, mean=0.4999693036079407)",
      limitation: "Demonstration policy threshold; not empirically calibrated for production deployment. Not derived from any cost-sensitive analysis.",
    },
    high: {
      name: "High probability threshold",
      value: 0.5576,
      rationale: "Set at the real K=1 full-pipeline VALIDATION 90th percentile (p90) - a reading higher than 90% of the validation population.",
      source: "results/attack_progression/attack_progression_trajectory_summary.csv (horizon=1, p90=0.5575703978538513)",
      limitation: "Demonstration policy threshold; not empirically calibrated for production deployment. The p90 describes the VALIDATION distribution only, not any external or live population.",
    },
    veryHigh: {
      name: "Very high probability threshold",
      value: 0.62,
      rationale: "Deliberately conservative margin above the p90 threshold, intended to represent a rare/extreme reading.",
      source: "Derived from the same trajectory data as a margin above p90; not itself a published percentile.",
      limitation: "Demonstration policy threshold; not empirically calibrated for production deployment. Arbitrary margin, not statistically derived.",
    },
  },
  trendDelta: {
    name: "Rising/falling trend delta",
    value: 0.02,
    rationale: "Minimum change in predicted probability between the earliest and latest available horizon (K=1 vs the largest of K=2/3/5) to call the trend 'rising' or 'falling' rather than 'flat'.",
    source: "Demonstration choice - not derived from any statistical significance test.",
    limitation: "Demonstration policy threshold; not empirically calibrated. Does not account for the compounding forecast error documented in Feature 12 (longer horizons are less reliable, not just 'more severe').",
  },
  mitreSevereEvidence: {
    name: "Severe MITRE evidence score",
    value: 60,
    rationale: "Matches Feature 14's own published 'HIGH' evidence-label band (60-79) from mitre_stage_rule_definitions.json's evidence_label_bands.",
    source: "results/mitre/mitre_stage_rule_definitions.json (evidence_label_bands.HIGH = '60-79')",
    limitation: "This is a Stage Evidence Score, not a probability or model confidence (Feature 14's own documented limitation) - reusing it as a policy input inherits that limitation.",
  },
  mitreMinEvidence: {
    name: "Minimum MITRE evidence for a primary stage",
    value: 30,
    rationale: "Reuses Feature 14's own published minimum-evidence threshold for assigning any primary_stage at all (below this, Feature 14 itself reports UNKNOWN / INSUFFICIENT_EVIDENCE).",
    source: "results/mitre/mitre_stage_rule_definitions.json (thresholds.min_evidence_threshold_for_primary_stage = 30)",
    limitation: "Reused as-is from Feature 14; not independently re-validated for mitigation decisioning.",
  },
  simulation: {
    illustrativeBaselineTotalFlows: {
      name: "Illustrative baseline total flow count",
      value: 1000,
      rationale: "A round, clearly-illustrative number used only to make the before/after simulation concrete and readable. The SPLIT between suspicious/legitimate is driven by real evidence (MITRE evidence score or attack probability); the absolute total is not.",
      source: "None - illustrative constant.",
      limitation: "Not a measured flow/packet count from any dataset or network. Simulated outcomes computed from it are not measured network outcomes.",
    },
    rateLimitReductionFactor: {
      name: "RATE_LIMIT suspicious-traffic reduction factor",
      value: 0.65,
      rationale: "Illustrates partial, non-destructive throttling: most - not all - suspicious traffic is reduced, while legitimate traffic is fully preserved.",
      source: "None - illustrative simulation parameter.",
      limitation: "Not derived from any measured rate-limiting deployment. A real enforcement adapter would need its own empirically-validated parameters.",
    },
    blockReductionFactor: {
      name: "TEMPORARY_BLOCK suspicious-traffic reduction factor",
      value: 0.98,
      rationale: "Illustrates a strong but not absolute block (2% residual represents realistic imperfection - e.g. retries via other paths - rather than claiming a perfect block).",
      source: "None - illustrative simulation parameter.",
      limitation: "Not derived from any measured blocking deployment.",
    },
    blockCollateralFactor: {
      name: "TEMPORARY_BLOCK legitimate-traffic collateral factor",
      value: 0.01,
      rationale: "Illustrates that blocking action is never perfectly precise in the real world (a small legitimate-traffic impact is modeled), rather than presenting blocking as risk-free.",
      source: "None - illustrative simulation parameter.",
      limitation: "Not derived from any measured false-positive rate of a real enforcement mechanism.",
    },
    rateLimitDurationSeconds: {
      name: "RATE_LIMIT simulated duration",
      value: 300,
      rationale: "5-minute illustrative window, long enough to be meaningful, short enough to require re-evaluation.",
      source: "None - illustrative simulation parameter.",
      limitation: "Not an operationally validated duration.",
    },
    blockDurationSeconds: {
      name: "TEMPORARY_BLOCK simulated duration",
      value: 900,
      rationale: "15-minute illustrative window, deliberately temporary (not a permanent block) per the CyberChess MITIGATE -> VERIFY cycle.",
      source: "None - illustrative simulation parameter.",
      limitation: "Not an operationally validated duration.",
    },
  },
  disclaimer:
    "CyberChess demonstration policy thresholds. These values are documented for transparency but are not scientifically optimal, not empirically calibrated for production deployment, and were not tuned against Feature 16 (external generalization) outcomes.",
};
