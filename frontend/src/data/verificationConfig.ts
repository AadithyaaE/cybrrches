import type { VerificationConfig } from "../types/verification";

/**
 * CyberChess demonstration verification criteria (Frontend Feature 11).
 *
 * Feature 10's mitigation-policy configuration (mitigationPolicyConfig.ts)
 * defines DECISION thresholds (when to choose a level) and SIMULATION
 * factors (how much simulated traffic changes), but it does not define a
 * verification TARGET - i.e. how much reduction counts as "sufficient" for
 * verification purposes. These two criteria fill that gap.
 *
 * Both values are chosen to sit clearly outside Feature 10's own configured
 * simulation factors (rateLimitReductionFactor=0.65, blockReductionFactor=0.98,
 * blockCollateralFactor=0.01) so that an action behaving as configured
 * naturally passes, while the criteria remain meaningful (a non-functioning
 * or excessively destructive action would fail them). They were NOT tuned
 * against Feature 16 (external generalization) results and are not
 * empirically calibrated for production deployment.
 */
export const VERIFICATION_CONFIG: VerificationConfig = {
  minSuspiciousReductionPct: {
    name: "Minimum suspicious-traffic reduction for threat suppression",
    value: 50,
    rationale: "Set well below Feature 10's configured RATE_LIMIT (65%) and TEMPORARY_BLOCK (98%) reduction factors, so a correctly-functioning traffic-modifying action passes, while a materially weaker or non-functioning action would fail.",
    source: "CyberChess demonstration verification criterion - not present in Feature 10's mitigationPolicyConfig.ts, defined here to fill that gap.",
    limitation: "Demonstration verification criterion; not empirically calibrated for production deployment; not tuned against Feature 16 outcomes.",
  },
  maxLegitimateLossPctAllowed: {
    name: "Maximum allowed legitimate-traffic loss for preservation",
    value: 5,
    rationale: "Set above Feature 10's configured TEMPORARY_BLOCK collateral factor (1%), so a correctly-functioning action passes, while remaining tight enough that a much larger legitimate-traffic impact would fail this objective independently of threat suppression.",
    source: "CyberChess demonstration verification criterion - not present in Feature 10's mitigationPolicyConfig.ts, defined here to fill that gap.",
    limitation: "Demonstration verification criterion; not empirically calibrated for production deployment; not tuned against Feature 16 outcomes.",
  },
  noModificationTolerancePct: {
    name: "Tolerance for 'no traffic modification' actions",
    value: 0.01,
    rationale: "MONITOR, ALERT, and ESCALATE are defined (Feature 10) as not modifying traffic. This tiny tolerance accounts only for floating-point arithmetic, not any real permitted change.",
    source: "Derived directly from Feature 10's MONITOR/ALERT/ESCALATE simulation factors (strengthFactor=0, i.e. no change by definition).",
    limitation: "Not a policy threshold - a numerical tolerance for exact-equality comparison.",
  },
  disclaimer:
    "CyberChess demonstration verification criterion. These values are documented for transparency but are not empirically calibrated for production deployment and were not tuned against Feature 16 (external generalization) outcomes or adjusted to make results look better.",
};
