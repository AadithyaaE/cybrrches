import { MITIGATION_POLICY_CONFIG } from "../../data/mitigationPolicyConfig";
import type {
  MitigationInput,
  MitigationDecision,
  MitigationLevel,
  ProbabilityTrend,
  EvidenceQuality,
  MitigationTriggerCondition,
} from "../../types/mitigation";

/**
 * Deterministic CyberChess demonstration mitigation policy engine.
 *
 * This is a documented demonstration policy, not a benchmark of competing
 * mitigation algorithms, and no mitigation level is described as best,
 * worst, optimal, or superior. The same MitigationInput always produces the
 * same MitigationDecision (pure function, no randomness, no network calls).
 */

const CFG = MITIGATION_POLICY_CONFIG;

function computeTrend(horizons: MitigationInput["horizonProbabilities"]): ProbabilityTrend {
  const p1 = horizons["1"];
  const latest = horizons["5"] ?? horizons["3"] ?? horizons["2"];
  if (p1 === null || latest === null || latest === undefined) return "unknown";
  const delta = latest - p1;
  if (delta >= CFG.trendDelta.value) return "rising";
  if (delta <= -CFG.trendDelta.value) return "falling";
  return "flat";
}

function computeEvidenceQuality(input: MitigationInput): EvidenceQuality {
  const hasProbability = input.attackProbability !== null;
  const hasStage = input.evidence.mitreStage !== null;
  const hasAttribution = input.evidence.attributionAvailable;

  if (!hasProbability && !hasStage) return "INSUFFICIENT";

  let score = 0;
  if (hasProbability) score++;
  if (hasStage) score++;
  if (hasAttribution) score++;
  if (hasStage && input.evidence.mitreStage!.status === "mapped") score++;
  if (hasStage && input.evidence.mitreStage!.evidenceScore >= CFG.mitreSevereEvidence.value) score++;

  if (score >= 4) return "HIGH";
  if (score >= 2) return "MEDIUM";
  return "LOW";
}

export function decideMitigation(input: MitigationInput): MitigationDecision {
  const p = input.attackProbability;
  const stage = input.evidence.mitreStage;
  const trend = computeTrend(input.horizonProbabilities);
  const evidenceQuality = computeEvidenceQuality(input);

  const conditions: MitigationTriggerCondition[] = [];
  const supportingEvidence: string[] = [];

  const hasProbability = p !== null;
  const hasStage = stage !== null;

  conditions.push({
    label: "Attack probability available",
    detail: hasProbability ? `P(Infiltration) = ${(p! * 100).toFixed(1)}%` : "No probability signal available for this input.",
    met: hasProbability,
  });
  conditions.push({
    label: "MITRE stage evidence available",
    detail: hasStage
      ? `Primary stage: ${stage!.stage} (${stage!.evidenceScore.toFixed(0)}/100, ${stage!.evidenceLabel}, ${stage!.status})`
      : "No MITRE stage evidence available for this input.",
    met: hasStage,
  });

  if (hasProbability) supportingEvidence.push(`Attack-progression probability: ${(p! * 100).toFixed(1)}% (Feature 13, forecast-based)`);
  if (hasStage) supportingEvidence.push(`MITRE ATT&CK evidence: ${stage!.stage} - ${stage!.evidenceScore.toFixed(0)}/100 (${stage!.evidenceLabel}, ${stage!.status}, Feature 14, observed state)`);
  if (input.evidence.attributionAvailable && input.evidence.topAttributionFeatures.length > 0) {
    const top = input.evidence.topAttributionFeatures[0];
    supportingEvidence.push(`Top contributing feature (Feature 15, exact classifier attribution): ${top.feature} (${top.direction}, ${top.contribution.toFixed(3)})`);
  }

  // --- No usable evidence at all: passive default ---
  if (!hasProbability && !hasStage) {
    return {
      level: "MONITOR",
      action: "Continue passive observation. No traffic modification.",
      reason: "No attack-progression probability and no MITRE stage evidence are available for this input - there is nothing actionable to respond to, so the policy defaults to the least intrusive level.",
      supportingEvidence: ["No Feature 13 probability available.", "No Feature 14 MITRE evidence available."],
      triggeringConditions: conditions,
      reversible: true,
      evidenceQuality,
      trend,
      simulationOnly: true,
      policyLabel: CFG.disclaimer,
    };
  }

  // --- Composite severity score (0..3+), documented rule cascade ---
  let score = 0;
  if (hasProbability) {
    if (p! >= CFG.probabilityThresholds.veryHigh.value) score = 3;
    else if (p! >= CFG.probabilityThresholds.high.value) score = 2;
    else if (p! >= CFG.probabilityThresholds.elevated.value) score = 1;
    else score = 0;
  }

  if (trend === "rising") {
    score += 1;
    supportingEvidence.push(`Rising attack-progression trend across forecast horizons (>= ${(CFG.trendDelta.value * 100).toFixed(0)} pt increase, K=1 to latest available K).`);
  } else if (trend === "falling" && score > 0) {
    score -= 1;
  }

  if (hasStage) {
    if (stage!.evidenceScore >= CFG.mitreSevereEvidence.value) {
      score += 1;
      supportingEvidence.push(`MITRE evidence score at or above the severe-evidence threshold (${CFG.mitreSevereEvidence.value}/100).`);
    } else if (stage!.evidenceScore < CFG.mitreMinEvidence.value) {
      score -= 1;
    }
    if (stage!.status === "candidate") {
      score -= 1;
      supportingEvidence.push(`MITRE stage "${stage!.stage}" is a CANDIDATE mapping only (Feature 14 caps its evidence and does not treat it as confirmed) - severity dampened accordingly.`);
    }
    if (stage!.stage === "Impact") {
      score += 1;
      supportingEvidence.push(`Primary stage is "Impact" (availability-disruption / DDoS-related evidence per T1498) - a deliberate policy weighting, documented, not a ranking of attack types.`);
    }
  }

  score = Math.max(0, Math.min(4, score));

  const missingOneSignal = !hasProbability || !hasStage;
  const conflicting = hasProbability && hasStage && trend === "falling" && stage!.evidenceScore >= CFG.mitreSevereEvidence.value;

  // --- Ambiguity override: high computed concern built on incomplete or conflicting evidence -> human review ---
  if ((missingOneSignal && score >= 2) || conflicting) {
    return {
      level: "ESCALATE",
      action: "Increase analyst attention / request manual intervention. No automatic traffic modification.",
      reason: conflicting
        ? "Signals conflict: MITRE evidence indicates a severe stage, but the attack-progression probability trend is falling. This ambiguity is routed to a human analyst rather than an automated traffic action."
        : "Computed concern is elevated, but only one of the two core evidence signals (attack probability, MITRE stage) is available. Acting automatically on partial evidence is avoided in favor of analyst review.",
      supportingEvidence,
      triggeringConditions: conditions,
      reversible: true,
      evidenceQuality,
      trend,
      simulationOnly: true,
      policyLabel: CFG.disclaimer,
    };
  }

  const levelLadder: MitigationLevel[] = ["MONITOR", "ALERT", "RATE_LIMIT", "TEMPORARY_BLOCK"];
  const level = levelLadder[Math.min(score, levelLadder.length - 1)];

  const actionText: Record<MitigationLevel, string> = {
    MONITOR: "Continue observation. No traffic modification.",
    ALERT: "Create a defender alert for analyst awareness. No traffic modification.",
    RATE_LIMIT: "Simulate throttling of suspicious traffic while preserving legitimate traffic.",
    TEMPORARY_BLOCK: "Simulate a temporary, reversible block of the identified suspicious source/flow, with a defined duration and rollback.",
    ESCALATE: "Increase analyst attention / request manual intervention. No automatic traffic modification.",
  };

  return {
    level,
    action: actionText[level],
    reason: `Composite demonstration-policy severity score = ${score} (0-4 scale, derived from probability threshold, forecast trend, and MITRE evidence per the documented rule cascade).`,
    supportingEvidence,
    triggeringConditions: conditions,
    reversible: true,
    evidenceQuality,
    trend,
    simulationOnly: true,
    policyLabel: CFG.disclaimer,
  };
}
