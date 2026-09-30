import { MITIGATION_POLICY_CONFIG } from "../../data/mitigationPolicyConfig";
import type { MitigationInput, MitigationLevel, MitigationSimulationResult, MitigationTrafficState } from "../../types/mitigation";

/**
 * Deterministic, controlled simulation of mitigation actions. Pure
 * arithmetic only - no network calls, no shell commands, no firewall or
 * routing changes of any kind. Every output is explicitly labeled
 * "Simulated outcome", never presented as a real network measurement.
 */

const CFG = MITIGATION_POLICY_CONFIG.simulation;

/**
 * The absolute traffic volume is an illustrative constant (documented in
 * mitigationPolicyConfig.ts). The suspicious/legitimate SPLIT is driven by
 * real evidence where available (MITRE evidence score, else attack
 * probability), so the simulation's shape reflects real signal even though
 * its scale does not claim to be a measured flow count.
 */
export function buildBeforeTrafficState(input: MitigationInput): MitigationTrafficState {
  const total = CFG.illustrativeBaselineTotalFlows.value;
  let suspiciousRatio: number;
  if (input.evidence.mitreStage) {
    suspiciousRatio = input.evidence.mitreStage.evidenceScore / 100;
  } else if (input.attackProbability !== null) {
    suspiciousRatio = input.attackProbability;
  } else {
    suspiciousRatio = 0;
  }
  suspiciousRatio = Math.max(0, Math.min(1, suspiciousRatio));

  const suspiciousFlows = Math.round(total * suspiciousRatio);
  const legitimateFlows = total - suspiciousFlows;
  return { totalFlows: total, suspiciousFlows, legitimateFlows };
}

export function simulateMitigation(before: MitigationTrafficState, level: MitigationLevel): MitigationSimulationResult {
  let suspiciousFactor = 1;
  let legitimateFactor = 1;
  let durationSeconds: number | null = null;

  switch (level) {
    case "MONITOR":
    case "ALERT":
    case "ESCALATE":
      suspiciousFactor = 1;
      legitimateFactor = 1;
      durationSeconds = null;
      break;
    case "RATE_LIMIT":
      suspiciousFactor = 1 - CFG.rateLimitReductionFactor.value;
      legitimateFactor = 1;
      durationSeconds = CFG.rateLimitDurationSeconds.value;
      break;
    case "TEMPORARY_BLOCK":
      suspiciousFactor = 1 - CFG.blockReductionFactor.value;
      legitimateFactor = 1 - CFG.blockCollateralFactor.value;
      durationSeconds = CFG.blockDurationSeconds.value;
      break;
  }

  const suspiciousAfter = Math.round(before.suspiciousFlows * suspiciousFactor);
  const legitimateAfter = Math.round(before.legitimateFlows * legitimateFactor);
  const totalAfter = suspiciousAfter + legitimateAfter;

  const suspiciousReductionPct = before.suspiciousFlows === 0 ? 0 : (1 - suspiciousAfter / before.suspiciousFlows) * 100;
  const legitimatePreservedPct = before.legitimateFlows === 0 ? 100 : (legitimateAfter / before.legitimateFlows) * 100;

  return {
    before,
    after: { totalFlows: totalAfter, suspiciousFlows: suspiciousAfter, legitimateFlows: legitimateAfter },
    action: level,
    strengthFactor: 1 - suspiciousFactor,
    durationSeconds,
    suspiciousReductionPct,
    legitimatePreservedPct,
    label: "Simulated outcome",
    baselineNote: CFG.illustrativeBaselineTotalFlows.rationale,
  };
}

export function rollbackSimulation(before: MitigationTrafficState): MitigationSimulationResult {
  return {
    before,
    after: before,
    action: "MONITOR",
    strengthFactor: 0,
    durationSeconds: null,
    suspiciousReductionPct: 0,
    legitimatePreservedPct: 100,
    label: "Simulated outcome",
    baselineNote: "Rolled back to the pre-action baseline traffic state (simulation only).",
  };
}
