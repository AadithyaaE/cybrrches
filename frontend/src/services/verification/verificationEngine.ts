import { VERIFICATION_CONFIG } from "../../data/verificationConfig";
import { rollbackSimulation } from "../mitigation/mitigationSimulation";
import type { MitigationLevel, MitigationTrafficState } from "../../types/mitigation";
import type {
  VerificationInput,
  VerificationSummary,
  VerificationObjective,
  VerificationObjectiveResult,
  VerificationTrafficComparison,
  RollbackVerification,
  RollbackFieldCheck,
  VerificationStatus,
  VerificationTimelineEvent,
} from "../../types/verification";

/**
 * Deterministic CyberChess verification engine. Pure functions only - no
 * network calls, no side effects. Reuses Feature 10's `rollbackSimulation`
 * rather than reimplementing rollback math.
 *
 * "SIMULATED VERIFICATION": every result here evaluates Feature 10's
 * simulated before/after traffic arithmetic, never a real, measured network
 * outcome.
 */

const CFG = VERIFICATION_CONFIG;
const TRAFFIC_MODIFYING_LEVELS: MitigationLevel[] = ["RATE_LIMIT", "TEMPORARY_BLOCK"];

function percentChange(before: number, after: number): number {
  if (before === 0) return 0;
  return ((after - before) / before) * 100;
}

export function evaluateThreatSuppression(
  before: MitigationTrafficState,
  after: MitigationTrafficState,
  level: MitigationLevel,
): VerificationObjective {
  const changePct = percentChange(before.suspiciousFlows, after.suspiciousFlows);
  const reductionPct = Math.max(0, -changePct);
  const isModifyingAction = TRAFFIC_MODIFYING_LEVELS.includes(level);

  if (isModifyingAction) {
    const pass = reductionPct >= CFG.minSuspiciousReductionPct.value;
    return {
      key: "threat_suppression",
      label: "Threat Suppression",
      expectedCondition: `Suspicious traffic reduction >= ${CFG.minSuspiciousReductionPct.value}% (demonstration verification criterion)`,
      actualResult: `Suspicious traffic reduced by ${reductionPct.toFixed(1)}% (${before.suspiciousFlows.toLocaleString()} -> ${after.suspiciousFlows.toLocaleString()})`,
      result: pass ? "PASS" : "FAIL",
      reason: pass
        ? `Reduction of ${reductionPct.toFixed(1)}% meets the ${CFG.minSuspiciousReductionPct.value}% demonstration criterion for a ${level.replace(/_/g, " ")} action.`
        : `Reduction of ${reductionPct.toFixed(1)}% is below the ${CFG.minSuspiciousReductionPct.value}% demonstration criterion for a ${level.replace(/_/g, " ")} action.`,
    };
  }

  const pass = Math.abs(changePct) <= CFG.noModificationTolerancePct.value;
  return {
    key: "threat_suppression",
    label: "Threat Suppression",
    expectedCondition: `No traffic modification (${level.replace(/_/g, " ")} is an observation-only action by design; 0% change expected)`,
    actualResult: `Suspicious traffic change: ${changePct.toFixed(2)}% (${before.suspiciousFlows.toLocaleString()} -> ${after.suspiciousFlows.toLocaleString()})`,
    result: pass ? "PASS" : "FAIL",
    reason: pass
      ? `${level.replace(/_/g, " ")} does not modify traffic by design, and none occurred, consistent with the mitigation policy.`
      : `${level.replace(/_/g, " ")} is not expected to modify traffic, but a change was observed - this would indicate a simulation inconsistency.`,
  };
}

export function evaluateLegitimatePreservation(before: MitigationTrafficState, after: MitigationTrafficState): VerificationObjective {
  const changePct = percentChange(before.legitimateFlows, after.legitimateFlows);
  const lossPct = Math.max(0, -changePct);
  const pass = lossPct <= CFG.maxLegitimateLossPctAllowed.value;

  return {
    key: "legitimate_preservation",
    label: "Legitimate Traffic Preservation",
    expectedCondition: `Legitimate traffic loss <= ${CFG.maxLegitimateLossPctAllowed.value}% (demonstration verification criterion)`,
    actualResult: `Legitimate traffic loss = ${lossPct.toFixed(1)}% (${before.legitimateFlows.toLocaleString()} -> ${after.legitimateFlows.toLocaleString()})`,
    result: pass ? "PASS" : "FAIL",
    reason: pass
      ? `Loss of ${lossPct.toFixed(1)}% is within the ${CFG.maxLegitimateLossPctAllowed.value}% allowed-impact demonstration criterion.`
      : `Loss of ${lossPct.toFixed(1)}% exceeds the ${CFG.maxLegitimateLossPctAllowed.value}% allowed-impact demonstration criterion - this mitigation would not be considered controlled.`,
  };
}

export function evaluateActionStatus(input: VerificationInput): VerificationObjective {
  if (!input.applied || !input.appliedRecord) {
    return {
      key: "action_status",
      label: "Mitigation Action Status",
      expectedCondition: "The policy-decided action was applied in the simulation.",
      actualResult: "No simulation has been applied for this input yet.",
      result: "UNAVAILABLE",
      reason: "Verification requires the mitigation action to have been applied first (Before / After Simulation section).",
    };
  }
  const pass = input.appliedRecord.level === input.decision.level;
  return {
    key: "action_status",
    label: "Mitigation Action Status",
    expectedCondition: `The policy-decided action (${input.decision.level.replace(/_/g, " ")}) was applied in the simulation.`,
    actualResult: `Applied action level: ${input.appliedRecord.level.replace(/_/g, " ")}`,
    result: pass ? "PASS" : "FAIL",
    reason: pass
      ? "The action applied in the simulation matches the policy engine's decision for this input."
      : "The applied action level does not match the current policy decision (the input may have changed since the action was applied).",
  };
}

export function evaluateRollback(before: MitigationTrafficState, performed: boolean): RollbackVerification {
  if (!performed) {
    return { performed: false, exactRestoration: null, before, restoredState: null, fieldChecks: [], label: "NOT PERFORMED" };
  }
  const rollbackResult = rollbackSimulation(before);
  const restoredState = rollbackResult.after;
  const fields: (keyof MitigationTrafficState)[] = ["suspiciousFlows", "legitimateFlows", "totalFlows"];
  const fieldChecks: RollbackFieldCheck[] = fields.map((field) => ({
    field,
    before: before[field],
    restored: restoredState[field],
    matches: before[field] === restoredState[field],
  }));
  const exact = fieldChecks.every((c) => c.matches);
  return {
    performed: true,
    exactRestoration: exact,
    before,
    restoredState,
    fieldChecks,
    label: exact ? "ROLLBACK VERIFIED" : "ROLLBACK NOT VERIFIED",
  };
}

function buildTrafficComparisons(before: MitigationTrafficState, after: MitigationTrafficState, objectives: VerificationObjective[]): VerificationTrafficComparison[] {
  const suppression = objectives.find((o) => o.key === "threat_suppression");
  const preservation = objectives.find((o) => o.key === "legitimate_preservation");

  return [
    {
      metric: "suspicious",
      label: "Suspicious Traffic",
      before: before.suspiciousFlows,
      after: after.suspiciousFlows,
      absoluteChange: after.suspiciousFlows - before.suspiciousFlows,
      percentChange: percentChange(before.suspiciousFlows, after.suspiciousFlows),
      objectiveResult: suppression?.result ?? "UNAVAILABLE",
    },
    {
      metric: "legitimate",
      label: "Legitimate Traffic",
      before: before.legitimateFlows,
      after: after.legitimateFlows,
      absoluteChange: after.legitimateFlows - before.legitimateFlows,
      percentChange: percentChange(before.legitimateFlows, after.legitimateFlows),
      objectiveResult: preservation?.result ?? "UNAVAILABLE",
    },
    {
      metric: "total",
      label: "Total Traffic",
      before: before.totalFlows,
      after: after.totalFlows,
      absoluteChange: after.totalFlows - before.totalFlows,
      percentChange: percentChange(before.totalFlows, after.totalFlows),
      objectiveResult: "INFO",
    },
  ];
}

function buildTimeline(input: VerificationInput, verifiedAt: number | null): VerificationTimelineEvent[] {
  return [
    {
      step: 1,
      label: "Threat observed",
      detail: input.mitigationInput.label,
      timestamp: null,
      occurred: true,
    },
    {
      step: 2,
      label: "Mitigation decision",
      detail: `${input.decision.level.replace(/_/g, " ")} - ${input.decision.reason}`,
      timestamp: input.proposedRecord?.timestamp ?? null,
      occurred: true,
    },
    {
      step: 3,
      label: "Simulation applied",
      detail: input.applied ? "Simulation applied." : "Not yet applied.",
      timestamp: input.appliedRecord?.timestamp ?? null,
      occurred: input.applied,
    },
    {
      step: 4,
      label: "Simulated post-mitigation state",
      detail: input.applied
        ? `Suspicious ${input.simulationResult.after.suspiciousFlows.toLocaleString()}, Legitimate ${input.simulationResult.after.legitimateFlows.toLocaleString()}`
        : "Not available until the simulation is applied.",
      timestamp: input.appliedRecord?.timestamp ?? null,
      occurred: input.applied,
    },
    {
      step: 5,
      label: "Verification performed",
      detail: verifiedAt !== null ? "Verification was run against the current simulated state." : "Not yet run.",
      timestamp: verifiedAt,
      occurred: verifiedAt !== null,
    },
    {
      step: 6,
      label: "Verification result",
      detail: verifiedAt !== null ? "See Verification Result section." : "Not available until verification is run.",
      timestamp: verifiedAt,
      occurred: verifiedAt !== null,
    },
    {
      step: 7,
      label: "Rollback if requested",
      detail: input.rolledBack ? "Rollback was requested and performed." : "Not requested.",
      timestamp: input.rolledBackRecord?.timestamp ?? null,
      occurred: input.rolledBack,
    },
  ];
}

function combineOverallStatus(objectives: VerificationObjective[]): VerificationStatus {
  const actionStatus = objectives.find((o) => o.key === "action_status");
  if (!actionStatus || actionStatus.result === "UNAVAILABLE") return "UNAVAILABLE";

  const coreResults: VerificationObjectiveResult[] = objectives
    .filter((o) => o.key === "threat_suppression" || o.key === "legitimate_preservation")
    .map((o) => o.result);

  const evaluable = coreResults.filter((r) => r !== "UNAVAILABLE");
  if (evaluable.length === 0) return "UNAVAILABLE";
  if (evaluable.every((r) => r === "PASS")) return "VERIFIED";
  if (evaluable.every((r) => r === "FAIL")) return "NOT_VERIFIED";
  return "PARTIALLY_VERIFIED";
}

export function runVerification(input: VerificationInput, verifiedAt: number): VerificationSummary {
  const actionStatus = evaluateActionStatus(input);

  if (actionStatus.result === "UNAVAILABLE") {
    const objectives = [actionStatus];
    return {
      status: "UNAVAILABLE",
      source: input.mitigationInput.source,
      objectives,
      trafficComparisons: buildTrafficComparisons(input.before, input.before, objectives),
      rollback: evaluateRollback(input.before, input.rolledBack),
      timeline: buildTimeline(input, null),
      simulationOnly: true,
      label: "SIMULATED VERIFICATION",
      reason: "The mitigation action has not been applied yet, so there is insufficient evidence to evaluate the mitigation objective.",
      verifiedAt,
    };
  }

  const suppression = evaluateThreatSuppression(input.simulationResult.before, input.simulationResult.after, input.decision.level);
  const preservation = evaluateLegitimatePreservation(input.simulationResult.before, input.simulationResult.after);
  const objectives = [suppression, preservation, actionStatus];

  const status = combineOverallStatus(objectives);

  const reasonByStatus: Record<VerificationStatus, string> = {
    VERIFIED: "The mitigation action was applied and both the threat-suppression and legitimate-traffic-preservation objectives were satisfied.",
    PARTIALLY_VERIFIED: "The mitigation action was applied, but only one of the threat-suppression and legitimate-traffic-preservation objectives was satisfied.",
    NOT_VERIFIED: "The mitigation action was applied, but neither the threat-suppression nor the legitimate-traffic-preservation objective was satisfied.",
    UNAVAILABLE: "Insufficient evidence to evaluate the mitigation objective.",
  };

  return {
    status,
    source: input.mitigationInput.source,
    objectives,
    trafficComparisons: buildTrafficComparisons(input.simulationResult.before, input.simulationResult.after, objectives),
    rollback: evaluateRollback(input.before, input.rolledBack),
    timeline: buildTimeline(input, verifiedAt),
    simulationOnly: true,
    label: "SIMULATED VERIFICATION",
    reason: reasonByStatus[status],
    verifiedAt,
  };
}
