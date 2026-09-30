import type {
  MitigationInput,
  MitigationInputSource,
  MitigationDecision,
  MitigationLevel,
  MitigationTrafficState,
  MitigationSimulationResult,
  MitigationActionRecord,
} from "./mitigation";

/**
 * Feature 11 - Mitigation Verification.
 *
 * Consumes Feature 10's outputs (MitigationInput, MitigationDecision,
 * MitigationTrafficState, MitigationSimulationResult, MitigationActionRecord)
 * without recomputing their math independently - this file only adds the
 * verification-specific evaluation layer on top.
 *
 * Feature 10 performs SIMULATION ONLY, so every verification result here is
 * a SIMULATED VERIFICATION, never a claim about a real network.
 */

export type VerificationSource = MitigationInputSource;

export type VerificationStatus = "VERIFIED" | "PARTIALLY_VERIFIED" | "NOT_VERIFIED" | "UNAVAILABLE";

export type VerificationObjectiveResult = "PASS" | "FAIL" | "UNAVAILABLE";

export interface VerificationObjective {
  key: "threat_suppression" | "legitimate_preservation" | "action_status" | "reversibility";
  label: string;
  expectedCondition: string;
  actualResult: string;
  result: VerificationObjectiveResult;
  reason: string;
}

export interface VerificationTrafficComparison {
  metric: "suspicious" | "legitimate" | "total";
  label: string;
  before: number;
  after: number;
  absoluteChange: number;
  percentChange: number;
  objectiveResult: VerificationObjectiveResult | "INFO";
}

export interface RollbackFieldCheck {
  field: keyof MitigationTrafficState;
  before: number;
  restored: number | null;
  matches: boolean | null;
}

export interface RollbackVerification {
  performed: boolean;
  exactRestoration: boolean | null;
  before: MitigationTrafficState;
  restoredState: MitigationTrafficState | null;
  fieldChecks: RollbackFieldCheck[];
  label: "ROLLBACK VERIFIED" | "ROLLBACK NOT VERIFIED" | "NOT PERFORMED";
}

export interface VerificationTimelineEvent {
  step: number;
  label: string;
  detail: string;
  timestamp: number | null;
  occurred: boolean;
}

export interface VerificationInput {
  mitigationInput: MitigationInput;
  decision: MitigationDecision;
  before: MitigationTrafficState;
  simulationResult: MitigationSimulationResult;
  proposedRecord: MitigationActionRecord | null;
  applied: boolean;
  appliedRecord: MitigationActionRecord | null;
  rolledBack: boolean;
  rolledBackRecord: MitigationActionRecord | null;
}

export interface VerificationSummary {
  status: VerificationStatus;
  source: VerificationSource;
  objectives: VerificationObjective[];
  trafficComparisons: VerificationTrafficComparison[];
  rollback: RollbackVerification;
  timeline: VerificationTimelineEvent[];
  simulationOnly: true;
  label: "SIMULATED VERIFICATION";
  reason: string;
  verifiedAt: number;
}

export interface VerificationCriterion {
  name: string;
  value: number;
  rationale: string;
  source: string;
  limitation: string;
}

export interface VerificationConfig {
  minSuspiciousReductionPct: VerificationCriterion;
  maxLegitimateLossPctAllowed: VerificationCriterion;
  noModificationTolerancePct: VerificationCriterion;
  disclaimer: string;
}

export type { MitigationLevel };
