/**
 * Feature 10 - Mitigation Engine + Controlled Simulation.
 *
 * Strict separation (never mixed):
 *   - RESEARCH-DERIVED values: read from real Feature 13/14/15 artifacts
 *     (via explainabilityService's ExplanationExample records).
 *   - DEMONSTRATION SCENARIO values: hand-authored, deterministic, clearly
 *     labeled example inputs used only when a complete real record is not
 *     being used.
 *   - POLICY CONFIGURATION: fixed thresholds/factors, documented, never
 *     tuned against Feature 16 outcomes.
 *   - SIMULATED OUTPUT: deterministic arithmetic over the above, never a
 *     measured network outcome.
 */

export type MitigationInputSource = "RESEARCH_DERIVED" | "DEMONSTRATION_SCENARIO";

export type EvidenceOrigin = "OBSERVED" | "FORECAST" | "MIXED" | "UNAVAILABLE";

export type MitreMappingStatus = "mapped" | "candidate" | "unknown";

export interface MitigationStageEvidence {
  stage: string;
  evidenceScore: number;
  evidenceLabel: string;
  status: MitreMappingStatus;
  isPrimary: boolean;
}

export interface MitigationAttributionFeature {
  feature: string;
  contribution: number;
  direction: "attack" | "benign";
}

export interface MitigationEvidenceBundle {
  mitreStage: MitigationStageEvidence | null;
  allStageScores: MitigationStageEvidence[];
  attributionAvailable: boolean;
  topAttributionFeatures: MitigationAttributionFeature[];
  occlusionAvailable: boolean;
  evidenceOrigin: EvidenceOrigin;
}

export interface MitigationInput {
  source: MitigationInputSource;
  id: string;
  label: string;
  attackProbability: number | null;
  horizonProbabilities: Record<"1" | "2" | "3" | "5", number | null>;
  evidence: MitigationEvidenceBundle;
  note: string;
}

export type MitigationLevel = "MONITOR" | "ALERT" | "RATE_LIMIT" | "TEMPORARY_BLOCK" | "ESCALATE";

export type ProbabilityTrend = "rising" | "falling" | "flat" | "unknown";

export type EvidenceQuality = "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";

export interface MitigationTriggerCondition {
  label: string;
  detail: string;
  met: boolean;
}

export interface MitigationDecision {
  level: MitigationLevel;
  action: string;
  reason: string;
  supportingEvidence: string[];
  triggeringConditions: MitigationTriggerCondition[];
  reversible: boolean;
  evidenceQuality: EvidenceQuality;
  trend: ProbabilityTrend;
  simulationOnly: true;
  policyLabel: string;
}

export interface MitigationActionRecord {
  actionId: string;
  timestamp: number;
  level: MitigationLevel;
  action: string;
  durationSeconds: number | null;
  status: "proposed" | "applied" | "rolled_back" | "reset";
  reversible: true;
  simulationOnly: true;
}

export interface MitigationTrafficState {
  totalFlows: number;
  suspiciousFlows: number;
  legitimateFlows: number;
}

export interface MitigationSimulationResult {
  before: MitigationTrafficState;
  after: MitigationTrafficState;
  action: MitigationLevel;
  strengthFactor: number;
  durationSeconds: number | null;
  suspiciousReductionPct: number;
  legitimatePreservedPct: number;
  label: "Simulated outcome";
  baselineNote: string;
}

export interface MitigationPolicyThreshold {
  name: string;
  value: number;
  rationale: string;
  source: string;
  limitation: string;
}

export interface MitigationPolicyConfig {
  probabilityThresholds: {
    elevated: MitigationPolicyThreshold;
    high: MitigationPolicyThreshold;
    veryHigh: MitigationPolicyThreshold;
  };
  trendDelta: MitigationPolicyThreshold;
  mitreSevereEvidence: MitigationPolicyThreshold;
  mitreMinEvidence: MitigationPolicyThreshold;
  simulation: {
    illustrativeBaselineTotalFlows: MitigationPolicyThreshold;
    rateLimitReductionFactor: MitigationPolicyThreshold;
    blockReductionFactor: MitigationPolicyThreshold;
    blockCollateralFactor: MitigationPolicyThreshold;
    rateLimitDurationSeconds: MitigationPolicyThreshold;
    blockDurationSeconds: MitigationPolicyThreshold;
  };
  disclaimer: string;
}

export interface MitigationScenario {
  id: string;
  title: string;
  expectedLevelHint: MitigationLevel;
  description: string;
  input: MitigationInput;
}
