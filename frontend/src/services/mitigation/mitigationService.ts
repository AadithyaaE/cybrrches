import { getExplanationExamples } from "../explainabilityService";
import { MITIGATION_POLICY_CONFIG } from "../../data/mitigationPolicyConfig";
import { MITIGATION_SCENARIOS } from "../../data/mitigationScenarios";
import type { ExplanationExample } from "../../types/explainability";
import type {
  MitigationInput,
  MitigationStageEvidence,
  MitigationScenario,
  MitreMappingStatus,
} from "../../types/mitigation";

/**
 * Builds MitigationInput records from REAL Feature 13/14/15 data already
 * fetched by explainabilityService.ts (results/explainability/explanation_examples.json)
 * - never duplicates that artifact, only reads it through the existing
 * service. Also exposes the clearly-labeled demonstration scenarios.
 *
 * MITRE stage_scores keys in the artifact are lowercase_with_underscores;
 * this module only re-keys them for lookup, it never recomputes or alters
 * any value.
 */

const STAGE_KEY_TO_DISPLAY_NAME: Record<string, string> = {
  discovery: "Discovery",
  command_and_control: "Command and Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
  reconnaissance: "Reconnaissance",
  initial_access: "Initial Access",
  lateral_movement: "Lateral Movement",
};

const MAPPED_STAGES = new Set(["Discovery", "Command and Control", "Exfiltration", "Impact"]);
const CANDIDATE_STAGES = new Set(["Reconnaissance", "Initial Access", "Lateral Movement"]);

function evidenceLabelFor(score: number): string {
  if (score >= 80) return "VERY HIGH";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

function statusFor(stageDisplayName: string): MitreMappingStatus {
  if (MAPPED_STAGES.has(stageDisplayName)) return "mapped";
  if (CANDIDATE_STAGES.has(stageDisplayName)) return "candidate";
  return "unknown";
}

export function buildMitigationInputFromExample(example: ExplanationExample): MitigationInput {
  const allStageScores: MitigationStageEvidence[] = Object.entries(example.mitre_evidence.stage_scores).map(([key, score]) => {
    const displayName = STAGE_KEY_TO_DISPLAY_NAME[key] ?? key;
    return {
      stage: displayName,
      evidenceScore: score,
      evidenceLabel: evidenceLabelFor(score),
      status: statusFor(displayName),
      isPrimary: displayName === example.mitre_evidence.primary_stage,
    };
  });

  const isKnownStage = example.mitre_evidence.primary_stage !== "UNKNOWN / INSUFFICIENT_EVIDENCE";
  const mitreStage: MitigationStageEvidence | null = isKnownStage
    ? allStageScores.find((s) => s.isPrimary) ?? null
    : null;

  const horizonProbabilities = {
    "1": example.feature_13_probability["1"]?.probability ?? example.attack_probability ?? null,
    "2": example.feature_13_probability["2"]?.probability ?? null,
    "3": example.feature_13_probability["3"]?.probability ?? null,
    "5": example.feature_13_probability["5"]?.probability ?? null,
  };

  return {
    source: "RESEARCH_DERIVED",
    id: `seq-${example.sequence_id}`,
    label: `Validation sequence #${example.sequence_id} (predicted ${example.prediction})`,
    attackProbability: horizonProbabilities["1"],
    horizonProbabilities,
    evidence: {
      mitreStage,
      allStageScores,
      attributionAvailable: example.top_contributors.length > 0,
      topAttributionFeatures: example.top_contributors.slice(0, 5).map((c) => ({
        feature: c.feature,
        contribution: c.contribution,
        direction: c.direction,
      })),
      occlusionAvailable: example.temporal_summary.per_timestep.length > 0,
      evidenceOrigin: "MIXED",
    },
    note: "Research-derived: real Feature 13 (attack-progression probability), Feature 14 (MITRE evidence, observed state), and Feature 15 (attribution) values for this VALIDATION sequence.",
  };
}

let examplesCache: Promise<ExplanationExample[]> | null = null;

export function getResearchDerivedInputs(): Promise<MitigationInput[]> {
  if (!examplesCache) examplesCache = getExplanationExamples();
  return examplesCache.then((examples) => examples.map(buildMitigationInputFromExample));
}

export function getDemonstrationScenarios(): MitigationScenario[] {
  return MITIGATION_SCENARIOS;
}

export function getPolicyConfig() {
  return MITIGATION_POLICY_CONFIG;
}
