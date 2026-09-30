import type { MitigationScenario } from "../types/mitigation";

/**
 * Demonstration policy scenarios — NOT research results. Every numeric value
 * here is hand-authored and deterministic, used only to exercise the policy
 * engine's rule cascade across its documented decision boundaries. These do
 * not resemble measured benchmark results and are never mixed with the real
 * Feature 13/14/15 records surfaced elsewhere in this page.
 *
 * Each scenario's `expectedLevelHint` documents what the policy engine
 * (services/mitigation/mitigationPolicy.ts) is expected to output for this
 * input, given its current documented rule cascade — it is illustrative
 * documentation, not a separate hardcoded decision; the live decision is
 * always (re)computed by the real engine at render time.
 */

const DEMO_NOTE = "Demonstration scenario — not a measured research result.";

export const MITIGATION_SCENARIOS: MitigationScenario[] = [
  {
    id: "scenario-monitor",
    title: "Low-confidence suspicious traffic",
    expectedLevelHint: "MONITOR",
    description: "Attack probability below the elevated threshold, weak/borderline MITRE evidence, no rising trend.",
    input: {
      source: "DEMONSTRATION_SCENARIO",
      id: "scenario-monitor",
      label: "Low-confidence suspicious traffic",
      attackProbability: 0.48,
      horizonProbabilities: { "1": 0.48, "2": 0.47, "3": 0.46, "5": 0.45 },
      evidence: {
        mitreStage: { stage: "Discovery", evidenceScore: 15, evidenceLabel: "LOW", status: "mapped", isPrimary: true },
        allStageScores: [{ stage: "Discovery", evidenceScore: 15, evidenceLabel: "LOW", status: "mapped", isPrimary: true }],
        attributionAvailable: false,
        topAttributionFeatures: [],
        occlusionAvailable: false,
        evidenceOrigin: "OBSERVED",
      },
      note: DEMO_NOTE,
    },
  },
  {
    id: "scenario-alert",
    title: "Elevated suspicious activity",
    expectedLevelHint: "ALERT",
    description: "Attack probability just above the elevated threshold, moderate MITRE evidence, flat trend.",
    input: {
      source: "DEMONSTRATION_SCENARIO",
      id: "scenario-alert",
      label: "Elevated suspicious activity",
      attackProbability: 0.53,
      horizonProbabilities: { "1": 0.53, "2": 0.535, "3": 0.53, "5": 0.54 },
      evidence: {
        mitreStage: { stage: "Discovery", evidenceScore: 35, evidenceLabel: "MEDIUM", status: "mapped", isPrimary: true },
        allStageScores: [{ stage: "Discovery", evidenceScore: 35, evidenceLabel: "MEDIUM", status: "mapped", isPrimary: true }],
        attributionAvailable: false,
        topAttributionFeatures: [],
        occlusionAvailable: false,
        evidenceOrigin: "OBSERVED",
      },
      note: DEMO_NOTE,
    },
  },
  {
    id: "scenario-rate-limit",
    title: "Sustained high-risk DDoS-like progression",
    expectedLevelHint: "RATE_LIMIT",
    description: "Attack probability near the population mean but rising across forecast horizons, combined with Impact-stage evidence.",
    input: {
      source: "DEMONSTRATION_SCENARIO",
      id: "scenario-rate-limit",
      label: "Sustained high-risk DDoS-like progression",
      attackProbability: 0.5,
      horizonProbabilities: { "1": 0.5, "2": 0.51, "3": 0.52, "5": 0.53 },
      evidence: {
        mitreStage: { stage: "Impact", evidenceScore: 45, evidenceLabel: "MEDIUM", status: "mapped", isPrimary: true },
        allStageScores: [{ stage: "Impact", evidenceScore: 45, evidenceLabel: "MEDIUM", status: "mapped", isPrimary: true }],
        attributionAvailable: false,
        topAttributionFeatures: [],
        occlusionAvailable: false,
        evidenceOrigin: "MIXED",
      },
      note: DEMO_NOTE,
    },
  },
  {
    id: "scenario-temporary-block",
    title: "Very high-risk controlled scenario",
    expectedLevelHint: "TEMPORARY_BLOCK",
    description: "Attack probability well above the very-high threshold, flat trend, severe Impact-stage MITRE evidence.",
    input: {
      source: "DEMONSTRATION_SCENARIO",
      id: "scenario-temporary-block",
      label: "Very high-risk controlled scenario",
      attackProbability: 0.65,
      horizonProbabilities: { "1": 0.65, "2": 0.655, "3": 0.65, "5": 0.66 },
      evidence: {
        mitreStage: { stage: "Impact", evidenceScore: 75, evidenceLabel: "HIGH", status: "mapped", isPrimary: true },
        allStageScores: [{ stage: "Impact", evidenceScore: 75, evidenceLabel: "HIGH", status: "mapped", isPrimary: true }],
        attributionAvailable: false,
        topAttributionFeatures: [],
        occlusionAvailable: false,
        evidenceOrigin: "MIXED",
      },
      note: DEMO_NOTE,
    },
  },
  {
    id: "scenario-escalate",
    title: "Ambiguous / high-impact situation requiring human decision",
    expectedLevelHint: "ESCALATE",
    description: "High attack probability and severe Impact-stage evidence, but the forecast trend is falling - the signals conflict.",
    input: {
      source: "DEMONSTRATION_SCENARIO",
      id: "scenario-escalate",
      label: "Ambiguous / high-impact situation requiring human decision",
      attackProbability: 0.6,
      horizonProbabilities: { "1": 0.6, "2": 0.58, "3": 0.56, "5": 0.55 },
      evidence: {
        mitreStage: { stage: "Impact", evidenceScore: 70, evidenceLabel: "HIGH", status: "mapped", isPrimary: true },
        allStageScores: [{ stage: "Impact", evidenceScore: 70, evidenceLabel: "HIGH", status: "mapped", isPrimary: true }],
        attributionAvailable: false,
        topAttributionFeatures: [],
        occlusionAvailable: false,
        evidenceOrigin: "MIXED",
      },
      note: DEMO_NOTE,
    },
  },
];
