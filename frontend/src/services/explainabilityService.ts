import {
  GLOBAL_FEATURE_IMPORTANCE_TOP15,
  CLASSIFIER_ATTRIBUTION_GROUNDING_CHECK_MAX_DIFF,
  EVALUATION_CHECKS,
  LEAKAGE_CHECKS,
  REPRODUCIBILITY,
  SAMPLE_SEQUENCE_IDS,
  EXPLAINABILITY_CONFIG,
  ATTRIBUTION_METHODS,
  LLM_STATUS,
  LLM_PROMPT_RULES,
  EXPLAINABILITY_LIMITATIONS,
} from "../data/explainabilityFeature15Data";
import type { ExplanationExample } from "../types/explainability";

/**
 * Data access for the Explainability page (Frontend Feature 7). Aggregate
 * metrics/config/checks are small and bundled as typed constants (see
 * data/explainabilityFeature15Data.ts, read directly from
 * results/explainability/). Per-sequence local explanations are fetched from
 * a static JSON snapshot that is a byte-for-byte copy of the real Feature 15
 * artifact (results/explainability/explanation_examples.json) - no
 * transformation, nothing invented.
 */

export interface ExplainabilityOverview {
  globalFeatureImportance: typeof GLOBAL_FEATURE_IMPORTANCE_TOP15;
  classifierAttributionGroundingCheckMaxDiff: number;
  evaluationChecks: Record<string, boolean>;
  leakageChecks: Record<string, boolean>;
  reproducibility: typeof REPRODUCIBILITY;
  sampleSequenceIds: number[];
  config: typeof EXPLAINABILITY_CONFIG;
  attributionMethods: typeof ATTRIBUTION_METHODS;
  llmStatus: typeof LLM_STATUS;
  llmPromptRules: string[];
  limitations: string[];
}

export function getExplainabilityOverview(): Promise<ExplainabilityOverview> {
  return Promise.resolve({
    globalFeatureImportance: GLOBAL_FEATURE_IMPORTANCE_TOP15,
    classifierAttributionGroundingCheckMaxDiff: CLASSIFIER_ATTRIBUTION_GROUNDING_CHECK_MAX_DIFF,
    evaluationChecks: EVALUATION_CHECKS,
    leakageChecks: LEAKAGE_CHECKS,
    reproducibility: REPRODUCIBILITY,
    sampleSequenceIds: SAMPLE_SEQUENCE_IDS,
    config: EXPLAINABILITY_CONFIG,
    attributionMethods: ATTRIBUTION_METHODS,
    llmStatus: LLM_STATUS,
    llmPromptRules: LLM_PROMPT_RULES,
    limitations: EXPLAINABILITY_LIMITATIONS,
  });
}

let examplesCache: Promise<ExplanationExample[]> | null = null;

export function getExplanationExamples(): Promise<ExplanationExample[]> {
  if (!examplesCache) {
    examplesCache = fetch("/data/explainability_examples.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load explanation examples: ${res.status}`);
      return res.json();
    });
  }
  return examplesCache;
}
