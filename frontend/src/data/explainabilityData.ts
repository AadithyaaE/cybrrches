/**
 * Source: results/explainability/explainability_metrics.json (Feature 15).
 * global_feature_importance_top15 is a GLOBAL summary (mean/std of Layer-C
 * linear-model contributions across all 3492 VALIDATION sequences).
 *
 * Temporal attribution summary is DERIVED in this file (not stored pre-aggregated
 * in the artifact): mean(|contribution|) per relative time step, aggregated across
 * results/explainability/temporal_attributions.csv (20 sample sequences x 68
 * features x 10 time steps = 1360 rows per time step). It shows which time steps
 * in the 10-second window carry the most occlusion-diagnostic weight.
 */

export interface GlobalFeatureImportance {
  feature: string;
  meanContribution: number;
  meanAbsContribution: number;
  stdContribution: number;
}

export const GLOBAL_FEATURE_IMPORTANCE_TOP: GlobalFeatureImportance[] = [
  { feature: "Protocol_6", meanContribution: -1.085958019649996, meanAbsContribution: 1.085958019649996, stdContribution: 0.13965698364129714 },
  { feature: "Pkt Len Std", meanContribution: 0.07584917993099204, meanAbsContribution: 0.392978693410832, stdContribution: 0.4989725844852928 },
  { feature: "Fwd IAT Mean", meanContribution: 0.09059108640520339, meanAbsContribution: 0.3294269602578516, stdContribution: 0.46291870871572144 },
  { feature: "Flow IAT Mean", meanContribution: -0.08836747070556975, meanAbsContribution: 0.32463298370756943, stdContribution: 0.4575111786724708 },
  { feature: "Fwd IAT Max", meanContribution: 0.06579340496519416, meanAbsContribution: 0.3068812658450505, stdContribution: 0.4387179313539578 },
  { feature: "Fwd Pkt Len Std", meanContribution: -0.06724777173454674, meanAbsContribution: 0.2020351854027961, stdContribution: 0.24352085538035328 },
  { feature: "Flow Duration", meanContribution: -0.025633121648981617, meanAbsContribution: 0.17243579758626465, stdContribution: 0.22712240755458193 },
  { feature: "Fwd IAT Tot", meanContribution: 0.025642841326054544, meanAbsContribution: 0.15858320196894013, stdContribution: 0.20458133640611878 },
];

export interface TemporalAttributionStep {
  timeStep: string;
  meanAbsContribution: number;
  n: number;
}

export const TEMPORAL_ATTRIBUTION_SUMMARY: TemporalAttributionStep[] = [
  { timeStep: "t-9", meanAbsContribution: 0.000276, n: 1360 },
  { timeStep: "t-8", meanAbsContribution: 0.000359, n: 1360 },
  { timeStep: "t-7", meanAbsContribution: 0.000364, n: 1360 },
  { timeStep: "t-6", meanAbsContribution: 0.000475, n: 1360 },
  { timeStep: "t-5", meanAbsContribution: 0.000504, n: 1360 },
  { timeStep: "t-4", meanAbsContribution: 0.000784, n: 1360 },
  { timeStep: "t-3", meanAbsContribution: 0.00084, n: 1360 },
  { timeStep: "t-2", meanAbsContribution: 0.000732, n: 1360 },
  { timeStep: "t-1", meanAbsContribution: 0.000971, n: 1360 },
  { timeStep: "t", meanAbsContribution: 0.001026, n: 1360 },
];

export const EXPLAINABILITY_SAMPLE_SIZE = 20;

export const LLM_EXPLAINER_STATUS = {
  enabled: false,
  label: "LLM: OPTIONAL / DISABLED BY DEFAULT",
  scopeStatement:
    "LLM is an interpretation layer and does not modify model outputs.",
  detail:
    "DisabledLLMExplainer active (no LLM_API_KEY configured); prompts were built and grounding-validated, but no network call was made.",
};

export const EXPLAINABILITY_SOURCE = {
  global: "results/explainability/explainability_metrics.json",
  temporal: "results/explainability/temporal_attributions.csv (aggregated in-app)",
};
