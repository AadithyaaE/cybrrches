/**
 * Source (read directly, all values real): results/explainability/explainability_metrics.json,
 * results/explainability/explainability_config.json, results/explainability/explainability_report.txt,
 * results/explainability/llm_explanation_examples.json (Feature 15).
 *
 * Layer C (classifier attribution) is EXACT: LogisticRegression is linear, so
 * coef * value is an exact per-dimension contribution. Layer D (LSTM
 * occlusion) is APPROXIMATE: a perturbation diagnostic, not a closed-form
 * attribution - the two are never conflated or added together.
 */

export interface GlobalFeatureImportance {
  feature: string;
  meanContribution: number;
  meanAbsContribution: number;
  stdContribution: number;
}

/** Full real top-15 global feature importances (mean |Layer-C contribution| across all 3,492 VALIDATION sequences). */
export const GLOBAL_FEATURE_IMPORTANCE_TOP15: GlobalFeatureImportance[] = [
  { feature: "Protocol_6", meanContribution: -1.085958019649996, meanAbsContribution: 1.085958019649996, stdContribution: 0.13965698364129714 },
  { feature: "Pkt Len Std", meanContribution: 0.07584917993099204, meanAbsContribution: 0.392978693410832, stdContribution: 0.4989725844852928 },
  { feature: "Fwd IAT Mean", meanContribution: 0.09059108640520339, meanAbsContribution: 0.3294269602578516, stdContribution: 0.46291870871572144 },
  { feature: "Flow IAT Mean", meanContribution: -0.08836747070556975, meanAbsContribution: 0.32463298370756943, stdContribution: 0.4575111786724708 },
  { feature: "Fwd IAT Max", meanContribution: 0.06579340496519416, meanAbsContribution: 0.3068812658450505, stdContribution: 0.4387179313539578 },
  { feature: "Fwd Pkt Len Std", meanContribution: -0.06724777173454674, meanAbsContribution: 0.2020351854027961, stdContribution: 0.24352085538035328 },
  { feature: "Flow Duration", meanContribution: -0.025633121648981617, meanAbsContribution: 0.17243579758626465, stdContribution: 0.22712240755458193 },
  { feature: "Fwd IAT Tot", meanContribution: 0.025642841326054544, meanAbsContribution: 0.15858320196894013, stdContribution: 0.20458133640611878 },
  { feature: "Idle Max", meanContribution: -0.03279478106940833, meanAbsContribution: 0.15674107654567, stdContribution: 0.2208363592142063 },
  { feature: "Pkt Len Var", meanContribution: -0.011146266037745404, meanAbsContribution: 0.13543212784613315, stdContribution: 0.17781489337358716 },
  { feature: "Bwd Pkt Len Std", meanContribution: -0.024264767789963452, meanAbsContribution: 0.12922922364410866, stdContribution: 0.1615354810664283 },
  { feature: "Fwd IAT Min", meanContribution: -0.03440544031562871, meanAbsContribution: 0.12467730373339692, stdContribution: 0.1750460194436339 },
  { feature: "Fwd Pkt Len Max", meanContribution: 0.035052576177623036, meanAbsContribution: 0.11544424491671595, stdContribution: 0.1421070876761821 },
  { feature: "Bwd Pkt Len Max", meanContribution: -0.01693838224636856, meanAbsContribution: 0.0928946190211689, stdContribution: 0.11744318387487863 },
  { feature: "Pkt Len Max", meanContribution: 0.02038771813540515, meanAbsContribution: 0.0900170173902428, stdContribution: 0.11371818469447594 },
];

export const CLASSIFIER_ATTRIBUTION_GROUNDING_CHECK_MAX_DIFF = 1.5477235154603974e-7;

export const EVALUATION_CHECKS: Record<string, boolean> = {
  feature_name_integrity: true,
  temporal_position_integrity: true,
  contributions_finite: true,
  direction_matches_sign: true,
  topk_integrity: true,
  prediction_consistency: true,
  feature13_integration_integrity: true,
  feature14_integration_integrity: true,
  no_future_ground_truth_used_as_input: true,
  llm_prompt_grounded_in_structured_evidence: true,
  feature7_14_artifacts_unchanged: true,
};

export const LEAKAGE_CHECKS: Record<string, boolean> = {
  no_model_trained: true,
  no_scaler_fitted: true,
  no_classifier_fitted: true,
  lstm_not_retrained: true,
  llm_did_not_alter_prediction: true,
  llm_did_not_alter_probability: true,
  llm_did_not_alter_mitre_score: true,
  llm_did_not_alter_mitre_stage: true,
  no_future_ground_truth_used_as_input: true,
  feature7_14_artifacts_unchanged: true,
};

export const REPRODUCIBILITY = {
  pass1EqualsPass2: true,
  tolerance: "exact equality (deterministic occlusion/linear-model computation)",
};

export const SAMPLE_SEQUENCE_IDS = [
  15670, 15853, 16037, 16221, 16404, 16588, 16772, 16956, 17139, 17323,
  17507, 17691, 17874, 18058, 18242, 18426, 18609, 18793, 18977, 19161,
];

export const EXPLAINABILITY_CONFIG = {
  sampleSize: 20,
  samplingMethod: "evenly-spaced indices across VALIDATION (np.linspace), deterministic",
  evaluationSplit: "validation",
  whyNotTest: "TEST partition contains zero Infiltration samples (Feature 7-9 finding); VALIDATION is the mixed-class development/evaluation partition used by Features 11/13.",
  occlusionBaseline: "TRAIN-set mean state vector per feature dimension (computed once from data/processed/splits/train/X_sequences_scaled.npy).",
};

export const ATTRIBUTION_METHODS = {
  layerC: "Exact linear-model logit decomposition of the classifier (LogisticRegression is linear, so coef * value is an EXACT per-dimension contribution - no approximation needed).",
  layerDPerTimestep: "Whole-timestep occlusion (replace with TRAIN-mean baseline), measuring change in P(Infiltration).",
  layerDPerCell: "Per-(timestep,feature) occlusion, same baseline/measurement, computed only for the deterministic 20-sequence sample (expensive: 680 forward passes/sequence).",
};

export const LLM_STATUS = {
  provider: "disabled",
  anyLiveTextGenerated: false,
  statusNote: "DisabledLLMExplainer active (no LLM_API_KEY configured); prompts were built and grounding-validated, but no network call was made.",
  scopeStatement: "The LLM is an explanation-generation layer only. It does not determine the attack prediction, attack probability, MITRE stage, evidence score, risk score, or mitigation decision.",
};

/** Real constraints extracted verbatim from the actual LLM prompt template used (results/explainability/llm_explanation_examples.json). */
export const LLM_PROMPT_RULES: string[] = [
  "Use ONLY the supplied evidence. Do not invent facts, feature names, numbers, or contributions that are not present in the JSON you were given.",
  "Do not invent or alter feature contributions. Every numeric value you state must come directly from the supplied evidence, reproduced exactly (do not round differently or recompute).",
  'Do not convert an "evidence score" (0-100, MITRE stage evidence) into a probability or percentage. Report it as "evidence score: X/100", never as "X% likely".',
  'Distinguish PREDICTION from CONFIRMATION. A model prediction or a MITRE "evidence score" is not proof that an attack occurred. Use language such as "consistent with", "the model predicts", "evidence suggests" - never "confirmed", "proven", or "occurred".',
  "State uncertainty explicitly where the evidence itself states a limitation.",
  "Mention important telemetry limitations included in the evidence (e.g. missing IP-address data, TEST-partition class limitations) when they are present in the supplied evidence.",
  "Preserve numerical values exactly as given - do not round to a different precision or invent derived percentages.",
  "Do NOT recommend mitigation, remediation, or any defensive action. That is out of scope for this explanation.",
];

export const EXPLAINABILITY_LIMITATIONS: string[] = [
  "Classifier attribution (Layer C) is exact for the linear classifier but explains only the mapping from the LSTM's predicted state to P(Infiltration), not the LSTM's internal computation.",
  "Layer D occlusion is an approximation (perturbation-based), not an exact attribution, and is distinct from SHAP.",
  "Per-cell occlusion (680 forward passes/sequence) was restricted to a deterministic 20-sequence sample for computational cost reasons.",
  "Feature 13 probabilities beyond K=1 depend on the LSTM's free-running recursive rollout, which compounds regression error at longer horizons (documented in Feature 12).",
  "MITRE evidence scores (Feature 14) are explicitly NOT probabilities.",
  "Evaluated on VALIDATION only (TEST has zero Infiltration samples, per Feature 7-9).",
  "No LLM provider was configured in this run; the LLM layer's grounding logic was exercised on the prompt construction, but no live natural-language text was generated.",
  "Attribution shows model dependence (how much a feature/timestep moved the model's own output), not causal proof of real-world attacker behaviour.",
];

export const EXPLAINABILITY_SOURCES = {
  metrics: "results/explainability/explainability_metrics.json",
  config: "results/explainability/explainability_config.json",
  report: "results/explainability/explainability_report.txt",
  examples: "results/explainability/explanation_examples.json",
  llmExamples: "results/explainability/llm_explanation_examples.json",
};
