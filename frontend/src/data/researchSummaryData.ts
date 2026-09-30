/**
 * Pipeline stage checklist for the Overview "Research Summary" section.
 * Reflects the completed Feature 1-16 Python research pipeline (see
 * results/ and data/processed/ for the underlying artifacts of each stage).
 */

export interface ResearchStage {
  label: string;
  detail: string;
}

export const RESEARCH_STAGES: ResearchStage[] = [
  { label: "Network State", detail: "S(t): 68-feature, 1-second aggregated state" },
  { label: "Temporal World Model", detail: "LSTM, 10-second history window" },
  { label: "Attack Prediction", detail: "Next-state attack classifier" },
  { label: "Future Forecasting", detail: "K-step ahead state forecasting (K = 1, 2, 3, 5)" },
  { label: "Explainability", detail: "Layer-C linear attribution + Layer-D temporal occlusion" },
  { label: "MITRE Evidence", detail: "Rule-based stage-to-technique evidence mapping" },
  { label: "Frozen Generalization", detail: "Frozen-pipeline evaluation on 3 external capture days" },
];
