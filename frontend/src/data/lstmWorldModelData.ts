/**
 * LSTM World Model configuration and forecast-rollout diagnostics for the
 * Forecasting page (Frontend Feature 4). Kept separate from
 * data/forecastingData.ts (Frontend Feature 2) so that file is never touched.
 *
 * Sources (all read directly from the research artifacts, real values only):
 *   - results/lstm/lstm_config.json
 *   - results/lstm/lstm_metrics.json
 *   - results/forecasting/k_step_forecast_config.json
 *   - results/forecasting/k_step_forecast_metrics.json (outlier_diagnostics, error_accumulation)
 *   - results/forecasting/k_step_forecast_predictions_summary.csv (one real example sequence)
 */

export const LSTM_MODEL_CONFIG = {
  modelType: "LSTM World Model",
  objective: "Learn P(S(t+1) | S(t-9), ..., S(t)) - next network-state regression, not attack classification.",
  inputDimensionality: 68,
  historySeconds: 10,
  outputDimensionality: 68,
  forecastHorizons: [1, 2, 3, 5] as const,
  hiddenSize: 128,
  numLayers: 2,
  dropout: 0.2,
  parameterCount: 242244,
  rolloutMethod:
    "Free-running recursive: the model's own predictions feed back into its input history; ground truth is never reinserted after step 1.",
};

export interface HorizonOutlierDiagnostic {
  horizon: 1 | 2 | 3 | 5;
  split: "train" | "validation" | "test";
  worstSampleSequenceId: number;
  worstSampleMse: number;
  dominantFeature: string;
  officialMse: number;
  diagnosticMseExcludingWorstSample: number;
}

export const TEST_OUTLIER_DIAGNOSTICS: HorizonOutlierDiagnostic[] = [
  { horizon: 1, split: "test", worstSampleSequenceId: 19842, worstSampleMse: 51833.4609375, dominantFeature: "Pkt Len Var", officialMse: 18.77292251586914, diagnosticMseExcludingWorstSample: 0.7190222144126892 },
  { horizon: 2, split: "test", worstSampleSequenceId: 19841, worstSampleMse: 51838.3046875, dominantFeature: "Pkt Len Var", officialMse: 19.76334571838379, diagnosticMseExcludingWorstSample: 0.7473709583282471 },
  { horizon: 3, split: "test", worstSampleSequenceId: 19840, worstSampleMse: 51836.2578125, dominantFeature: "Pkt Len Var", officialMse: 20.75524139404297, diagnosticMseExcludingWorstSample: 0.7569757699966431 },
  { horizon: 5, split: "test", worstSampleSequenceId: 19838, worstSampleMse: 51841.734375, dominantFeature: "Pkt Len Var", officialMse: 22.912490844726562, diagnosticMseExcludingWorstSample: 0.7676916122436523 },
];

export const OUTLIER_DOMINANT_FEATURE_TRAIN_RANGE = {
  feature: "Pkt Len Var",
  trainScaledRange: [-1.1165771484375, 11.80485725402832] as [number, number],
  testWorstSampleActualScaledValue: 1874.0142822265625,
};

/**
 * One real test-partition sequence (sequence_id 19279, a Benign example - the
 * TEST target-window label distribution is 100% Benign, so no Infilteration
 * example exists in TEST) tracked across all 4 horizons. Not the pathological
 * outlier sequence - chosen because it is present at every horizon with finite,
 * non-outlier error, to make the concept of recursive rollout concrete.
 */
export interface ExampleSequencePoint {
  horizon: 1 | 2 | 3 | 5;
  sampleMse: number;
  sampleMae: number;
}

export const EXAMPLE_SEQUENCE_TRACE = {
  sequenceId: 19279,
  split: "test" as const,
  inputEndTimestamp: "2018-03-01 11:38:32",
  forecastTargetLabel: "Benign",
  points: [
    { horizon: 1, sampleMse: 0.195463, sampleMae: 0.289574 },
    { horizon: 2, sampleMse: 0.345466, sampleMae: 0.405902 },
    { horizon: 3, sampleMse: 0.727346, sampleMae: 0.493098 },
    { horizon: 5, sampleMse: 0.413284, sampleMae: 0.376317 },
  ] as ExampleSequencePoint[],
  note:
    "This single sequence's error does not increase at every step (K=5 is lower than K=3 here) - individual sequences vary. The observed increase in test RMSE/MSE with horizon is an aggregate trend across all 2,871 test sequences, not a guarantee for every individual sequence.",
};

export const FORECASTING_ARTIFACT_SOURCES = {
  lstmConfig: "results/lstm/lstm_config.json",
  lstmMetrics: "results/lstm/lstm_metrics.json",
  kStepConfig: "results/forecasting/k_step_forecast_config.json",
  kStepMetrics: "results/forecasting/k_step_forecast_metrics.json",
  kStepHorizonMetrics: "results/forecasting/k_step_forecast_horizon_metrics.csv",
  kStepPredictionsSummary: "results/forecasting/k_step_forecast_predictions_summary.csv",
};
