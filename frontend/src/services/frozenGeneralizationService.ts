import {
  DATASET_SUMMARY,
  BINARY_ATTACK_METRICS,
  CONFUSION_MATRICES,
  ATTACK_FAMILY_METRICS,
  FORECASTING_GENERALIZATION,
  WED21_LSTM_OUTLIER,
  PREDICTION_SUMMARY_SAMPLE,
  DATA_QUALITY_CAVEATS,
  NOT_PROVEN,
  DOES_PROVIDE,
  MODEL_LABELS,
  type DatasetSummaryRow,
  type BinaryAttackMetricRow,
  type ConfusionMatrix,
  type AttackFamilyMetricRow,
  type ForecastingGeneralizationRow,
  type PredictionSummaryRow,
  type ExternalDay,
} from "../data/frozenGeneralizationData";

/**
 * Data access for the Generalization page (Frontend Feature 8). All data is
 * small (a few dozen rows total across 3 external capture days), so it is
 * bundled as typed constants (see data/frozenGeneralizationData.ts, read
 * directly from results/frozen_generalization/) rather than fetched, but
 * exposed as async functions matching the seam used by the other services.
 */

export interface FrozenGeneralizationOverview {
  datasetSummary: DatasetSummaryRow[];
  binaryAttackMetrics: BinaryAttackMetricRow[];
  confusionMatrices: Record<ExternalDay, Record<string, ConfusionMatrix>>;
  attackFamilyMetrics: AttackFamilyMetricRow[];
  forecastingGeneralization: ForecastingGeneralizationRow[];
  wed21LstmOutlier: typeof WED21_LSTM_OUTLIER;
  predictionSummarySample: PredictionSummaryRow[];
  dataQualityCaveats: string[];
  notProven: string[];
  doesProvide: string[];
  modelLabels: Record<string, string>;
}

export function getFrozenGeneralizationOverview(): Promise<FrozenGeneralizationOverview> {
  return Promise.resolve({
    datasetSummary: DATASET_SUMMARY,
    binaryAttackMetrics: BINARY_ATTACK_METRICS,
    confusionMatrices: CONFUSION_MATRICES,
    attackFamilyMetrics: ATTACK_FAMILY_METRICS,
    forecastingGeneralization: FORECASTING_GENERALIZATION,
    wed21LstmOutlier: WED21_LSTM_OUTLIER,
    predictionSummarySample: PREDICTION_SUMMARY_SAMPLE,
    dataQualityCaveats: DATA_QUALITY_CAVEATS,
    notProven: NOT_PROVEN,
    doesProvide: DOES_PROVIDE,
    modelLabels: MODEL_LABELS,
  });
}
