import { FORECAST_HORIZON_METRICS, type ForecastHorizonMetric } from "../data/forecastingData";
import {
  LSTM_MODEL_CONFIG,
  TEST_OUTLIER_DIAGNOSTICS,
  EXAMPLE_SEQUENCE_TRACE,
  type HorizonOutlierDiagnostic,
  type ExampleSequencePoint,
} from "../data/lstmWorldModelData";

/**
 * Data access for the Forecasting page. The underlying metrics are small
 * (a few dozen numbers from Feature 12's k_step_forecast_horizon_metrics.csv
 * and k_step_forecast_metrics.json), so they are bundled as typed constants
 * rather than fetched JSON - but every value is still returned through this
 * async service layer, matching the seam used by networkStateService.ts, so
 * a future FastAPI backend can replace the implementation here without any
 * change to consuming components.
 */

export interface LstmModelConfig {
  modelType: string;
  objective: string;
  inputDimensionality: number;
  historySeconds: number;
  outputDimensionality: number;
  forecastHorizons: readonly number[];
  hiddenSize: number;
  numLayers: number;
  dropout: number;
  parameterCount: number;
  rolloutMethod: string;
}

export function getLstmModelConfig(): Promise<LstmModelConfig> {
  return Promise.resolve(LSTM_MODEL_CONFIG);
}

export function getForecastHorizonMetrics(): Promise<ForecastHorizonMetric[]> {
  return Promise.resolve(FORECAST_HORIZON_METRICS);
}

export function getTestOutlierDiagnostics(): Promise<HorizonOutlierDiagnostic[]> {
  return Promise.resolve(TEST_OUTLIER_DIAGNOSTICS);
}

export function getExampleSequenceTrace(): Promise<{
  sequenceId: number;
  split: string;
  inputEndTimestamp: string;
  forecastTargetLabel: string;
  points: ExampleSequencePoint[];
  note: string;
}> {
  return Promise.resolve(EXAMPLE_SEQUENCE_TRACE);
}
