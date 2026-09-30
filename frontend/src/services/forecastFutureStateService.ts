import type { ForecastFutureStateSummary, ForecastFutureStateSample } from "../types/forecastFutureState";

/**
 * Data access for the "Future Network State" section of the Forecasting page
 * (Frontend Feature 4B). Backed by static JSON snapshots generated from the
 * EXISTING Feature 12 saved rollout predictions
 * (data/processed/forecasting/test_rollout_predictions.npy, shape (2871, 5, 68))
 * and the existing frozen, train-fitted preprocessing pipeline - no model was
 * retrained and no research-pipeline file was modified to produce this data.
 *
 * network_state_windows.json is a 32-sample subset of the 2,871 test
 * sequences, not the full artifact. Every value is a real saved model output
 * or a read-only transform/inverse-transform of one, never fabricated.
 */

let summaryCache: Promise<ForecastFutureStateSummary> | null = null;
let samplesCache: Promise<ForecastFutureStateSample[]> | null = null;

export function getForecastFutureStateSummary(): Promise<ForecastFutureStateSummary> {
  if (!summaryCache) {
    summaryCache = fetch("/data/forecast_future_states_summary.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load forecast future-state summary: ${res.status}`);
      return res.json();
    });
  }
  return summaryCache;
}

export function getForecastFutureStateSamples(): Promise<ForecastFutureStateSample[]> {
  if (!samplesCache) {
    samplesCache = fetch("/data/forecast_future_states.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load forecast future-state samples: ${res.status}`);
      return res.json();
    });
  }
  return samplesCache;
}
