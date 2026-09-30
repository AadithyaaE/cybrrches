/**
 * Source: results/forecasting/k_step_forecast_horizon_metrics.csv (Feature 12).
 * K-step LSTM world-model forecasting error, chronological train/validation/test split.
 * This is a DEVELOPMENT / TEST EVALUATION, not a live-inference metric.
 */

export type ForecastSplit = "train" | "validation" | "test";

export interface ForecastHorizonMetric {
  horizon: 1 | 2 | 3 | 5;
  split: ForecastSplit;
  mse: number;
  rmse: number;
  mae: number;
  n: number;
}

export const FORECAST_HORIZONS: Array<1 | 2 | 3 | 5> = [1, 2, 3, 5];

export const FORECAST_HORIZON_METRICS: ForecastHorizonMetric[] = [
  { horizon: 1, split: "train", mse: 0.8312842845916748, rmse: 0.911747932434082, mae: 0.444521427154541, n: 15660 },
  { horizon: 1, split: "validation", mse: 0.7961475253105164, rmse: 0.8922709822654724, mae: 0.46167224645614624, n: 3492 },
  { horizon: 1, split: "test", mse: 18.77292251586914, rmse: 4.332773208618164, mae: 0.47180914878845215, n: 2871 },

  { horizon: 2, split: "train", mse: 0.8631632924079895, rmse: 0.9290658235549927, mae: 0.45521673560142517, n: 15144 },
  { horizon: 2, split: "validation", mse: 0.8329390287399292, rmse: 0.9126549363136292, mae: 0.4731771647930145, n: 3388 },
  { horizon: 2, split: "test", mse: 19.76334571838379, rmse: 4.445598602294922, mae: 0.48139914870262146, n: 2726 },

  { horizon: 3, split: "train", mse: 0.881429135799408, rmse: 0.9388445615768433, mae: 0.4597964584827423, n: 14651 },
  { horizon: 3, split: "validation", mse: 0.843924880027771, rmse: 0.9186538457870483, mae: 0.4771537184715271, n: 3288 },
  { horizon: 3, split: "test", mse: 20.75524139404297, rmse: 4.555791854858398, mae: 0.48362573981285095, n: 2592 },

  { horizon: 5, split: "train", mse: 0.8977382779121399, rmse: 0.9474905133247375, mae: 0.46620988845825195, n: 13727 },
  { horizon: 5, split: "validation", mse: 0.8701534271240234, rmse: 0.9328201413154602, mae: 0.48244526982307434, n: 3092 },
  { horizon: 5, split: "test", mse: 22.912490844726562, rmse: 4.786699295043945, mae: 0.4895744323730469, n: 2341 },
];

export const FORECASTING_SOURCE = "results/forecasting/k_step_forecast_horizon_metrics.csv";
