import MiniBarChart from "../ui/MiniBarChart";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import SummarySection from "./SummarySection";
import {
  FORECAST_HORIZONS,
  FORECAST_HORIZON_METRICS,
  type ForecastHorizonMetric,
} from "../../data/forecastingData";
import "./ForecastingSummary.css";

export default function ForecastingSummary() {
  const categories = FORECAST_HORIZONS.map((h) => `K=${h}`);
  const rmseByHorizon = (split: ForecastHorizonMetric["split"]) =>
    FORECAST_HORIZONS.map((h) => {
      const row = FORECAST_HORIZON_METRICS.find((m) => m.horizon === h && m.split === split);
      return row ? row.rmse : null;
    });

  const columns: DataTableColumn<ForecastHorizonMetric>[] = [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "split", header: "Split", render: (r) => r.split },
    { key: "mse", header: "MSE", align: "right", render: (r) => r.mse.toFixed(3) },
    { key: "rmse", header: "RMSE", align: "right", render: (r) => r.rmse.toFixed(3) },
    { key: "mae", header: "MAE", align: "right", render: (r) => r.mae.toFixed(3) },
    { key: "n", header: "n", align: "right", render: (r) => r.n.toLocaleString() },
  ];

  return (
    <SummarySection
      title="Forecasting Summary"
      evalLabel="Development / Test Evaluation"
      description="K-step LSTM world-model forecasting error (regression MSE/RMSE/MAE) across the chronological train / validation / test split. Not a live forecast."
    >
      <div className="forecasting-summary__chart">
        <MiniBarChart
          categories={categories}
          series={[
            { label: "Validation RMSE", color: "var(--accent-cyan)", values: rmseByHorizon("validation") },
            { label: "Test RMSE", color: "var(--accent-violet)", values: rmseByHorizon("test") },
          ]}
        />
      </div>
      <DataTable
        columns={columns}
        rows={FORECAST_HORIZON_METRICS}
        getRowKey={(r) => `${r.horizon}-${r.split}`}
      />
    </SummarySection>
  );
}
