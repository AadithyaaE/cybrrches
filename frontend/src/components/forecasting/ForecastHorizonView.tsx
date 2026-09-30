import MiniBarChart from "../ui/MiniBarChart";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import { FORECAST_HORIZONS, type ForecastHorizonMetric } from "../../data/forecastingData";
import "./ForecastHorizonView.css";

interface ForecastHorizonViewProps {
  metrics: ForecastHorizonMetric[];
}

export default function ForecastHorizonView({ metrics }: ForecastHorizonViewProps) {
  const categories = FORECAST_HORIZONS.map((h) => `K=${h}`);
  const rmseByHorizon = (split: ForecastHorizonMetric["split"]) =>
    FORECAST_HORIZONS.map((h) => {
      const row = metrics.find((m) => m.horizon === h && m.split === split);
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
    <div className="forecast-horizon-view">
      <div className="forecast-horizon-view__chart">
        <MiniBarChart
          categories={categories}
          series={[
            { label: "Train RMSE", color: "var(--status-neutral)", values: rmseByHorizon("train") },
            { label: "Validation RMSE", color: "var(--accent-cyan)", values: rmseByHorizon("validation") },
            { label: "Test RMSE", color: "var(--accent-violet)", values: rmseByHorizon("test") },
          ]}
        />
      </div>
      <DataTable columns={columns} rows={metrics} getRowKey={(r) => `${r.horizon}-${r.split}`} />
    </div>
  );
}
