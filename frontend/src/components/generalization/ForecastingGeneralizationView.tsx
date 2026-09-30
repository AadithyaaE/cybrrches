import { useState } from "react";
import MiniBarChart from "../ui/MiniBarChart";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { ForecastingGeneralizationRow, ExternalDay } from "../../data/frozenGeneralizationData";
import { EXTERNAL_DAYS } from "../../data/frozenGeneralizationData";
import "./ForecastingGeneralizationView.css";

interface ForecastingGeneralizationViewProps {
  rows: ForecastingGeneralizationRow[];
}

const HORIZONS = [1, 2, 3, 5];

export default function ForecastingGeneralizationView({ rows }: ForecastingGeneralizationViewProps) {
  const [day, setDay] = useState<ExternalDay>(EXTERNAL_DAYS[0]);
  const dayRows = rows.filter((r) => r.day === day).sort((a, b) => a.horizon - b.horizon);

  const columns: DataTableColumn<ForecastingGeneralizationRow>[] = [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "n", header: "n", align: "right", render: (r) => r.n.toLocaleString() },
    { key: "mse", header: "MSE", align: "right", render: (r) => r.mse.toFixed(3) },
    { key: "rmse", header: "RMSE", align: "right", render: (r) => r.rmse.toFixed(3) },
    { key: "mae", header: "MAE", align: "right", render: (r) => r.mae.toFixed(3) },
  ];

  return (
    <div className="forecasting-generalization-view">
      <div className="forecasting-generalization-view__tabs">
        {EXTERNAL_DAYS.map((d) => (
          <button
            key={d}
            type="button"
            className={`forecasting-generalization-view__tab ${day === d ? "forecasting-generalization-view__tab--active" : ""}`}
            onClick={() => setDay(d)}
          >
            {d}
          </button>
        ))}
      </div>

      <div className="forecasting-generalization-view__chart">
        <MiniBarChart
          categories={HORIZONS.map((h) => `K=${h}`)}
          series={[
            {
              label: "RMSE",
              color: "var(--accent-violet)",
              values: HORIZONS.map((h) => dayRows.find((r) => r.horizon === h)?.rmse ?? null),
            },
          ]}
        />
      </div>

      <DataTable columns={columns} rows={dayRows} getRowKey={(r) => `${r.day}-${r.horizon}`} />

      <p className="forecasting-generalization-view__note">
        This evaluates whether the World Model's future-state forecasting transfers to different capture
        conditions - it is a regression error on the 68-dimensional state vector, not an attack-detection
        metric. A lower or higher forecasting error here does not automatically mean better or worse attack
        detection; see "Forecasting / Detection Connection" below for the specific diagnostic evidence on
        that relationship.
      </p>
    </div>
  );
}
