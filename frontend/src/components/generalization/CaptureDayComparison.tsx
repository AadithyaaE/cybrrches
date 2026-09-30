import { useState } from "react";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { BinaryAttackMetricRow, ExternalDay } from "../../data/frozenGeneralizationData";
import { EXTERNAL_DAYS } from "../../data/frozenGeneralizationData";
import "./CaptureDayComparison.css";

interface CaptureDayComparisonProps {
  rows: BinaryAttackMetricRow[];
  modelLabels: Record<string, string>;
}

export default function CaptureDayComparison({ rows, modelLabels }: CaptureDayComparisonProps) {
  const [day, setDay] = useState<ExternalDay>(EXTERNAL_DAYS[0]);
  const dayRows = rows.filter((r) => r.day === day);

  const columns: DataTableColumn<BinaryAttackMetricRow>[] = [
    { key: "model", header: "Model", render: (r) => modelLabels[r.model] ?? r.model },
    { key: "accuracy", header: "Accuracy", align: "right", render: (r) => `${(r.accuracy * 100).toFixed(1)}%` },
    { key: "precision", header: "Precision", align: "right", render: (r) => `${(r.precision * 100).toFixed(1)}%` },
    { key: "recall", header: "Recall", align: "right", render: (r) => `${(r.recall * 100).toFixed(1)}%` },
    { key: "f1", header: "F1", align: "right", render: (r) => r.f1.toFixed(3) },
    { key: "rocAuc", header: "ROC-AUC", align: "right", render: (r) => r.rocAuc.toFixed(3) },
    { key: "fpr", header: "FPR", align: "right", render: (r) => `${(r.fpr * 100).toFixed(1)}%` },
  ];

  return (
    <div className="capture-day-comparison">
      <div className="capture-day-comparison__tabs">
        {EXTERNAL_DAYS.map((d) => (
          <button
            key={d}
            type="button"
            className={`capture-day-comparison__tab ${day === d ? "capture-day-comparison__tab--active" : ""}`}
            onClick={() => setDay(d)}
          >
            {d}
          </button>
        ))}
      </div>
      <DataTable columns={columns} rows={dayRows} getRowKey={(r) => r.model} />
      <p className="capture-day-comparison__note">
        All metrics shown are real, defined values for this day (no metric was unavailable here). These four
        rows are not a ranking - they are four different real evaluation views of the same frozen models on
        the same held-out external data.
      </p>
    </div>
  );
}
