import type { ReactNode } from "react";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { AttackProgressionMetric } from "../../data/attackProgressionData";
import "./KStepSummary.css";

interface KStepSummaryProps {
  metrics: AttackProgressionMetric[];
}

const NA = <span className="k-step-summary__na">— Not available</span>;

function pct(value: number | null): ReactNode {
  if (value === null) return NA;
  return `${(value * 100).toFixed(1)}%`;
}

function num(value: number | null): ReactNode {
  if (value === null) return NA;
  return value.toFixed(3);
}

function buildColumns(): DataTableColumn<AttackProgressionMetric>[] {
  return [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "rocAuc", header: "ROC-AUC", align: "right", render: (r) => num(r.rocAuc) },
    { key: "prAuc", header: "PR-AUC", align: "right", render: (r) => num(r.prAuc) },
    { key: "precision", header: "Precision", align: "right", render: (r) => pct(r.precision) },
    { key: "recall", header: "Recall", align: "right", render: (r) => pct(r.recall) },
    { key: "f1", header: "F1", align: "right", render: (r) => num(r.f1) },
    { key: "fpr", header: "FPR", align: "right", render: (r) => pct(r.fpr) },
  ];
}

export default function KStepSummary({ metrics }: KStepSummaryProps) {
  const validation = metrics.filter((m) => m.partition === "validation");
  const fullPipeline = validation.filter((m) => m.mode === "full_pipeline").sort((a, b) => a.horizon - b.horizon);
  const oracle = validation.filter((m) => m.mode === "oracle_diagnostic").sort((a, b) => a.horizon - b.horizon);

  return (
    <div className="k-step-summary">
      <div className="k-step-summary__block">
        <h4 className="k-step-summary__block-title k-step-summary__block-title--pipeline">
          Full Pipeline (deployable path: LSTM-forecast state → classifier)
        </h4>
        <DataTable columns={buildColumns()} rows={fullPipeline} getRowKey={(r) => `fp-${r.horizon}`} />
      </div>
      <div className="k-step-summary__block">
        <h4 className="k-step-summary__block-title k-step-summary__block-title--oracle">
          Oracle Diagnostic (upper bound: ground-truth future state → classifier, not deployable)
        </h4>
        <DataTable columns={buildColumns()} rows={oracle} getRowKey={(r) => `or-${r.horizon}`} />
      </div>
      <p className="k-step-summary__note">
        Both are evaluated on the mixed-class VALIDATION partition (development-stage evaluation) - the
        chronological TEST partition has no Infiltration sequences, so these metrics cannot be computed
        there (see Test Limitation below).
      </p>
    </div>
  );
}
