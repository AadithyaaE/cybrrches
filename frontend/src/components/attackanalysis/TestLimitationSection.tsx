import type { ReactNode } from "react";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { AttackProgressionMetric } from "../../data/attackProgressionData";
import "./TestLimitationSection.css";

interface TestLimitationSectionProps {
  metrics: AttackProgressionMetric[];
}

const NA = <span className="test-limitation-section__na">— Not available</span>;

function format(value: number | null, asPct: boolean): ReactNode {
  if (value === null) return NA;
  return asPct ? `${(value * 100).toFixed(1)}%` : value.toFixed(3);
}

export default function TestLimitationSection({ metrics }: TestLimitationSectionProps) {
  const testRows = metrics
    .filter((m) => m.partition === "test" && m.mode === "full_pipeline")
    .sort((a, b) => a.horizon - b.horizon);

  const columns: DataTableColumn<AttackProgressionMetric>[] = [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "n", header: "n", align: "right", render: (r) => r.n.toLocaleString() },
    { key: "nPositive", header: "Positives (Infiltration)", align: "right", render: (r) => r.nPositive.toLocaleString() },
    { key: "rocAuc", header: "ROC-AUC", align: "right", render: (r) => format(r.rocAuc, false) },
    { key: "prAuc", header: "PR-AUC", align: "right", render: (r) => format(r.prAuc, false) },
    { key: "precision", header: "Precision", align: "right", render: (r) => format(r.precision, true) },
    { key: "recall", header: "Recall", align: "right", render: (r) => format(r.recall, true) },
    { key: "f1", header: "F1", align: "right", render: (r) => format(r.f1, false) },
    { key: "fpr", header: "FPR", align: "right", render: (r) => format(r.fpr, true) },
  ];

  return (
    <div className="test-limitation-section">
      <div className="test-limitation-section__banner">
        <StatusBadge label="Known Limitation" tone="danger" />
        <p>
          The held-out TEST partition contains <strong>zero Infiltration sequences</strong> at every
          horizon (0 positives out of 2,871 → 2,341 sequences). Attack-detection metrics that require both
          classes (ROC-AUC, PR-AUC, Recall, F1) are mathematically undefined here and are never estimated
          from a single class.
        </p>
      </div>
      <DataTable columns={columns} rows={testRows} getRowKey={(r) => `test-${r.horizon}`} />
      <p className="test-limitation-section__note">
        Precision = 0.0% is a real, mathematically defined value (every predicted-positive on an all-negative
        set is a false positive), not a missing value. FPR remains defined and available since it only
        depends on the negative class, which TEST does have. This is why Feature 13's evaluation is
        described as a validation/development-stage assessment, not a final generalization result.
      </p>
    </div>
  );
}
