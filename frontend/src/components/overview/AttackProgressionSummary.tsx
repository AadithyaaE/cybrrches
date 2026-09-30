import DataTable, { type DataTableColumn } from "../ui/DataTable";
import SummarySection from "./SummarySection";
import {
  ATTACK_PROGRESSION_METRICS,
  type AttackProgressionMetric,
} from "../../data/attackProgressionData";
import "./AttackProgressionSummary.css";

const NA = <span className="attack-progression-summary__na">— Not available</span>;

function pct(value: number | null) {
  if (value === null) return NA;
  return `${(value * 100).toFixed(1)}%`;
}

export default function AttackProgressionSummary() {
  const columns: DataTableColumn<AttackProgressionMetric>[] = [
    { key: "horizon", header: "Horizon", render: (r) => `K=${r.horizon}` },
    { key: "mode", header: "Mode", render: (r) => (r.mode === "full_pipeline" ? "Full Pipeline" : "Oracle Diagnostic") },
    { key: "partition", header: "Partition", render: (r) => r.partition },
    { key: "n", header: "n", align: "right", render: (r) => r.n.toLocaleString() },
    { key: "nPositive", header: "Positives", align: "right", render: (r) => r.nPositive.toLocaleString() },
    { key: "rocAuc", header: "ROC-AUC", align: "right", render: (r) => (r.rocAuc === null ? NA : r.rocAuc.toFixed(3)) },
    { key: "prAuc", header: "PR-AUC", align: "right", render: (r) => (r.prAuc === null ? NA : r.prAuc.toFixed(3)) },
    { key: "precision", header: "Precision", align: "right", render: (r) => pct(r.precision) },
    { key: "recall", header: "Recall", align: "right", render: (r) => pct(r.recall) },
    { key: "f1", header: "F1", align: "right", render: (r) => (r.f1 === null ? NA : r.f1.toFixed(3)) },
    { key: "fpr", header: "FPR", align: "right", render: (r) => pct(r.fpr) },
  ];

  return (
    <SummarySection
      title="Attack Progression Summary"
      evalLabel="Validation Evaluation"
      description="K-step attack-progression-probability metrics from the Feature 11 classifier fed by the LSTM world model (Full Pipeline) versus the ground-truth future state (Oracle Diagnostic). These are held-out evaluation metrics, not live attack probabilities."
    >
      <DataTable
        columns={columns}
        rows={ATTACK_PROGRESSION_METRICS}
        getRowKey={(r) => `${r.horizon}-${r.mode}-${r.partition}`}
      />
      <p className="attack-progression-summary__note">
        The TEST partition contains 0 positive sequences at every horizon, so ROC-AUC, PR-AUC, Recall
        and F1 are undefined there (shown as "— Not available"). Precision = 0.0% on TEST is a
        mathematically defined value on an all-negative set and is shown as-is, not treated as missing.
      </p>
    </SummarySection>
  );
}
