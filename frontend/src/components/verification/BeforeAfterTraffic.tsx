import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { VerificationTrafficComparison } from "../../types/verification";
import "./BeforeAfterTraffic.css";

interface BeforeAfterTrafficProps {
  comparisons: VerificationTrafficComparison[];
}

export default function BeforeAfterTraffic({ comparisons }: BeforeAfterTrafficProps) {
  const columns: DataTableColumn<VerificationTrafficComparison>[] = [
    { key: "label", header: "Metric", render: (r) => r.label },
    { key: "before", header: "Before", align: "right", render: (r) => r.before.toLocaleString() },
    { key: "after", header: "After", align: "right", render: (r) => r.after.toLocaleString() },
    { key: "change", header: "Change", align: "right", render: (r) => `${r.percentChange >= 0 ? "+" : ""}${r.percentChange.toFixed(1)}%` },
    {
      key: "result",
      header: "Result",
      render: (r) =>
        r.objectiveResult === "INFO" ? (
          <StatusBadge label="Info" tone="neutral" dot={false} />
        ) : r.objectiveResult === "UNAVAILABLE" ? (
          <StatusBadge label="Unavailable" tone="neutral" dot={false} />
        ) : (
          <StatusBadge label={r.objectiveResult} tone={r.objectiveResult === "PASS" ? "success" : "danger"} dot={false} />
        ),
    },
  ];

  return (
    <div className="before-after-traffic">
      <StatusBadge label="SIMULATED TRAFFIC STATE" tone="warning" />
      <DataTable columns={columns} rows={comparisons} getRowKey={(r) => r.metric} />
      <p className="before-after-traffic__note">
        These figures are Feature 10's simulated arithmetic over an illustrative baseline, never real packet
        or flow measurements.
      </p>
    </div>
  );
}
