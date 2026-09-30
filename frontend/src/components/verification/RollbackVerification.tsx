import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { RollbackVerification as RollbackVerificationType, RollbackFieldCheck } from "../../types/verification";
import "./RollbackVerification.css";

interface RollbackVerificationProps {
  rollback: RollbackVerificationType;
}

export default function RollbackVerification({ rollback }: RollbackVerificationProps) {
  if (!rollback.performed) {
    return (
      <div className="rollback-verification">
        <StatusBadge label="NOT PERFORMED" tone="neutral" />
        <p className="rollback-verification__note">
          Rollback has not been requested for this input yet. Rollback verification will check whether the
          simulated state after rolling back exactly matches the original baseline.
        </p>
      </div>
    );
  }

  const columns: DataTableColumn<RollbackFieldCheck>[] = [
    { key: "field", header: "Field", render: (r) => r.field },
    { key: "before", header: "Baseline (Before Mitigation)", align: "right", render: (r) => r.before.toLocaleString() },
    { key: "restored", header: "State After Rollback", align: "right", render: (r) => (r.restored === null ? "—" : r.restored.toLocaleString()) },
    { key: "matches", header: "Matches", render: (r) => <StatusBadge label={r.matches ? "Exact Match" : "Mismatch"} tone={r.matches ? "success" : "danger"} dot={false} /> },
  ];

  return (
    <div className="rollback-verification">
      <StatusBadge label={rollback.label} tone={rollback.exactRestoration ? "success" : "danger"} />
      <DataTable columns={columns} rows={rollback.fieldChecks} getRowKey={(r) => r.field} />
      <p className="rollback-verification__note">
        This checks deterministic equality between the original baseline traffic state and the simulated
        state produced by Feature 10's rollback function. This is a simulation-only check, not a real-world
        rollback test.
      </p>
    </div>
  );
}
