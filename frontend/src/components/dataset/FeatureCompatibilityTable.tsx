import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { CompatibilityReport, FeatureMappingEntry, FeatureMappingKind } from "../../types/dataset";
import "./FeatureCompatibilityTable.css";

interface FeatureCompatibilityTableProps {
  compatibility: CompatibilityReport;
}

const KIND_TONE: Record<FeatureMappingKind, "success" | "info" | "danger" | "neutral"> = {
  DIRECT: "success",
  DERIVED: "info",
  MISSING: "danger",
  UNSUPPORTED: "neutral",
};

export default function FeatureCompatibilityTable({ compatibility }: FeatureCompatibilityTableProps) {
  const unsupportedEntries: FeatureMappingEntry[] = compatibility.unsupportedColumns.map((c) => ({
    feature: c,
    kind: "UNSUPPORTED",
    detail: "Present in the upload but not part of the CyberChess feature/state requirements. Ignored, not held against compatibility.",
  }));

  const allRows: FeatureMappingEntry[] = [...compatibility.direct, ...compatibility.derived, ...compatibility.missing, ...unsupportedEntries];

  const columns: DataTableColumn<FeatureMappingEntry>[] = [
    { key: "feature", header: "Feature / Column", render: (r) => r.feature },
    { key: "kind", header: "Status", render: (r) => <StatusBadge label={r.kind} tone={KIND_TONE[r.kind]} dot={false} /> },
    { key: "detail", header: "Detail", render: (r) => r.detail },
  ];

  return (
    <div className="feature-compatibility-table">
      <div className="feature-compatibility-table__summary">
        <div className="feature-compatibility-table__stat">
          <StatusBadge label={`${compatibility.direct.length} Direct`} tone="success" dot={false} />
        </div>
        <div className="feature-compatibility-table__stat">
          <StatusBadge label={`${compatibility.derived.length} Derived`} tone="info" dot={false} />
        </div>
        <div className="feature-compatibility-table__stat">
          <StatusBadge label={`${compatibility.missing.length} Missing`} tone="danger" dot={false} />
        </div>
        <div className="feature-compatibility-table__stat">
          <StatusBadge label={`${compatibility.unsupportedColumns.length} Unsupported/Unused`} tone="neutral" dot={false} />
        </div>
      </div>
      <DataTable columns={columns} rows={allRows} getRowKey={(r) => `${r.kind}-${r.feature}`} />
    </div>
  );
}
