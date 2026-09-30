import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import SummarySection from "./SummarySection";
import { MITRE_TECHNIQUE_MAP, type MitreMapping } from "../../data/mitreData";

export default function MitreSummary() {
  const columns: DataTableColumn<MitreMapping>[] = [
    { key: "stage", header: "Stage", render: (r) => r.stage },
    { key: "techniqueId", header: "Technique ID", render: (r) => r.techniqueId },
    { key: "techniqueName", header: "Technique Name", render: (r) => r.techniqueName },
    {
      key: "status",
      header: "Status",
      render: (r) =>
        r.candidate ? (
          <StatusBadge label="Candidate" tone="warning" dot={false} />
        ) : (
          <StatusBadge label="Mapped" tone="success" dot={false} />
        ),
    },
  ];

  return (
    <SummarySection
      title="MITRE ATT&CK Summary"
      evalLabel="Rule-Based Evidence Mapping"
      description="Deterministic, rule-based evidence mapping from observed network-behaviour stages to MITRE ATT&CK techniques. There is no ATT&CK ground truth in this dataset - this is evidence mapping, not verified technique attribution or accuracy."
    >
      <DataTable columns={columns} rows={MITRE_TECHNIQUE_MAP} getRowKey={(r) => r.techniqueId} />
    </SummarySection>
  );
}
