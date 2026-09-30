import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import SummarySection from "./SummarySection";
import {
  PER_ATTACK_FAMILY_METRICS,
  GENERALIZATION_KNOWN_FAILURE_FAMILY,
  type AttackFamilyGeneralization,
} from "../../data/generalizationData";
import "./GeneralizationSummary.css";

export default function GeneralizationSummary() {
  const columns: DataTableColumn<AttackFamilyGeneralization>[] = [
    { key: "day", header: "Capture Day", render: (r) => r.day },
    { key: "attackFamily", header: "Attack Family", render: (r) => r.attackFamily },
    { key: "n", header: "Sequences", align: "right", render: (r) => r.nSequences.toLocaleString() },
    { key: "detected", header: "Detected", align: "right", render: (r) => r.detectedAsAttackCount.toLocaleString() },
    {
      key: "recall",
      header: "Detection Recall",
      align: "right",
      render: (r) => (
        <span className={r.attackFamily === GENERALIZATION_KNOWN_FAILURE_FAMILY ? "generalization-summary__recall--failure" : undefined}>
          {(r.detectionRecall * 100).toFixed(2)}%
        </span>
      ),
    },
  ];

  return (
    <SummarySection
      title="Generalization Summary"
      evalLabel="Transfer / Generalization Diagnostic"
      description="The frozen (never retrained) pipeline evaluated on 3 external CSE-CIC-IDS2018 capture days it was not trained on. These are binary anomaly-detection recall figures, not attack-family classification results - the classifier was only ever trained on a benign-vs-Infiltration view."
    >
      <DataTable
        columns={columns}
        rows={PER_ATTACK_FAMILY_METRICS}
        getRowKey={(r) => `${r.day}-${r.attackFamily}`}
      />
      <div className="generalization-summary__callout">
        <StatusBadge label="Known Failure Case" tone="danger" />
        <p>
          {GENERALIZATION_KNOWN_FAILURE_FAMILY} on Wednesday-21-02-2018 is detected at only 0.22% recall
          (1 of 458 sequences) - a known, documented frozen-generalization failure, not a data or
          measurement error.
        </p>
      </div>
    </SummarySection>
  );
}
