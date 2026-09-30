import DataTable, { type DataTableColumn } from "../ui/DataTable";
import type { AttackFamilyMetricRow } from "../../data/frozenGeneralizationData";
import "./AttackFamilyResults.css";

interface AttackFamilyResultsProps {
  rows: AttackFamilyMetricRow[];
}

export default function AttackFamilyResults({ rows }: AttackFamilyResultsProps) {
  const columns: DataTableColumn<AttackFamilyMetricRow>[] = [
    { key: "day", header: "Capture Day", render: (r) => r.day },
    { key: "attackFamily", header: "Attack Family", render: (r) => r.attackFamily },
    { key: "n", header: "Sequences", align: "right", render: (r) => r.nSequences.toLocaleString() },
    { key: "detected", header: "Detected as Attack", align: "right", render: (r) => r.detectedAsAttackCount.toLocaleString() },
    { key: "fn", header: "False Negatives", align: "right", render: (r) => r.falseNegatives.toLocaleString() },
    { key: "recall", header: "Detection Recall", align: "right", render: (r) => `${(r.detectionRecall * 100).toFixed(2)}%` },
  ];

  return (
    <div className="attack-family-results">
      <DataTable columns={columns} rows={rows} getRowKey={(r) => `${r.day}-${r.attackFamily}`} />
      <p className="attack-family-results__note">
        These are observed results for specific external attack families, not a ranked scoreboard. Each row
        is a binary anomaly-detection recall (predicted non-Benign) against the frozen classifier - the
        classifier was only ever trained on a benign-vs-Infiltration view, so it was never trained to
        distinguish FTP-BruteForce, SSH-Bruteforce, or DDoS specifically. A 100% recall result is not
        described as "perfect" or "best," and a 0.22% recall result is not described as a "failure of the
        whole system" - both are simply what was observed for that specific family on that specific day.
      </p>
    </div>
  );
}
