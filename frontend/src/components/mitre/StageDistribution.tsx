import MiniBarChart from "../ui/MiniBarChart";
import DataTable, { type DataTableColumn } from "../ui/DataTable";
import "./StageDistribution.css";

interface StageDistributionProps {
  distribution: Record<string, number>;
  totalAuditRecords: number;
  sampleCounts: { sequences: number; evidencePointsPerSequence: number };
}

interface StageDistributionRow {
  stage: string;
  count: number;
  pct: number;
}

export default function StageDistribution({ distribution, totalAuditRecords, sampleCounts }: StageDistributionProps) {
  const rows: StageDistributionRow[] = Object.entries(distribution)
    .map(([stage, count]) => ({ stage, count, pct: (count / totalAuditRecords) * 100 }))
    .sort((a, b) => b.count - a.count);

  const columns: DataTableColumn<StageDistributionRow>[] = [
    { key: "stage", header: "Primary Stage", render: (r) => r.stage },
    { key: "count", header: "Count", align: "right", render: (r) => r.count.toLocaleString() },
    { key: "pct", header: "Share of Records", align: "right", render: (r) => `${r.pct.toFixed(1)}%` },
  ];

  return (
    <div className="stage-distribution">
      <div className="stage-distribution__chart">
        <MiniBarChart
          categories={rows.map((r) => r.stage)}
          series={[{ label: "Primary stage count", color: "var(--accent-cyan)", values: rows.map((r) => r.count) }]}
          valueFormatter={(v) => v.toLocaleString()}
        />
      </div>
      <DataTable columns={columns} rows={rows} getRowKey={(r) => r.stage} />
      <p className="stage-distribution__note">
        This is the real distribution of the deterministic mapper's <strong>primary_stage</strong> output
        across all {totalAuditRecords.toLocaleString()} audit records ({sampleCounts.sequences.toLocaleString()}{" "}
        validation sequences x {sampleCounts.evidencePointsPerSequence} evidence points each: the observed
        current state plus the K=1/2/3/5 forecast states). This is a distribution of rule outputs, not an
        attack-attribution accuracy figure - there is no ATT&amp;CK ground truth to score it against.
      </p>
    </div>
  );
}
