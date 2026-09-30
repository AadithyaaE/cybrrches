import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { StageTechnique, MappingStatus } from "../../data/mitreRulesData";
import "./AttackStageMap.css";

interface AttackStageMapProps {
  stageTechniques: StageTechnique[];
  stageStatus: Record<string, MappingStatus>;
  stageMaxScore: Record<string, number | null>;
}

export default function AttackStageMap({ stageTechniques, stageStatus, stageMaxScore }: AttackStageMapProps) {
  const columns: DataTableColumn<StageTechnique>[] = [
    { key: "stage", header: "Stage", render: (r) => r.stage },
    { key: "techniqueId", header: "Technique ID", render: (r) => r.techniqueId },
    { key: "techniqueName", header: "Technique Name (as stored in the artifact)", render: (r) => r.techniqueName },
    {
      key: "status",
      header: "Mapping Status",
      render: (r) =>
        stageStatus[r.stage] === "mapped" ? (
          <StatusBadge label="Mapped" tone="success" />
        ) : (
          <StatusBadge label="Candidate" tone="warning" />
        ),
    },
    {
      key: "maxScore",
      header: "Max Evidence Score",
      align: "right",
      render: (r) => {
        const max = stageMaxScore[r.stage];
        return max === 0 ? "0 / 100 (never fires)" : `${max} / 100`;
      },
    },
  ];

  return (
    <div className="attack-stage-map">
      <DataTable columns={columns} rows={stageTechniques} getRowKey={(r) => r.stage} />
      <p className="attack-stage-map__note">
        "Mapped" stages (Discovery, Command and Control, Exfiltration, Impact) can reach the full 0-100
        evidence-score range. "Candidate" stages (Reconnaissance, Initial Access, Lateral Movement) are
        explicitly capped below 100, or at 0 for Lateral Movement, because flow telemetry alone cannot
        establish attacker intent or confirm compromise for these stages on this dataset.
      </p>
    </div>
  );
}
