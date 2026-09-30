import StatusBadge from "../ui/StatusBadge";
import type { DatasetSummaryRow } from "../../data/frozenGeneralizationData";
import "./DatasetOverview.css";

interface DatasetOverviewProps {
  datasetSummary: DatasetSummaryRow[];
}

export default function DatasetOverview({ datasetSummary }: DatasetOverviewProps) {
  return (
    <div className="dataset-overview">
      <div className="dataset-overview__dev">
        <StatusBadge label="Development Dataset" tone="info" dot={false} />
        <p>
          Thursday-01-03-2018 (the single capture day used for all training, validation, and the internal
          chronological test split - Features 1-15). Not re-shown here; see Network State / Models pages.
        </p>
      </div>

      {datasetSummary.map((row) => (
        <div className="dataset-overview__card" key={row.day}>
          <div className="dataset-overview__card-header">
            <StatusBadge label="Frozen External Evaluation" tone="warning" dot={false} />
            <h4>{row.day}</h4>
          </div>
          <div className="dataset-overview__grid">
            <div>
              <span className="dataset-overview__field-label">Sequences / Windows</span>
              <span className="dataset-overview__field-value">
                {row.nSequences.toLocaleString()} / {row.nWindows.toLocaleString()}
              </span>
            </div>
            <div>
              <span className="dataset-overview__field-label">Attack Prevalence (windows)</span>
              <span className="dataset-overview__field-value">{row.attackPrevalenceWindowsPct.toFixed(2)}%</span>
            </div>
            <div>
              <span className="dataset-overview__field-label">Training-Compatible View</span>
              <span className="dataset-overview__field-value">{row.trainingCompatibleViewApplicable ? "Applicable" : "Not applicable"}</span>
            </div>
          </div>
          <div className="dataset-overview__labels">
            <span className="dataset-overview__field-label">Label Distribution (raw rows)</span>
            <div className="dataset-overview__label-chips">
              {Object.entries(row.labelDistribution).map(([label, value]) => (
                <span className="dataset-overview__label-chip" key={label}>
                  {label}: {value}
                </span>
              ))}
            </div>
          </div>
          <p className="dataset-overview__timestamp">
            <strong>Timestamp coverage:</strong> {row.timestampRange}
          </p>
          <p className="dataset-overview__caveat">{row.qualityCaveat}</p>
        </div>
      ))}
    </div>
  );
}
