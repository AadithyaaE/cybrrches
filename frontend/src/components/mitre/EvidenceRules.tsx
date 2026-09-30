import DataTable, { type DataTableColumn } from "../ui/DataTable";
import StatusBadge from "../ui/StatusBadge";
import type { MitreRule, EvidenceFeatureAvailability } from "../../data/mitreRulesData";
import "./EvidenceRules.css";

interface EvidenceRulesProps {
  rules: MitreRule[];
  evidenceFeatureAvailability: EvidenceFeatureAvailability[];
}

const STAGE_ORDER = ["Discovery", "Command and Control", "Exfiltration", "Impact", "Reconnaissance", "Initial Access", "Lateral Movement"];

export default function EvidenceRules({ rules, evidenceFeatureAvailability }: EvidenceRulesProps) {
  const availabilityColumns: DataTableColumn<EvidenceFeatureAvailability>[] = [
    { key: "feature", header: "Evidence Field", render: (r) => r.feature },
    { key: "observed", header: "Observed Availability", align: "right", render: (r) => `${r.observedAvailabilityPct.toFixed(1)}%` },
    { key: "k1", header: "Predicted K=1", align: "right", render: (r) => `${r.predictedAvailabilityPctByHorizon["1"].toFixed(1)}%` },
    { key: "k2", header: "Predicted K=2", align: "right", render: (r) => `${r.predictedAvailabilityPctByHorizon["2"].toFixed(1)}%` },
    { key: "k3", header: "Predicted K=3", align: "right", render: (r) => `${r.predictedAvailabilityPctByHorizon["3"].toFixed(1)}%` },
    { key: "k5", header: "Predicted K=5", align: "right", render: (r) => `${r.predictedAvailabilityPctByHorizon["5"].toFixed(1)}%` },
  ];

  return (
    <div className="evidence-rules">
      {STAGE_ORDER.map((stage) => {
        const stageRules = rules.filter((r) => r.stage === stage);
        return (
          <div className="evidence-rules__stage" key={stage}>
            <h4 className="evidence-rules__stage-title">{stage}</h4>
            {stageRules.map((rule) => (
              <div className="evidence-rules__rule" key={rule.ruleId}>
                <div className="evidence-rules__rule-header">
                  <span className="evidence-rules__rule-id">{rule.ruleId}</span>
                  <StatusBadge label={`${rule.triggerCount.toLocaleString()} triggers`} tone="neutral" dot={false} />
                  <StatusBadge label={`+${rule.scoreContribution} pts`} tone="info" dot={false} />
                </div>
                <ul className="evidence-rules__conditions">
                  {rule.conditions.map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
                <p className="evidence-rules__explanation">{rule.explanation}</p>
                <p className="evidence-rules__limitation">
                  <strong>Limitation:</strong> {rule.limitation}
                </p>
                {rule.supportingFeatures.length === 0 ? (
                  <p className="evidence-rules__supporting-empty">No supporting features available for this rule.</p>
                ) : (
                  <p className="evidence-rules__supporting">
                    Supporting features: {rule.supportingFeatures.join(", ")}
                  </p>
                )}
              </div>
            ))}
          </div>
        );
      })}

      <div className="evidence-rules__availability">
        <h4 className="evidence-rules__stage-title">
          Evidence Field Availability: Observed vs. Predicted (LSTM Forecast) State
        </h4>
        <p className="evidence-rules__availability-note">
          Several evidence fields are Feature 6 window metadata, not part of the 68-dimensional LSTM state
          vector, so they are 0% available on PREDICTED evidence at every horizon - those rules can only
          fire on OBSERVED evidence.
        </p>
        <DataTable columns={availabilityColumns} rows={evidenceFeatureAvailability} getRowKey={(r) => r.feature} />
      </div>
    </div>
  );
}
