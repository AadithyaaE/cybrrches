import StatusBadge from "../ui/StatusBadge";
import { EXAMPLE_AUDIT_RECORD, MIN_EVIDENCE_THRESHOLD_FOR_PRIMARY_STAGE } from "../../data/mitreRulesData";
import "./ExampleAuditRecord.css";

export default function ExampleAuditRecord() {
  const record = EXAMPLE_AUDIT_RECORD;

  return (
    <div className="example-audit-record">
      <div className="example-audit-record__header">
        <span>
          Real audit record - sequence #{record.sequenceId}, {record.evidencePoint}, {record.timestamp}
        </span>
        <StatusBadge label={`Primary stage: ${record.primaryStage}`} tone="info" dot={false} />
      </div>
      <div className="example-audit-record__grid">
        {record.stageScores.map((s) => (
          <div
            className={`example-audit-record__stage ${s.stage === record.primaryStage ? "example-audit-record__stage--primary" : ""}`}
            key={s.stage}
          >
            <span className="example-audit-record__stage-name">{s.stage}</span>
            <span className="example-audit-record__stage-score">{s.score.toFixed(0)} / 100</span>
            <span className="example-audit-record__stage-label">{s.label}</span>
            {s.triggeredRules.length > 0 && (
              <span className="example-audit-record__stage-rules">{s.triggeredRules.join(", ")}</span>
            )}
          </div>
        ))}
      </div>
      <p className="example-audit-record__note">
        This one real record shows how evidence scores across all 7 stages are always preserved (never
        deleted), even though only the highest-scoring stage above the {MIN_EVIDENCE_THRESHOLD_FOR_PRIMARY_STAGE}{" "}
        threshold becomes the "primary stage" for this evidence point.
      </p>
    </div>
  );
}
