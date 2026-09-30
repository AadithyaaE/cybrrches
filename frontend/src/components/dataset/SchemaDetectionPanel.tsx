import StatusBadge from "../ui/StatusBadge";
import type { SchemaDetectionResult } from "../../services/dataset/schemaDetection";
import "./SchemaDetectionPanel.css";

interface SchemaDetectionPanelProps {
  detection: SchemaDetectionResult;
}

const CONFIDENCE_TONE = {
  exact: "success",
  strong: "success",
  partial: "warning",
  unrecognized: "danger",
} as const;

export default function SchemaDetectionPanel({ detection }: SchemaDetectionPanelProps) {
  return (
    <div className="schema-detection-panel">
      <div className="schema-detection-panel__header">
        <StatusBadge label={detection.confidence.toUpperCase()} tone={CONFIDENCE_TONE[detection.confidence]} />
        <span className="schema-detection-panel__family">{detection.family}</span>
      </div>
      <div className="schema-detection-panel__stats">
        <div>
          <span className="schema-detection-panel__stat-label">Overlap with known 80-column schema</span>
          <span className="schema-detection-panel__stat-value">
            {detection.overlapCount} / 80 ({(detection.overlapRatio * 100).toFixed(0)}%)
          </span>
        </div>
        <div>
          <span className="schema-detection-panel__stat-label">Unrecognized columns in upload</span>
          <span className="schema-detection-panel__stat-value">{detection.extraColumnCount}</span>
        </div>
      </div>
      <p className="schema-detection-panel__note">
        This is a header-based match against the known CSE-CIC-IDS2018 / CICFlowMeter column schema
        (research Feature 2-4). It is a schema-family identification, not proof of the data's real-world
        origin or quality - identity is never claimed from weak evidence.
      </p>
    </div>
  );
}
