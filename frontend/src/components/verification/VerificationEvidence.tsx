import StatusBadge from "../ui/StatusBadge";
import type { VerificationObjective } from "../../types/verification";
import "./VerificationEvidence.css";

interface VerificationEvidenceProps {
  objectives: VerificationObjective[];
}

export default function VerificationEvidence({ objectives }: VerificationEvidenceProps) {
  return (
    <div className="verification-evidence">
      {objectives.map((o) => (
        <div className="verification-evidence__item" key={o.key}>
          <div className="verification-evidence__header">
            <span className="verification-evidence__label">{o.label}</span>
            <StatusBadge label={o.result} tone={o.result === "PASS" ? "success" : o.result === "FAIL" ? "danger" : "neutral"} />
          </div>
          <div className="verification-evidence__row">
            <span className="verification-evidence__field-label">Expected:</span>
            <span>{o.expectedCondition}</span>
          </div>
          <div className="verification-evidence__row">
            <span className="verification-evidence__field-label">Actual:</span>
            <span>{o.actualResult}</span>
          </div>
          <div className="verification-evidence__row">
            <span className="verification-evidence__field-label">Reason:</span>
            <span>{o.reason}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
