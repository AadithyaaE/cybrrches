import StatusBadge from "../ui/StatusBadge";
import type { InferenceReadiness } from "../../types/dataset";
import "./InferenceReadinessPanel.css";

interface InferenceReadinessPanelProps {
  readiness: InferenceReadiness;
}

export default function InferenceReadinessPanel({ readiness }: InferenceReadinessPanelProps) {
  return (
    <div className="inference-readiness-panel">
      <div className={`inference-readiness-panel__verdict ${readiness.ready ? "inference-readiness-panel__verdict--ready" : "inference-readiness-panel__verdict--not-ready"}`}>
        <StatusBadge label={readiness.ready ? "Ready for CyberChess Inference" : "Not Ready"} tone={readiness.ready ? "success" : "danger"} />
      </div>

      <ul className="inference-readiness-panel__checks">
        {readiness.checks.map((check) => (
          <li key={check.label} className="inference-readiness-panel__check">
            <span className={`inference-readiness-panel__check-mark ${check.passed ? "inference-readiness-panel__check-mark--pass" : "inference-readiness-panel__check-mark--fail"}`}>
              {check.passed ? "✓" : "✗"}
            </span>
            <div>
              <span className="inference-readiness-panel__check-label">{check.label}</span>
              <p className="inference-readiness-panel__check-detail">{check.detail}</p>
            </div>
          </li>
        ))}
      </ul>

      {!readiness.ready && readiness.missingSummary.length > 0 && (
        <div className="inference-readiness-panel__missing">
          <span className="inference-readiness-panel__missing-label">Missing:</span>
          <ul>
            {readiness.missingSummary.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        </div>
      )}

      <p className="inference-readiness-panel__disclaimer">
        "Ready for CyberChess inference" means the uploaded data can be mapped into the 68-dimensional
        network state representation - it is not a prediction, an attack probability, or a detection
        result. No inference is run by this page.
      </p>
    </div>
  );
}
