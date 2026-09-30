import StatusBadge from "../ui/StatusBadge";
import type { MitigationInput } from "../../types/mitigation";
import "./MitigationEvidence.css";

interface MitigationEvidenceProps {
  input: MitigationInput;
}

export default function MitigationEvidence({ input }: MitigationEvidenceProps) {
  return (
    <div className="mitigation-evidence">
      <div className="mitigation-evidence__origin">
        <StatusBadge label={`Origin: ${input.evidence.evidenceOrigin}`} tone="info" dot={false} />
        <p>
          MITRE stage evidence reflects the <strong>observed</strong> current network state (Feature 14's
          "observed_t" evidence point); attack-progression probabilities reflect the LSTM's{" "}
          <strong>forecast</strong> future state (Feature 12/13). Attribution (Feature 15) explains the
          classifier's mapping from forecast state to probability - it does not explain the LSTM's internal
          computation.
        </p>
      </div>

      <div className="mitigation-evidence__section">
        <h4>Top Contributing Features {input.evidence.attributionAvailable ? "(Feature 15, exact classifier attribution)" : ""}</h4>
        {input.evidence.attributionAvailable && input.evidence.topAttributionFeatures.length > 0 ? (
          <ul className="mitigation-evidence__list">
            {input.evidence.topAttributionFeatures.map((f) => (
              <li key={f.feature}>
                <span className="mitigation-evidence__feature">{f.feature}</span>
                <StatusBadge label={f.direction} tone={f.direction === "attack" ? "danger" : "success"} dot={false} />
                <span className="mitigation-evidence__contribution">{f.contribution.toFixed(4)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mitigation-evidence__na">— Not available for this input.</p>
        )}
      </div>

      <div className="mitigation-evidence__section">
        <h4>All MITRE Stage Scores (Feature 14, rule-based evidence mapping)</h4>
        {input.evidence.allStageScores.length > 0 ? (
          <ul className="mitigation-evidence__list">
            {input.evidence.allStageScores.map((s) => (
              <li key={s.stage}>
                <span className="mitigation-evidence__feature">{s.stage}</span>
                <StatusBadge label={s.status} tone={s.status === "mapped" ? "success" : s.status === "candidate" ? "warning" : "neutral"} dot={false} />
                <span className="mitigation-evidence__contribution">{s.evidenceScore.toFixed(0)}/100</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mitigation-evidence__na">— Not available for this input.</p>
        )}
      </div>

      <p className="mitigation-evidence__link">
        See the Explainability and MITRE ATT&amp;CK pages for the full research context behind this
        evidence.
      </p>
    </div>
  );
}
