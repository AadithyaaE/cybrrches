import StatusBadge from "../ui/StatusBadge";
import type { MitigationDecision } from "../../types/mitigation";
import { MITIGATION_POLICY_CONFIG } from "../../data/mitigationPolicyConfig";
import "./RecommendedAction.css";

interface RecommendedActionProps {
  decision: MitigationDecision;
}

function durationForLevel(level: MitigationDecision["level"]): number | null {
  if (level === "RATE_LIMIT") return MITIGATION_POLICY_CONFIG.simulation.rateLimitDurationSeconds.value;
  if (level === "TEMPORARY_BLOCK") return MITIGATION_POLICY_CONFIG.simulation.blockDurationSeconds.value;
  return null;
}

export default function RecommendedAction({ decision }: RecommendedActionProps) {
  const duration = durationForLevel(decision.level);

  return (
    <div className="recommended-action">
      <div className="recommended-action__row">
        <div className="recommended-action__field">
          <span className="recommended-action__label">Action</span>
          <span className="recommended-action__value">{decision.action}</span>
        </div>
        <div className="recommended-action__field">
          <span className="recommended-action__label">Reversibility</span>
          <StatusBadge label={decision.reversible ? "Reversible" : "Not Reversible"} tone={decision.reversible ? "success" : "danger"} dot={false} />
        </div>
        {duration !== null && (
          <div className="recommended-action__field">
            <span className="recommended-action__label">Duration (if applied)</span>
            <span className="recommended-action__value">{duration.toLocaleString()} seconds</span>
          </div>
        )}
      </div>

      <div className="recommended-action__why">
        <h4>Why?</h4>
        <ol>
          {decision.supportingEvidence.length === 0 ? (
            <li>No specific evidence contributed to this decision.</li>
          ) : (
            decision.supportingEvidence.map((e) => <li key={e}>{e}</li>)
          )}
        </ol>
      </div>

      <p className="recommended-action__simulation-note">
        This is a SIMULATION-ONLY recommendation. No real traffic, firewall rule, or routing configuration is
        affected by displaying or applying this action.
      </p>
    </div>
  );
}
