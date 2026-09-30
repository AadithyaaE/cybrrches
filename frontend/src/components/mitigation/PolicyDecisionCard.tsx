import StatusBadge from "../ui/StatusBadge";
import type { MitigationDecision, MitigationLevel, MitigationPolicyConfig } from "../../types/mitigation";
import "./PolicyDecisionCard.css";

interface PolicyDecisionCardProps {
  decision: MitigationDecision;
  policyConfig: MitigationPolicyConfig;
}

const LEVELS: MitigationLevel[] = ["MONITOR", "ALERT", "RATE_LIMIT", "TEMPORARY_BLOCK", "ESCALATE"];
const LEVEL_TONE: Record<MitigationLevel, "success" | "info" | "warning" | "danger" | "neutral"> = {
  MONITOR: "success",
  ALERT: "info",
  RATE_LIMIT: "warning",
  TEMPORARY_BLOCK: "danger",
  ESCALATE: "neutral",
};

export default function PolicyDecisionCard({ decision, policyConfig }: PolicyDecisionCardProps) {
  return (
    <div className="policy-decision-card">
      <div className="policy-decision-card__ladder">
        {LEVELS.map((level) => (
          <div
            key={level}
            className={`policy-decision-card__rung ${level === decision.level ? `policy-decision-card__rung--active policy-decision-card__rung--${LEVEL_TONE[level]}` : ""}`}
          >
            {level.replace(/_/g, " ")}
          </div>
        ))}
      </div>

      <div className="policy-decision-card__result">
        <StatusBadge label={decision.level.replace(/_/g, " ")} tone={LEVEL_TONE[decision.level]} />
        <p className="policy-decision-card__reason">{decision.reason}</p>
      </div>

      <div className="policy-decision-card__conditions">
        <h4>Triggering Conditions</h4>
        <ul>
          {decision.triggeringConditions.map((c) => (
            <li key={c.label} className={c.met ? "policy-decision-card__condition--met" : "policy-decision-card__condition--unmet"}>
              <span className="policy-decision-card__condition-mark">{c.met ? "✓" : "○"}</span>
              <span>
                <strong>{c.label}:</strong> {c.detail}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <details className="policy-decision-card__thresholds">
        <summary>Policy thresholds used (documented, demonstration-only)</summary>
        <ul>
          <li>
            <strong>{policyConfig.probabilityThresholds.elevated.name}:</strong> {policyConfig.probabilityThresholds.elevated.value} —{" "}
            {policyConfig.probabilityThresholds.elevated.rationale}
          </li>
          <li>
            <strong>{policyConfig.probabilityThresholds.high.name}:</strong> {policyConfig.probabilityThresholds.high.value} —{" "}
            {policyConfig.probabilityThresholds.high.rationale}
          </li>
          <li>
            <strong>{policyConfig.probabilityThresholds.veryHigh.name}:</strong> {policyConfig.probabilityThresholds.veryHigh.value} —{" "}
            {policyConfig.probabilityThresholds.veryHigh.rationale}
          </li>
          <li>
            <strong>{policyConfig.mitreSevereEvidence.name}:</strong> {policyConfig.mitreSevereEvidence.value} —{" "}
            {policyConfig.mitreSevereEvidence.rationale}
          </li>
          <li>
            <strong>{policyConfig.trendDelta.name}:</strong> {policyConfig.trendDelta.value} — {policyConfig.trendDelta.rationale}
          </li>
        </ul>
      </details>

      <p className="policy-decision-card__disclaimer">{decision.policyLabel}</p>
    </div>
  );
}
