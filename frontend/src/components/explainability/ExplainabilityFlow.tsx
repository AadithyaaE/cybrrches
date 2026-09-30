import { IconChevronRight, IconNetwork, IconForecast, IconAttack, IconExplain, IconMitre } from "../ui/icons";
import "./ExplainabilityFlow.css";

const STEPS = [
  { label: "Observed Network State", sub: "S(t) - 68 features", icon: <IconNetwork /> },
  { label: "Forecast", sub: "LSTM World Model, K seconds ahead", icon: <IconForecast /> },
  { label: "Attack Progression", sub: "Frozen classifier P(Infiltration)", icon: <IconAttack /> },
  { label: "Explainability Evidence", sub: "Layer C (exact) + Layer D (approximate)", icon: <IconExplain /> },
  { label: "MITRE Mapping", sub: "Deterministic rule-based stage evidence", icon: <IconMitre /> },
];

export default function ExplainabilityFlow() {
  return (
    <div className="explainability-flow">
      {STEPS.map((step, i) => (
        <div className="explainability-flow__step-wrap" key={step.label}>
          <div className="explainability-flow__step">
            <span className="explainability-flow__icon">{step.icon}</span>
            <span className="explainability-flow__label">{step.label}</span>
            <span className="explainability-flow__sub">{step.sub}</span>
          </div>
          {i < STEPS.length - 1 && <IconChevronRight className="explainability-flow__arrow" />}
        </div>
      ))}
    </div>
  );
}
