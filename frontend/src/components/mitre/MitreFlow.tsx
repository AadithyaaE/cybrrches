import { IconChevronRight, IconNetwork, IconForecast, IconAttack, IconMitre } from "../ui/icons";
import "./MitreFlow.css";

const STEPS = [
  { label: "Observed Network Behaviour", sub: "S(t) - 68 features", icon: <IconNetwork /> },
  { label: "Future State Forecast", sub: "LSTM World Model, K seconds ahead", icon: <IconForecast /> },
  { label: "Attack Progression", sub: "Frozen classifier P(Infiltration)", icon: <IconAttack /> },
  { label: "ATT&CK Evidence Mapping", sub: "Deterministic rule-based stage evidence", icon: <IconMitre /> },
];

export default function MitreFlow() {
  return (
    <div className="mitre-flow">
      {STEPS.map((step, i) => (
        <div className="mitre-flow__step-wrap" key={step.label}>
          <div className="mitre-flow__step">
            <span className="mitre-flow__icon">{step.icon}</span>
            <span className="mitre-flow__label">{step.label}</span>
            <span className="mitre-flow__sub">{step.sub}</span>
          </div>
          {i < STEPS.length - 1 && <IconChevronRight className="mitre-flow__arrow" />}
        </div>
      ))}
    </div>
  );
}
