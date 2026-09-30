import { IconChevronRight, IconNetwork, IconForecast, IconAttack } from "../ui/icons";
import "./CyberChessWorkflow.css";

const STEPS = [
  { label: "Observed State", sub: "S(t) - 68 features", icon: <IconNetwork /> },
  { label: "Future State Forecast", sub: "LSTM World Model, K seconds ahead", icon: <IconForecast /> },
  { label: "Attack Progression Assessment", sub: "Frozen classifier on the forecast state", icon: <IconAttack /> },
];

export default function CyberChessWorkflow() {
  return (
    <div className="cyberchess-workflow">
      {STEPS.map((step, i) => (
        <div className="cyberchess-workflow__step-wrap" key={step.label}>
          <div className="cyberchess-workflow__step">
            <span className="cyberchess-workflow__icon">{step.icon}</span>
            <span className="cyberchess-workflow__label">{step.label}</span>
            <span className="cyberchess-workflow__sub">{step.sub}</span>
          </div>
          {i < STEPS.length - 1 && <IconChevronRight className="cyberchess-workflow__arrow" />}
        </div>
      ))}
    </div>
  );
}
