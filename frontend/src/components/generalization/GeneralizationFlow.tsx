import { IconChevronRight, IconDatasets, IconLayers, IconNetwork, IconForecast, IconAttack, IconGeneralization } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./GeneralizationFlow.css";

const STEPS = [
  { label: "Development Data", sub: "Thursday-01-03-2018", icon: <IconDatasets /> },
  { label: "Frozen Models", sub: "No retraining beyond this point", icon: <IconLayers />, frozen: true },
  { label: "New Capture Day", sub: "Wed-28 / Wed-14 / Wed-21", icon: <IconDatasets /> },
  { label: "Network State", sub: "S(t) - 68 features", icon: <IconNetwork /> },
  { label: "Forecast", sub: "Frozen LSTM World Model", icon: <IconForecast /> },
  { label: "Attack Analysis", sub: "Frozen classifier", icon: <IconAttack /> },
  { label: "Evaluate Generalization", sub: "Metrics only, no fitting", icon: <IconGeneralization /> },
];

export default function GeneralizationFlow() {
  return (
    <div className="generalization-flow">
      <div className="generalization-flow__row">
        {STEPS.map((step, i) => (
          <div className="generalization-flow__step-wrap" key={step.label}>
            <div className={`generalization-flow__step ${step.frozen ? "generalization-flow__step--frozen" : ""}`}>
              <span className="generalization-flow__icon">{step.icon}</span>
              <span className="generalization-flow__label">{step.label}</span>
              <span className="generalization-flow__sub">{step.sub}</span>
              {step.frozen && <StatusBadge label="Not Retrained" tone="warning" dot={false} />}
            </div>
            {i < STEPS.length - 1 && <IconChevronRight className="generalization-flow__arrow" />}
          </div>
        ))}
      </div>
      <p className="generalization-flow__note">
        Everything from "Frozen Models" onward reuses the exact same trained weights and fitted
        preprocessing from the development capture - nothing is fit, trained, or tuned on any new capture
        day shown on this page.
      </p>
    </div>
  );
}
