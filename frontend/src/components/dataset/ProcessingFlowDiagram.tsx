import { IconChevronRight, IconDatasets, IconNetwork, IconLayers, IconForecast, IconAttack, IconMitre, IconExplain } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./ProcessingFlowDiagram.css";

const STEPS = [
  { label: "Input", sub: "CSV / PCAP", icon: <IconDatasets />, implemented: true },
  { label: "Feature Mapping", sub: "Direct / Derived / Missing", icon: <IconNetwork />, implemented: true },
  { label: "Network State", sub: "68-dimensional S(t)", icon: <IconLayers />, implemented: false },
  { label: "World Model", sub: "Frozen LSTM", icon: <IconLayers />, implemented: false },
  { label: "Forecast", sub: "K-step rollout", icon: <IconForecast />, implemented: false },
  { label: "Attack Analysis", sub: "P(Infiltration)", icon: <IconAttack />, implemented: false },
  { label: "MITRE", sub: "Evidence mapping", icon: <IconMitre />, implemented: false },
  { label: "Explainability", sub: "Attribution", icon: <IconExplain />, implemented: false },
];

export default function ProcessingFlowDiagram() {
  return (
    <div className="processing-flow-diagram">
      <div className="processing-flow-diagram__row">
        {STEPS.map((step, i) => (
          <div className="processing-flow-diagram__step-wrap" key={step.label}>
            <div className={`processing-flow-diagram__step ${step.implemented ? "processing-flow-diagram__step--implemented" : ""}`}>
              <span className="processing-flow-diagram__icon">{step.icon}</span>
              <span className="processing-flow-diagram__label">{step.label}</span>
              <span className="processing-flow-diagram__sub">{step.sub}</span>
              {!step.implemented && <StatusBadge label="Implemented in later features" tone="neutral" dot={false} />}
            </div>
            {i < STEPS.length - 1 && <IconChevronRight className="processing-flow-diagram__arrow" />}
          </div>
        ))}
      </div>
      <p className="processing-flow-diagram__note">
        This feature (Feature 9) implements Input and Feature Mapping only. Network State through
        Explainability are already implemented as separate research-evaluation pages (Overview, Network
        State, Forecasting, Attack Analysis, MITRE, Explainability) using frozen research artifacts - they
        are not yet wired to accept a freshly uploaded dataset as live input.
      </p>
    </div>
  );
}
