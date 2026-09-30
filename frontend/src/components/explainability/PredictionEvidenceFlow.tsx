import { IconChevronRight, IconAttack, IconExplain, IconMitre, IconResearch } from "../ui/icons";
import "./PredictionEvidenceFlow.css";

const STEPS = [
  { label: "Model Prediction", sub: "Frozen LSTM + classifier, P(Infiltration)", icon: <IconAttack /> },
  { label: "Feature Attribution", sub: "Layer C (exact) + Layer D (approximate)", icon: <IconExplain /> },
  { label: "Structured Evidence", sub: "Contributions, timesteps, MITRE context", icon: <IconMitre /> },
  { label: "Optional NL Explanation", sub: "LLM layer - disabled by default", icon: <IconResearch /> },
];

export default function PredictionEvidenceFlow() {
  return (
    <div className="prediction-evidence-flow">
      <div className="prediction-evidence-flow__row">
        {STEPS.map((step, i) => (
          <div className="prediction-evidence-flow__step-wrap" key={step.label}>
            <div className="prediction-evidence-flow__step">
              <span className="prediction-evidence-flow__icon">{step.icon}</span>
              <span className="prediction-evidence-flow__label">{step.label}</span>
              <span className="prediction-evidence-flow__sub">{step.sub}</span>
            </div>
            {i < STEPS.length - 1 && <IconChevronRight className="prediction-evidence-flow__arrow" />}
          </div>
        ))}
      </div>
      <p className="prediction-evidence-flow__note">
        The LLM is <strong>not</strong> the prediction engine. Every prediction, probability, and evidence
        score in this pipeline is produced by deterministic statistical/ML models and rule engines before
        the (currently disabled) LLM layer would ever run. The LLM, when enabled, can only render already-
        computed structured evidence into natural language - it cannot generate or alter any number shown
        on this page.
      </p>
    </div>
  );
}
