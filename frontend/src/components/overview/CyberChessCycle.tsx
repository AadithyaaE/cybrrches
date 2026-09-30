import Card from "../ui/Card";
import { IconChevronRight } from "../ui/icons";
import "./CyberChessCycle.css";

interface CycleStep {
  label: string;
  done: boolean;
  note: string;
}

const steps: CycleStep[] = [
  { label: "OBSERVE", done: true, note: "Network state S(t)" },
  { label: "IDENTIFY", done: true, note: "Anomaly & MITRE evidence" },
  { label: "PREDICT", done: true, note: "K-step forecasting" },
  { label: "MITIGATE", done: true, note: "Simulation" },
  { label: "VERIFY", done: true, note: "Simulation" },
];

export default function CyberChessCycle() {
  return (
    <Card className="cycle-card">
      <div className="cycle-card__header">
        <h2 className="cycle-card__title">The CyberChess Cycle</h2>
        <p className="cycle-card__subtitle">
          Observe network behaviour, identify anomalies, predict future state, then mitigate and verify.
        </p>
      </div>
      <div className="cycle-row">
        {steps.map((step, idx) => (
          <div className="cycle-row__item" key={step.label}>
            <div className={"cycle-step" + (step.done ? " cycle-step--done" : " cycle-step--pending")}>
              <div className="cycle-step__marker" aria-hidden="true">
                {step.done ? (
                  <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M4 10.5l3.5 3.5L16 6" />
                  </svg>
                ) : (
                  <span className="cycle-step__marker-dot" />
                )}
              </div>
              <div className="cycle-step__text">
                <span className="cycle-step__label">{step.label}</span>
                <span className="cycle-step__note">{step.note}</span>
              </div>
            </div>
            {idx < steps.length - 1 && (
              <span className="cycle-row__arrow" aria-hidden="true">
                <IconChevronRight />
              </span>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}
