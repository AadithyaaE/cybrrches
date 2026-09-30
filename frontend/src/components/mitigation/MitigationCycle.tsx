import { IconChevronRight } from "../ui/icons";
import StatusBadge from "../ui/StatusBadge";
import "./MitigationCycle.css";

const STEPS = [
  { label: "OBSERVE", done: true, note: "Network state S(t)" },
  { label: "IDENTIFY", done: true, note: "MITRE evidence" },
  { label: "PREDICT", done: true, note: "K-step forecasting + attack progression" },
  { label: "MITIGATE", done: true, note: "This feature - demonstration policy + simulation" },
  { label: "VERIFY", done: false, note: "Feature 11 — implemented next" },
];

export default function MitigationCycle() {
  return (
    <div className="mitigation-cycle">
      {STEPS.map((step, i) => (
        <div className="mitigation-cycle__step-wrap" key={step.label}>
          <div className={`mitigation-cycle__step ${step.done ? "mitigation-cycle__step--done" : ""}`}>
            <span className="mitigation-cycle__marker">{step.done ? "✓" : "○"}</span>
            <span className="mitigation-cycle__label">{step.label}</span>
            <span className="mitigation-cycle__note">{step.note}</span>
            {!step.done && <StatusBadge label="Coming Soon" tone="neutral" dot={false} />}
          </div>
          {i < STEPS.length - 1 && <IconChevronRight className="mitigation-cycle__arrow" />}
        </div>
      ))}
    </div>
  );
}
