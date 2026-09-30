import { IconChevronRight } from "../ui/icons";
import "./VerificationCycle.css";

const STEPS = [
  { label: "OBSERVE", note: "Network state S(t)" },
  { label: "IDENTIFY", note: "MITRE evidence" },
  { label: "PREDICT", note: "K-step forecasting + attack progression" },
  { label: "MITIGATE", note: "Demonstration policy + simulation" },
  { label: "VERIFY", note: "This feature - simulated verification" },
];

export default function VerificationCycle() {
  return (
    <div className="verification-cycle">
      {STEPS.map((step, i) => (
        <div className="verification-cycle__step-wrap" key={step.label}>
          <div className="verification-cycle__step">
            <span className="verification-cycle__marker">✓</span>
            <span className="verification-cycle__label">{step.label}</span>
            <span className="verification-cycle__note">{step.note}</span>
          </div>
          {i < STEPS.length - 1 && <IconChevronRight className="verification-cycle__arrow" />}
        </div>
      ))}
    </div>
  );
}
