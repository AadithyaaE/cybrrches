import StatusBadge from "../ui/StatusBadge";
import type { VerificationObjective } from "../../types/verification";
import "./VerificationObjectives.css";

interface VerificationObjectivesProps {
  objectives: VerificationObjective[];
}

export default function VerificationObjectives({ objectives }: VerificationObjectivesProps) {
  return (
    <ul className="verification-objectives">
      {objectives.map((o) => (
        <li className="verification-objectives__item" key={o.key}>
          <span className="verification-objectives__label">{o.label}</span>
          <StatusBadge
            label={o.result}
            tone={o.result === "PASS" ? "success" : o.result === "FAIL" ? "danger" : "neutral"}
          />
        </li>
      ))}
    </ul>
  );
}
