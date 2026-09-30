import type { VerificationTimelineEvent } from "../../types/verification";
import "./VerificationTimeline.css";

interface VerificationTimelineProps {
  events: VerificationTimelineEvent[];
}

export default function VerificationTimeline({ events }: VerificationTimelineProps) {
  return (
    <ol className="verification-timeline">
      {events.map((e) => (
        <li className={`verification-timeline__item ${e.occurred ? "verification-timeline__item--occurred" : ""}`} key={e.step}>
          <span className="verification-timeline__marker">{e.occurred ? "✓" : "○"}</span>
          <div className="verification-timeline__body">
            <span className="verification-timeline__label">
              {e.step}. {e.label}
            </span>
            <span className="verification-timeline__detail">{e.detail}</span>
            <span className="verification-timeline__timestamp">
              {e.timestamp !== null ? new Date(e.timestamp).toLocaleTimeString() : "No real timestamp for this step"}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}
