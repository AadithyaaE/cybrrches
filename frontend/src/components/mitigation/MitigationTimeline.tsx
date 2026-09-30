import StatusBadge from "../ui/StatusBadge";
import type { MitigationActionRecord } from "../../types/mitigation";
import "./MitigationTimeline.css";

interface MitigationTimelineProps {
  records: MitigationActionRecord[];
}

const STATUS_TONE: Record<MitigationActionRecord["status"], "info" | "success" | "warning" | "neutral"> = {
  proposed: "info",
  applied: "success",
  rolled_back: "warning",
  reset: "neutral",
};

export default function MitigationTimeline({ records }: MitigationTimelineProps) {
  if (records.length === 0) {
    return <p className="mitigation-timeline__empty">No simulated actions yet for this input. Decisions are proposed automatically; applying a simulation adds an entry here.</p>;
  }

  return (
    <ul className="mitigation-timeline">
      {records.map((r) => (
        <li className="mitigation-timeline__item" key={r.actionId}>
          <StatusBadge label={r.status.replace(/_/g, " ")} tone={STATUS_TONE[r.status]} dot={false} />
          <div className="mitigation-timeline__body">
            <span className="mitigation-timeline__action">
              {r.level.replace(/_/g, " ")} - {r.action}
            </span>
            <span className="mitigation-timeline__meta">
              {new Date(r.timestamp).toLocaleTimeString()}
              {r.durationSeconds !== null ? ` - duration ${r.durationSeconds.toLocaleString()}s` : ""} - action ID{" "}
              <code>{r.actionId}</code> - reversible - simulation only
            </span>
          </div>
        </li>
      ))}
    </ul>
  );
}
