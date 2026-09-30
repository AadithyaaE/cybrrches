import type { StatusTone } from "../../types/status";
import "./StatusBadge.css";

interface StatusBadgeProps {
  label: string;
  tone?: StatusTone;
  dot?: boolean;
}

export default function StatusBadge({ label, tone = "neutral", dot = true }: StatusBadgeProps) {
  return (
    <span className={`status-badge status-badge--${tone}`}>
      {dot && <span className="status-badge__dot" aria-hidden="true" />}
      {label}
    </span>
  );
}
