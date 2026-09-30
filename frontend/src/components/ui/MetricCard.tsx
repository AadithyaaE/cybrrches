import type { ReactNode } from "react";
import Card from "./Card";
import StatusBadge from "./StatusBadge";
import type { StatusTone } from "../../types/status";
import "./MetricCard.css";

interface MetricCardProps {
  eyebrow: string;
  value: string;
  detail: string;
  statusLabel: string;
  statusTone: StatusTone;
  accent?: "cyan" | "violet" | "neutral";
  icon?: ReactNode;
}

export default function MetricCard({
  eyebrow,
  value,
  detail,
  statusLabel,
  statusTone,
  accent = "neutral",
  icon,
}: MetricCardProps) {
  return (
    <Card className={`metric-card metric-card--${accent}`}>
      <div className="metric-card__top">
        <span className="metric-card__eyebrow">{eyebrow}</span>
        {icon && <span className="metric-card__icon">{icon}</span>}
      </div>
      <div className="metric-card__value">{value}</div>
      <div className="metric-card__detail">{detail}</div>
      <div className="metric-card__footer">
        <StatusBadge label={statusLabel} tone={statusTone} />
      </div>
    </Card>
  );
}
