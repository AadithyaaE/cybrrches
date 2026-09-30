import type { ReactNode } from "react";
import Card from "../ui/Card";
import StatusBadge from "../ui/StatusBadge";
import "./SummarySection.css";

interface SummarySectionProps {
  title: string;
  evalLabel?: string;
  description?: string;
  children: ReactNode;
}

export default function SummarySection({ title, evalLabel, description, children }: SummarySectionProps) {
  return (
    <Card className="summary-section">
      <div className="summary-section__header">
        <h2 className="summary-section__title">{title}</h2>
        {evalLabel && <StatusBadge label={evalLabel} tone="info" dot={false} />}
      </div>
      {description && <p className="summary-section__description">{description}</p>}
      <div className="summary-section__body">{children}</div>
    </Card>
  );
}
