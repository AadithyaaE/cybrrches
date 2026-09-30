import StatusBadge from "../ui/StatusBadge";
import SummarySection from "./SummarySection";
import { RESEARCH_STAGES } from "../../data/researchSummaryData";
import "./ResearchSummary.css";

export default function ResearchSummary() {
  return (
    <SummarySection
      title="Research Summary"
      description="Features 1-16 of the offline research pipeline, from raw network-flow ingestion through frozen-model generalization testing."
    >
      <ul className="research-summary__list">
        {RESEARCH_STAGES.map((stage) => (
          <li className="research-summary__item" key={stage.label}>
            <div>
              <div className="research-summary__label">{stage.label}</div>
              <div className="research-summary__detail">{stage.detail}</div>
            </div>
            <StatusBadge label="Complete" tone="success" />
          </li>
        ))}
      </ul>
    </SummarySection>
  );
}
