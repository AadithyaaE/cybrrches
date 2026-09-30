import SummarySection from "./SummarySection";
import { RESEARCH_LIMITATIONS } from "../../data/generalizationData";
import "./ResearchNotes.css";

export default function ResearchNotes() {
  return (
    <SummarySection
      title="Research Limitations"
      description="Known scope limitations and negative findings from the Feature 1-16 pipeline. These are not hidden or softened."
    >
      <ul className="research-notes__list">
        {RESEARCH_LIMITATIONS.map((note) => (
          <li className="research-notes__item" key={note}>
            {note}
          </li>
        ))}
      </ul>
    </SummarySection>
  );
}
