import { EXPLAINABILITY_LIMITATIONS } from "../../data/explainabilityFeature15Data";
import "./ExplainabilityLimitations.css";

export default function ExplainabilityLimitations() {
  return (
    <ul className="explainability-limitations__list">
      {EXPLAINABILITY_LIMITATIONS.map((note) => (
        <li key={note} className="explainability-limitations__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
