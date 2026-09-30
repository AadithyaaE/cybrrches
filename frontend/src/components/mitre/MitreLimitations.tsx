import { MITRE_LIMITATIONS } from "../../data/mitreRulesData";
import "./MitreLimitations.css";

export default function MitreLimitations() {
  return (
    <ul className="mitre-limitations__list">
      {MITRE_LIMITATIONS.map((note) => (
        <li key={note} className="mitre-limitations__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
