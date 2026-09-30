import SummarySection from "../overview/SummarySection";
import "./NetworkStateLimitations.css";

const LIMITATIONS = [
  "This page displays offline research data. It is not live network monitoring.",
  "The state representation is based on the current CSE-CIC-IDS2018 feature schema.",
  "Some state values may be unavailable where the research pipeline intentionally preserved missing values (e.g. Flow Byts/s and Flow Pkts/s are undefined for a small number of windows/observations) - these are never displayed as zero.",
  "This dataset's states carry only two labels, Benign and Infilteration; no other attack families are represented at the state level.",
  "The Feature Explorer browses a 402-window evenly-spaced sample of the full 32,068-window artifact for performance, not the complete capture.",
];

export default function NetworkStateLimitations() {
  return (
    <SummarySection title="Important Limitations">
      <ul className="network-state-limitations__list">
        {LIMITATIONS.map((item) => (
          <li key={item} className="network-state-limitations__item">
            {item}
          </li>
        ))}
      </ul>
    </SummarySection>
  );
}
