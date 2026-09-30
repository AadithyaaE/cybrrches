import "./SimulationNotice.css";

const NOTES = [
  "This page performs SIMULATED VERIFICATION, not OBSERVED / REAL NETWORK VERIFICATION.",
  "CyberChess does not claim real firewall enforcement, real packet suppression, real attacker blocking, real network recovery, or production verification.",
  "All traffic figures come from Feature 10's deterministic simulation arithmetic over an illustrative baseline - never a measured network outcome.",
  "Research-derived inputs use real Feature 13/14/15 values (probabilities, MITRE evidence, attribution), unaltered - but the traffic simulation and its verification remain simulated regardless of input source.",
  "A future real-telemetry adapter would need to supply measured before/after network state to this same verification engine in place of Feature 10's simulation.",
];

export default function SimulationNotice() {
  return (
    <ul className="simulation-notice__list">
      {NOTES.map((n) => (
        <li key={n} className="simulation-notice__item">
          {n}
        </li>
      ))}
    </ul>
  );
}
