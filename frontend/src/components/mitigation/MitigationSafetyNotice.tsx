import "./MitigationSafetyNotice.css";

const SAFETY_NOTES = [
  "Simulation only. No real firewall, network, or routing changes are made by this feature.",
  "This is a demonstration policy. Thresholds are documented in mitigationPolicyConfig.ts but are not deployment-calibrated.",
  "Thresholds are not empirically calibrated for production deployment and were not tuned against Feature 16 (external generalization) outcomes.",
  "Simulated outcomes (before/after traffic figures) are deterministic arithmetic over an illustrative baseline, not measured network outcomes.",
  "No mitigation level is described as best, worst, optimal, or superior - this is a documented decision policy, not a benchmark of competing algorithms.",
  "No model is retrained, tuned, or modified by this feature.",
];

export default function MitigationSafetyNotice() {
  return (
    <ul className="mitigation-safety-notice__list">
      {SAFETY_NOTES.map((note) => (
        <li key={note} className="mitigation-safety-notice__item">
          {note}
        </li>
      ))}
    </ul>
  );
}
