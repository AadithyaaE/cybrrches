import "./WhatIsMitre.css";

export default function WhatIsMitre() {
  return (
    <div className="what-is-mitre">
      <p className="what-is-mitre__lead">
        The system maps measurable network-behaviour evidence to ATT&amp;CK stages/techniques so an
        analyst can understand what type of attacker behaviour the evidence resembles.
      </p>
      <p className="what-is-mitre__detail">
        MITRE ATT&amp;CK is a public knowledge base of attacker tactics and techniques, organized by
        stage (Discovery, Command and Control, Exfiltration, Impact, and more). This page does not run a
        trained model to identify these stages - it applies a fixed set of deterministic, human-readable
        rules to real network-flow evidence (both the actual observed state and the LSTM's forecast future
        state) and reports which stages that evidence is consistent with, and how strongly.
      </p>
    </div>
  );
}
