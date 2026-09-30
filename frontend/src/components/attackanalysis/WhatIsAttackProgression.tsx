import "./WhatIsAttackProgression.css";

export default function WhatIsAttackProgression() {
  return (
    <div className="what-is-attack-progression">
      <p className="what-is-attack-progression__lead">
        The system estimates whether the predicted future network state is consistent with attack
        progression.
      </p>
      <p className="what-is-attack-progression__detail">
        Concretely: the frozen LSTM World Model (Feature 12) forecasts what the 68-dimensional network
        state will look like K seconds ahead. That forecast state is then passed into a separate, frozen
        classifier (Feature 11) that was trained to distinguish Benign from Infilteration states. The
        classifier's output - a probability between 0 and 1 - is what this page calls the{" "}
        <strong>attack-progression probability</strong>: how consistent the forecast future state is with
        the Infiltration class the classifier was trained on, not a measurement of attacker intent, a
        MITRE ATT&CK stage, or a mitigation decision.
      </p>
    </div>
  );
}
