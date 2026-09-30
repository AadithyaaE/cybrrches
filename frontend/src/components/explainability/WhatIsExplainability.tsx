import "./WhatIsExplainability.css";

export default function WhatIsExplainability() {
  return (
    <div className="what-is-explainability">
      <p className="what-is-explainability__lead">
        The model produces a prediction, and the explainability layer shows which measurable network
        features contributed to that prediction.
      </p>
      <p className="what-is-explainability__detail">
        Feature 15 explains the actual deployed forecasting path: the frozen LSTM World Model (Feature 10)
        forecasts a future network state, and the frozen classifier (Feature 11) turns that forecast into
        P(Infiltration). Two different, never-conflated attribution methods are used: an{" "}
        <strong>exact</strong> decomposition of the classifier's own logit (Layer C), and an{" "}
        <strong>approximate</strong> occlusion diagnostic of the LSTM's temporal behaviour (Layer D).
      </p>
    </div>
  );
}
