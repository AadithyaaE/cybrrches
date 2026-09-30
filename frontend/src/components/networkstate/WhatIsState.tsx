import SummarySection from "../overview/SummarySection";
import "./WhatIsState.css";

export default function WhatIsState() {
  return (
    <SummarySection title="What is S(t)?">
      <p className="what-is-state__text">
        S(t) is the 68-dimensional representation of network behaviour at a given 1-second window. It is the
        input representation used by the temporal forecasting pipeline.
      </p>
      <div className="what-is-state__meta">
        <div>
          <span className="what-is-state__meta-label">Source</span>
          <span className="what-is-state__meta-value">CSE-CIC-IDS2018</span>
        </div>
        <div>
          <span className="what-is-state__meta-label">Pipeline</span>
          <span className="what-is-state__meta-value">1-second aggregation → network state → temporal sequence</span>
        </div>
      </div>
    </SummarySection>
  );
}
