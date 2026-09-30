import MiniBarChart from "../ui/MiniBarChart";
import SummarySection from "./SummarySection";
import {
  GLOBAL_FEATURE_IMPORTANCE_TOP,
  TEMPORAL_ATTRIBUTION_SUMMARY,
  LLM_EXPLAINER_STATUS,
  EXPLAINABILITY_SAMPLE_SIZE,
} from "../../data/explainabilityData";
import "./ExplainabilitySummary.css";

export default function ExplainabilitySummary() {
  const maxAbs = Math.max(...GLOBAL_FEATURE_IMPORTANCE_TOP.map((f) => f.meanAbsContribution));

  return (
    <SummarySection
      title="Explainability Summary"
      description={`Layer-C linear attribution (global, aggregated across all 3,492 validation sequences) and Layer-D temporal occlusion attribution (aggregated across ${EXPLAINABILITY_SAMPLE_SIZE} sample sequences).`}
    >
      <div className="explainability-summary__block">
        <h3 className="explainability-summary__block-title">Global Feature Contribution (top features)</h3>
        <ul className="explainability-summary__bars">
          {GLOBAL_FEATURE_IMPORTANCE_TOP.map((f) => (
            <li className="explainability-summary__bar-row" key={f.feature}>
              <span className="explainability-summary__bar-label">{f.feature}</span>
              <div className="explainability-summary__bar-track">
                <div
                  className="explainability-summary__bar-fill"
                  style={{ width: `${(f.meanAbsContribution / maxAbs) * 100}%` }}
                />
              </div>
              <span className="explainability-summary__bar-value">{f.meanAbsContribution.toFixed(3)}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="explainability-summary__block">
        <h3 className="explainability-summary__block-title">Temporal Attribution (10-second window)</h3>
        <MiniBarChart
          categories={TEMPORAL_ATTRIBUTION_SUMMARY.map((t) => t.timeStep)}
          series={[
            {
              label: "Mean |contribution|",
              color: "var(--accent-violet)",
              values: TEMPORAL_ATTRIBUTION_SUMMARY.map((t) => t.meanAbsContribution),
            },
          ]}
          valueFormatter={(v) => v.toFixed(4)}
        />
      </div>

      <div className={`explainability-summary__llm ${LLM_EXPLAINER_STATUS.enabled ? "" : "explainability-summary__llm--disabled"}`}>
        <span className="explainability-summary__llm-label">{LLM_EXPLAINER_STATUS.label}</span>
        <p className="explainability-summary__llm-text">{LLM_EXPLAINER_STATUS.scopeStatement}</p>
      </div>
    </SummarySection>
  );
}
