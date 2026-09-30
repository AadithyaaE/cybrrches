import type { GlobalFeatureImportance } from "../../data/explainabilityFeature15Data";
import "./TopFeatures.css";

interface TopFeaturesProps {
  features: GlobalFeatureImportance[];
}

export default function TopFeatures({ features }: TopFeaturesProps) {
  const maxAbs = Math.max(...features.map((f) => f.meanAbsContribution));

  return (
    <div className="top-features">
      <ul className="top-features__list">
        {features.map((f, i) => (
          <li className="top-features__row" key={f.feature}>
            <span className="top-features__rank">{i + 1}</span>
            <span className="top-features__label">{f.feature}</span>
            <div className="top-features__track">
              <div className="top-features__fill" style={{ width: `${(f.meanAbsContribution / maxAbs) * 100}%` }} />
            </div>
            <span className="top-features__value">{f.meanAbsContribution.toFixed(4)}</span>
            <span className={`top-features__sign ${f.meanContribution >= 0 ? "top-features__sign--attack" : "top-features__sign--benign"}`}>
              {f.meanContribution >= 0 ? "attack-leaning" : "benign-leaning"}
            </span>
          </li>
        ))}
      </ul>
      <p className="top-features__caption">
        Global mean |Layer-C contribution| across all 3,492 VALIDATION sequences (real values from
        results/explainability/explainability_metrics.json, top 15 as saved - none added, none omitted).
        "Attack-leaning" / "benign-leaning" reflects the sign of the mean (signed) contribution, not the
        magnitude bar, which always shows the absolute value.
      </p>
    </div>
  );
}
