import { FEATURE_GROUPS } from "../../data/featureGroups";
import type { FeatureRanges } from "../../types/networkState";
import "./FeatureHeatBars.css";

interface FeatureHeatBarsProps {
  features: Record<string, number | null>;
  ranges: FeatureRanges;
}

function normalize(value: number | null, range: { min: number | null; max: number | null } | undefined): number | null {
  if (value === null || !range || range.min === null || range.max === null) return null;
  if (range.max === range.min) return value > 0 ? 1 : 0;
  const pct = (value - range.min) / (range.max - range.min);
  return Math.min(Math.max(pct, 0), 1);
}

export default function FeatureHeatBars({ features, ranges }: FeatureHeatBarsProps) {
  const allFeatures = FEATURE_GROUPS.flatMap((g) => g.features);

  return (
    <div className="feature-heat-bars">
      {allFeatures.map((feature) => {
        const value = features[feature] ?? null;
        const pct = normalize(value, ranges[feature]);
        return (
          <div className="feature-heat-bars__row" key={feature} title={`${feature}: ${value === null ? "not available" : value}`}>
            <span className="feature-heat-bars__label">{feature}</span>
            <div className="feature-heat-bars__track">
              {pct === null ? (
                <span className="feature-heat-bars__na">n/a</span>
              ) : (
                <div className="feature-heat-bars__fill" style={{ width: `${Math.max(pct * 100, 1.5)}%`, opacity: 0.25 + pct * 0.75 }} />
              )}
            </div>
          </div>
        );
      })}
      <p className="feature-heat-bars__legend">
        Bar width shows each feature's value relative to its observed min/max across all 32,068 one-second windows in this capture.
      </p>
    </div>
  );
}
