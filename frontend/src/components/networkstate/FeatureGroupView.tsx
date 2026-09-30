import { FEATURE_GROUPS } from "../../data/featureGroups";
import "./FeatureGroupView.css";

interface FeatureGroupViewProps {
  features: Record<string, number | null>;
}

function formatValue(value: number | null): string {
  if (value === null || value === undefined) return "";
  if (Number.isInteger(value)) return value.toLocaleString();
  return value.toLocaleString(undefined, { maximumFractionDigits: 4 });
}

export default function FeatureGroupView({ features }: FeatureGroupViewProps) {
  return (
    <div className="feature-group-view">
      {FEATURE_GROUPS.map((group) => (
        <div className="feature-group-view__group" key={group.title}>
          <h3 className="feature-group-view__group-title">{group.title}</h3>
          <div className="feature-group-view__grid">
            {group.features.map((feature) => {
              const value = features[feature] ?? null;
              return (
                <div className="feature-group-view__row" key={feature}>
                  <span className="feature-group-view__name">{feature}</span>
                  <span className={`feature-group-view__value ${value === null ? "feature-group-view__value--na" : ""}`}>
                    {value === null ? "— Not available" : formatValue(value)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
