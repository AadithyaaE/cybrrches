import { useState } from "react";
import type { ForecastFutureStateSample, ValueMode } from "../../types/forecastFutureState";
import "./HorizonComparisonView.css";

interface HorizonComparisonViewProps {
  sample: ForecastFutureStateSample;
  featureOrder: string[];
  mode: ValueMode;
}

const HORIZONS = [1, 2, 3, 5];

function formatValue(value: number | null): string {
  if (value === null) return "—";
  if (Number.isInteger(value)) return value.toLocaleString();
  return value.toLocaleString(undefined, { maximumFractionDigits: 3 });
}

export default function HorizonComparisonView({ sample, featureOrder, mode }: HorizonComparisonViewProps) {
  const [feature, setFeature] = useState(featureOrder[0]);
  const idx = featureOrder.indexOf(feature);

  const observedValue = sample.observed[mode]?.[idx] ?? null;

  return (
    <div className="horizon-comparison-view">
      <label className="horizon-comparison-view__select-label">
        Feature:
        <select
          className="horizon-comparison-view__select"
          value={feature}
          onChange={(e) => setFeature(e.target.value)}
        >
          {featureOrder.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>

      <div className="horizon-comparison-view__strip">
        <div className="horizon-comparison-view__point horizon-comparison-view__point--observed">
          <span className="horizon-comparison-view__k">Observed</span>
          <span className="horizon-comparison-view__value">{formatValue(observedValue)}</span>
        </div>
        {HORIZONS.map((h) => {
          const forecastValue = sample.forecasts[String(h)]?.[mode]?.[idx] ?? null;
          const gt = sample.groundTruth[String(h)];
          const gtValue = gt?.available ? (gt[mode]?.[idx] ?? null) : null;
          return (
            <div className="horizon-comparison-view__point" key={h}>
              <span className="horizon-comparison-view__k">K={h}</span>
              <span className="horizon-comparison-view__value horizon-comparison-view__value--forecast">
                {formatValue(forecastValue)}
              </span>
              <span className="horizon-comparison-view__value horizon-comparison-view__value--truth">
                {gt?.available ? formatValue(gtValue) : "— Not available"}
              </span>
            </div>
          );
        })}
      </div>
      <p className="horizon-comparison-view__legend">
        <span className="horizon-comparison-view__legend-item horizon-comparison-view__legend-item--forecast">Forecast</span>
        <span className="horizon-comparison-view__legend-item horizon-comparison-view__legend-item--truth">Ground Truth</span>
      </p>
      <p className="horizon-comparison-view__caption">
        Real saved values for <strong>{feature}</strong> ({mode === "scaled" ? "standardized feature space" : "raw units"}).
        Ground-truth values are shown only where a valid future window exists for this sequence.
      </p>
    </div>
  );
}
