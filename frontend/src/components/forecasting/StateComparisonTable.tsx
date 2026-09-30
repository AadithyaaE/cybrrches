import { FEATURE_GROUPS } from "../../data/featureGroups";
import type { ForecastFutureStateSample, ValueMode } from "../../types/forecastFutureState";
import "./StateComparisonTable.css";

interface StateComparisonTableProps {
  sample: ForecastFutureStateSample;
  featureOrder: string[];
  horizon: number;
  mode: ValueMode;
}

function formatValue(value: number | null | undefined): string {
  if (value === null || value === undefined) return "— Not available";
  if (Number.isInteger(value)) return value.toLocaleString();
  return value.toLocaleString(undefined, { maximumFractionDigits: 4 });
}

export default function StateComparisonTable({ sample, featureOrder, horizon, mode }: StateComparisonTableProps) {
  const forecast = sample.forecasts[String(horizon)];
  const groundTruth = sample.groundTruth[String(horizon)];
  const gtAvailable = groundTruth?.available;

  const observedArr = sample.observed[mode];
  const forecastArr = forecast?.[mode];
  const gtArr = gtAvailable ? groundTruth?.[mode] : undefined;

  return (
    <div className="state-comparison-table">
      <div className="state-comparison-table__header-row">
        <span className="state-comparison-table__header-cell state-comparison-table__header-cell--name">Feature</span>
        <span className="state-comparison-table__header-cell state-comparison-table__header-cell--observed">Observed</span>
        <span className="state-comparison-table__header-cell state-comparison-table__header-cell--forecast">Forecast K={horizon}</span>
        <span className="state-comparison-table__header-cell state-comparison-table__header-cell--truth">
          Ground Truth K={horizon}
        </span>
      </div>

      {FEATURE_GROUPS.map((group) => (
        <div className="state-comparison-table__group" key={group.title}>
          <h4 className="state-comparison-table__group-title">{group.title}</h4>
          {group.features.map((feature) => {
            const idx = featureOrder.indexOf(feature);
            return (
              <div className="state-comparison-table__row" key={feature}>
                <span className="state-comparison-table__cell state-comparison-table__cell--name">{feature}</span>
                <span className="state-comparison-table__cell">{formatValue(observedArr?.[idx])}</span>
                <span className="state-comparison-table__cell state-comparison-table__cell--forecast">
                  {formatValue(forecastArr?.[idx])}
                </span>
                <span className="state-comparison-table__cell state-comparison-table__cell--truth">
                  {gtAvailable ? formatValue(gtArr?.[idx]) : "— Not available"}
                </span>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
