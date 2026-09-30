import type { ForecastHorizonMetric } from "../../data/forecastingData";
import "./ErrorAccumulationCaveat.css";

interface ErrorAccumulationCaveatProps {
  testMetrics: ForecastHorizonMetric[];
}

export default function ErrorAccumulationCaveat({ testMetrics }: ErrorAccumulationCaveatProps) {
  const sorted = [...testMetrics].sort((a, b) => a.horizon - b.horizon);

  return (
    <div className="error-accumulation-caveat">
      <p className="error-accumulation-caveat__text">
        Observed research result: test-partition RMSE increases as the recursive rollout gets longer.
      </p>
      <div className="error-accumulation-caveat__row">
        {sorted.map((m) => (
          <div className="error-accumulation-caveat__point" key={m.horizon}>
            <span className="error-accumulation-caveat__k">K={m.horizon}</span>
            <span className="error-accumulation-caveat__rmse">{m.rmse.toFixed(3)}</span>
          </div>
        ))}
      </div>
      <p className="error-accumulation-caveat__explain">
        <strong>Longer recursive forecasts accumulate prediction error.</strong> Because each step beyond K=1
        feeds the model's own prior prediction back in as input, small errors compound. This is a
        development/test evaluation result on this dataset's chronological split, not a universal law about
        all networks or all models.
      </p>
      <p className="error-accumulation-caveat__disclaimer">
        This does not mean the model predicts attacks directly from these numbers - state-forecasting error
        is a regression metric on the 68-dimensional state vector, not an attack probability. Attack-progression
        probability is handled separately by the Attack Analysis feature.
      </p>
    </div>
  );
}
