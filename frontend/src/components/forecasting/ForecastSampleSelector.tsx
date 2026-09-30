import StatusBadge from "../ui/StatusBadge";
import type { ForecastFutureStateSample, ValueMode } from "../../types/forecastFutureState";
import "./ForecastSampleSelector.css";

const HORIZONS = [1, 2, 3, 5];

interface ForecastSampleSelectorProps {
  samples: ForecastFutureStateSample[];
  selectedSequenceId: number;
  onSelectSequence: (sequenceId: number) => void;
  horizon: number;
  onSelectHorizon: (horizon: number) => void;
  mode: ValueMode;
  onSelectMode: (mode: ValueMode) => void;
  totalTestSequences: number;
}

export default function ForecastSampleSelector({
  samples,
  selectedSequenceId,
  onSelectSequence,
  horizon,
  onSelectHorizon,
  mode,
  onSelectMode,
  totalTestSequences,
}: ForecastSampleSelectorProps) {
  return (
    <div className="forecast-sample-selector">
      <div className="forecast-sample-selector__row">
        <label className="forecast-sample-selector__label">
          Forecast sample:
          <select
            className="forecast-sample-selector__select"
            value={selectedSequenceId}
            onChange={(e) => onSelectSequence(Number(e.target.value))}
          >
            {samples.map((s) => (
              <option key={s.sequenceId} value={s.sequenceId}>
                {s.inputEndTimestamp} - test seq #{s.sequenceId}
                {s.isKnownOutlierExample ? " (known outlier example)" : ""}
              </option>
            ))}
          </select>
        </label>

        <div className="forecast-sample-selector__k-group">
          {HORIZONS.map((h) => (
            <button
              key={h}
              type="button"
              className={`forecast-sample-selector__k-btn ${horizon === h ? "forecast-sample-selector__k-btn--active" : ""}`}
              onClick={() => onSelectHorizon(h)}
            >
              K={h}
            </button>
          ))}
        </div>

        <div className="forecast-sample-selector__mode-group">
          <button
            type="button"
            className={`forecast-sample-selector__mode-btn ${mode === "scaled" ? "forecast-sample-selector__mode-btn--active" : ""}`}
            onClick={() => onSelectMode("scaled")}
          >
            Standardized (model space)
          </button>
          <button
            type="button"
            className={`forecast-sample-selector__mode-btn ${mode === "raw" ? "forecast-sample-selector__mode-btn--active" : ""}`}
            onClick={() => onSelectMode("raw")}
          >
            Display raw units
          </button>
        </div>
      </div>

      <div className="forecast-sample-selector__notice">
        <StatusBadge label="Frozen Research Evaluation" tone="neutral" dot={false} />
        <p>
          Representative saved model forecasts from the frozen research evaluation - showing{" "}
          {samples.length} of {totalTestSequences.toLocaleString()} test sequences. These are saved
          outputs of a one-time evaluation run, not live inference.
        </p>
      </div>
    </div>
  );
}
