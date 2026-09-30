import { useState } from "react";
import StatusBadge from "../ui/StatusBadge";
import ForecastSampleSelector from "./ForecastSampleSelector";
import StateComparisonTable from "./StateComparisonTable";
import HorizonComparisonView from "./HorizonComparisonView";
import type { ForecastFutureStateSummary, ForecastFutureStateSample, ValueMode } from "../../types/forecastFutureState";
import "./FutureNetworkState.css";

interface FutureNetworkStateProps {
  summary: ForecastFutureStateSummary;
  samples: ForecastFutureStateSample[];
}

export default function FutureNetworkState({ summary, samples }: FutureNetworkStateProps) {
  const [selectedSequenceId, setSelectedSequenceId] = useState(samples[0].sequenceId);
  const [horizon, setHorizon] = useState(1);
  const [mode, setMode] = useState<ValueMode>("scaled");

  const sample = samples.find((s) => s.sequenceId === selectedSequenceId) ?? samples[0];
  const groundTruth = sample.groundTruth[String(horizon)];

  return (
    <div className="future-network-state">
      <ForecastSampleSelector
        samples={samples}
        selectedSequenceId={selectedSequenceId}
        onSelectSequence={setSelectedSequenceId}
        horizon={horizon}
        onSelectHorizon={setHorizon}
        mode={mode}
        onSelectMode={setMode}
        totalTestSequences={summary.totalTestSequences}
      />

      <div className="future-network-state__mode-note">
        {mode === "scaled" ? summary.scaledSpaceNote : summary.rawUnitsNote}
      </div>

      <div className="future-network-state__legend">
        <div className="future-network-state__legend-item">
          <StatusBadge label="Observed" tone="info" dot={false} />
          <span>Actual network state from the dataset (last second of the 10-second input history).</span>
        </div>
        <div className="future-network-state__legend-item">
          <StatusBadge label="Forecast" tone="warning" dot={false} />
          <span>LSTM-generated predicted future network state (recursive for K&gt;1).</span>
        </div>
        <div className="future-network-state__legend-item">
          <StatusBadge label="Ground Truth" tone="success" dot={false} />
          <span>The actual recorded future state, when a valid (non-gap) future window exists in the test set.</span>
        </div>
      </div>

      {sample.isKnownOutlierExample && (
        <div className="future-network-state__outlier-flag">
          <StatusBadge label="Known Outlier Example" tone="danger" />
          <p>
            This is the sequence behind the test-set outlier referenced in the Outlier Caveat below. Its
            recorded ground-truth <strong>Pkt Len Var</strong> is far outside anything the model saw during
            training - a genuine out-of-distribution event in the data, not a bug. Select K=1 and switch to
            "Standardized (model space)" to see the ~1874 standardized value directly in the comparison table.
          </p>
        </div>
      )}

      {!groundTruth?.available && (
        <p className="future-network-state__no-truth-note">
          No ground-truth future state is available for this sequence at K={horizon} (it would cross a
          temporal gap or the end of the capture) - this is not fabricated, it is simply absent from the
          research artifact for this specific sample/horizon combination.
        </p>
      )}

      <h3 className="future-network-state__subheading">Feature-by-Feature State Comparison</h3>
      <StateComparisonTable sample={sample} featureOrder={summary.featureOrder} horizon={horizon} mode={mode} />

      <h3 className="future-network-state__subheading">Single-Feature Horizon Comparison</h3>
      <HorizonComparisonView sample={sample} featureOrder={summary.featureOrder} mode={mode} />

      <div className="future-network-state__honesty">
        <p>This is an offline research-model evaluation, not live network forecasting.</p>
        <p>
          The LSTM forecasts network-state vectors; it does not directly guarantee that an attack will occur.
        </p>
        <p>Attack-progression probability is evaluated separately (Attack Analysis feature).</p>
      </div>
    </div>
  );
}
