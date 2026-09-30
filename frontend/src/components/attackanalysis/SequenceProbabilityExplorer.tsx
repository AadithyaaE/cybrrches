import { useState } from "react";
import StatusBadge from "../ui/StatusBadge";
import type { AttackProgressionSequenceSample, AttackProgressionSequenceSummary } from "../../types/attackProgressionSequence";
import "./SequenceProbabilityExplorer.css";

interface SequenceProbabilityExplorerProps {
  summary: AttackProgressionSequenceSummary;
  samples: AttackProgressionSequenceSample[];
}

const HORIZONS = [1, 2, 3, 5];

export default function SequenceProbabilityExplorer({ summary, samples }: SequenceProbabilityExplorerProps) {
  const [selectedSequenceId, setSelectedSequenceId] = useState(samples[0].sequenceId);
  const [horizon, setHorizon] = useState(1);

  const sample = samples.find((s) => s.sequenceId === selectedSequenceId) ?? samples[0];
  const point = sample.horizons[String(horizon)];

  return (
    <div className="sequence-probability-explorer">
      <div className="sequence-probability-explorer__controls">
        <label className="sequence-probability-explorer__select-label">
          Forecast sample:
          <select
            className="sequence-probability-explorer__select"
            value={selectedSequenceId}
            onChange={(e) => setSelectedSequenceId(Number(e.target.value))}
          >
            {samples.map((s) => (
              <option key={s.sequenceId} value={s.sequenceId}>
                {s.currentTimestamp} - test seq #{s.sequenceId}
              </option>
            ))}
          </select>
        </label>
        <div className="sequence-probability-explorer__k-group">
          {HORIZONS.map((h) => (
            <button
              key={h}
              type="button"
              className={`sequence-probability-explorer__k-btn ${horizon === h ? "sequence-probability-explorer__k-btn--active" : ""}`}
              onClick={() => setHorizon(h)}
            >
              K={h}
            </button>
          ))}
        </div>
      </div>

      <div className="sequence-probability-explorer__notice">
        <StatusBadge label="Frozen Evaluation" tone="neutral" dot={false} />
        <p>
          Showing {summary.sampledSequenceCount} of {summary.totalTestSequencesWithAllHorizons.toLocaleString()}{" "}
          TEST-partition sequences with a valid forecast at every horizon, {summary.mode.replace("_", " ")} mode,
          threshold {summary.threshold}. {summary.note}
        </p>
      </div>

      {point && (
        <div className="sequence-probability-explorer__result">
          <div className="sequence-probability-explorer__prob-block">
            <span className="sequence-probability-explorer__prob-label">P(Infiltration) at K={horizon}</span>
            <span className="sequence-probability-explorer__prob-value">
              {(point.predictedInfiltrationProbability * 100).toFixed(1)}%
            </span>
            <div className="sequence-probability-explorer__prob-track">
              <div
                className="sequence-probability-explorer__prob-fill"
                style={{ width: `${point.predictedInfiltrationProbability * 100}%` }}
              />
              <div className="sequence-probability-explorer__prob-threshold" style={{ left: "50%" }} />
            </div>
            <span className="sequence-probability-explorer__prob-caption">
              Threshold {summary.threshold} - values above the line are classified "Infiltration-consistent"
            </span>
          </div>

          <div className="sequence-probability-explorer__badges">
            <div className="sequence-probability-explorer__badge-item">
              <span className="sequence-probability-explorer__badge-label">Predicted Class (0.5 threshold)</span>
              <StatusBadge
                label={point.predictedAttackClassAt050 === 1 ? "Infiltration-consistent" : "Benign-consistent"}
                tone={point.predictedAttackClassAt050 === 1 ? "danger" : "success"}
              />
            </div>
            <div className="sequence-probability-explorer__badge-item">
              <span className="sequence-probability-explorer__badge-label">Actual Future Label (ground truth)</span>
              <StatusBadge
                label={point.actualFutureLabel}
                tone={point.actualFutureLabel === "Infilteration" ? "danger" : "success"}
              />
            </div>
          </div>
        </div>
      )}

      <div className="sequence-probability-explorer__trace">
        <h4 className="sequence-probability-explorer__trace-title">K=1 → K=5 probability trace for this sequence</h4>
        <div className="sequence-probability-explorer__trace-row">
          {HORIZONS.map((h) => {
            const p = sample.horizons[String(h)];
            return (
              <div className="sequence-probability-explorer__trace-point" key={h}>
                <span className="sequence-probability-explorer__trace-k">K={h}</span>
                <span className="sequence-probability-explorer__trace-value">
                  {p ? `${(p.predictedInfiltrationProbability * 100).toFixed(1)}%` : "—"}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
