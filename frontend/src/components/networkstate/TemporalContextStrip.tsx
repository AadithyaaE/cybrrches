import type { NetworkStateWindow } from "../../types/networkState";
import "./TemporalContextStrip.css";

interface TemporalContextStripProps {
  window: NetworkStateWindow;
}

export default function TemporalContextStrip({ window: w }: TemporalContextStripProps) {
  if (!w.hasValidTemporalSequence || !w.temporalContext) {
    return (
      <p className="temporal-context-strip__unavailable">
        This window sits at a temporal-gap boundary (see "num_temporal_gaps" in the Feature 6 report) or too
        close to the start of the capture, so it does not anchor a full, valid 10-window input sequence. No
        t-9...t context is available for it.
      </p>
    );
  }

  return (
    <div className="temporal-context-strip">
      <div className="temporal-context-strip__track">
        {w.temporalContext.map((entry) => (
          <div
            key={entry.windowId}
            className={`temporal-context-strip__chip temporal-context-strip__chip--${entry.label.toLowerCase()} ${
              entry.position === 0 ? "temporal-context-strip__chip--current" : ""
            }`}
            title={`${entry.timestamp} - ${entry.label}`}
          >
            <span className="temporal-context-strip__position">{entry.position === 0 ? "t" : `t${entry.position}`}</span>
          </div>
        ))}
      </div>
      <p className="temporal-context-strip__caption">
        10-second input window (t-9 ... t) that would feed the LSTM world model if this sequence were used for
        forecasting. Shown for context only - this page does not run forecasting.
      </p>
    </div>
  );
}
