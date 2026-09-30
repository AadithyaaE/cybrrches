import { IconChevronRight } from "../ui/icons";
import type { ForecastHorizonMetric } from "../../data/forecastingData";
import type { ExampleSequencePoint } from "../../data/lstmWorldModelData";
import "./ForecastFlowDiagram.css";

interface ForecastFlowDiagramProps {
  testMetrics: ForecastHorizonMetric[];
  example: {
    sequenceId: number;
    inputEndTimestamp: string;
    forecastTargetLabel: string;
    points: ExampleSequencePoint[];
    note: string;
  };
}

export default function ForecastFlowDiagram({ testMetrics, example }: ForecastFlowDiagramProps) {
  const rmseByHorizon = (h: number) => testMetrics.find((m) => m.horizon === h)?.rmse ?? null;

  const steps = [
    { label: "Observed", sub: "S(t)", rmse: null as number | null },
    { label: "K=1 forecast", sub: "S(t+1)", rmse: rmseByHorizon(1) },
    { label: "K=2 forecast", sub: "S(t+2)", rmse: rmseByHorizon(2) },
    { label: "K=3 forecast", sub: "S(t+3)", rmse: rmseByHorizon(3) },
    { label: "K=5 forecast", sub: "S(t+5)", rmse: rmseByHorizon(5) },
  ];

  return (
    <div className="forecast-flow-diagram">
      <div className="forecast-flow-diagram__row">
        {steps.map((step, i) => (
          <div className="forecast-flow-diagram__step-wrap" key={step.label}>
            <div className="forecast-flow-diagram__step">
              <span className="forecast-flow-diagram__step-label">{step.label}</span>
              <span className="forecast-flow-diagram__step-sub">{step.sub}</span>
              {step.rmse !== null && (
                <span className="forecast-flow-diagram__step-rmse">Test RMSE {step.rmse.toFixed(3)}</span>
              )}
            </div>
            {i < steps.length - 1 && <IconChevronRight className="forecast-flow-diagram__arrow" />}
          </div>
        ))}
      </div>
      <p className="forecast-flow-diagram__caption">
        This diagram shows the real evaluation error (test-partition RMSE) at each recursive forecast step,
        not fabricated per-feature forecast values. The research artifacts store per-sequence error summaries
        (sample MSE/MAE), not full predicted 68-dimensional state vectors suitable for a safe browser
        visualization, so this page presents the actual horizon metrics rather than invented forecast content.
      </p>

      <div className="forecast-flow-diagram__example">
        <h3 className="forecast-flow-diagram__example-title">
          One real example - test sequence #{example.sequenceId}
        </h3>
        <p className="forecast-flow-diagram__example-meta">
          Input window ending {example.inputEndTimestamp} - forecast target label: {example.forecastTargetLabel}
        </p>
        <div className="forecast-flow-diagram__example-row">
          {example.points.map((p) => (
            <div className="forecast-flow-diagram__example-point" key={p.horizon}>
              <span className="forecast-flow-diagram__example-k">K={p.horizon}</span>
              <span className="forecast-flow-diagram__example-metric">MSE {p.sampleMse.toFixed(3)}</span>
              <span className="forecast-flow-diagram__example-metric">MAE {p.sampleMae.toFixed(3)}</span>
            </div>
          ))}
        </div>
        <p className="forecast-flow-diagram__example-note">{example.note}</p>
      </div>
    </div>
  );
}
