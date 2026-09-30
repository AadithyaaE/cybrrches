import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import WorldModelCard from "../components/forecasting/WorldModelCard";
import ForecastHorizonView from "../components/forecasting/ForecastHorizonView";
import WhatIsK from "../components/forecasting/WhatIsK";
import ForecastFlowDiagram from "../components/forecasting/ForecastFlowDiagram";
import ErrorAccumulationCaveat from "../components/forecasting/ErrorAccumulationCaveat";
import OutlierCaveat from "../components/forecasting/OutlierCaveat";
import ForecastingScopeNotes from "../components/forecasting/ForecastingScopeNotes";
import FutureNetworkState from "../components/forecasting/FutureNetworkState";
import {
  getLstmModelConfig,
  getForecastHorizonMetrics,
  getTestOutlierDiagnostics,
  getExampleSequenceTrace,
  type LstmModelConfig,
} from "../services/forecastingService";
import {
  getForecastFutureStateSummary,
  getForecastFutureStateSamples,
} from "../services/forecastFutureStateService";
import type { ForecastHorizonMetric } from "../data/forecastingData";
import type { HorizonOutlierDiagnostic, ExampleSequencePoint } from "../data/lstmWorldModelData";
import type { ForecastFutureStateSummary, ForecastFutureStateSample } from "../types/forecastFutureState";
import "./ForecastingPage.css";

interface ExampleTrace {
  sequenceId: number;
  split: string;
  inputEndTimestamp: string;
  forecastTargetLabel: string;
  points: ExampleSequencePoint[];
  note: string;
}

export default function ForecastingPage() {
  const [config, setConfig] = useState<LstmModelConfig | null>(null);
  const [metrics, setMetrics] = useState<ForecastHorizonMetric[] | null>(null);
  const [outliers, setOutliers] = useState<HorizonOutlierDiagnostic[] | null>(null);
  const [example, setExample] = useState<ExampleTrace | null>(null);
  const [futureStateSummary, setFutureStateSummary] = useState<ForecastFutureStateSummary | null>(null);
  const [futureStateSamples, setFutureStateSamples] = useState<ForecastFutureStateSample[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      getLstmModelConfig(),
      getForecastHorizonMetrics(),
      getTestOutlierDiagnostics(),
      getExampleSequenceTrace(),
      getForecastFutureStateSummary(),
      getForecastFutureStateSamples(),
    ])
      .then(([configRes, metricsRes, outliersRes, exampleRes, futureSummaryRes, futureSamplesRes]) => {
        setConfig(configRes);
        setMetrics(metricsRes);
        setOutliers(outliersRes);
        setExample(exampleRes);
        setFutureStateSummary(futureSummaryRes);
        setFutureStateSamples(futureSamplesRes);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load forecasting data."));
  }, []);

  const testMetrics = metrics ? metrics.filter((m) => m.split === "test") : [];

  return (
    <div>
      <SectionHeader
        title="Forecasting"
        description="Explore how the LSTM World Model forecasts future network states from recent temporal behaviour."
        actions={
          <div className="forecasting-page__badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Development / Test Evaluation" tone="info" dot={false} />
          </div>
        }
      />

      {error && (
        <SummarySection title="Unable to load forecasting data">
          <p className="forecasting-page__error">{error}</p>
        </SummarySection>
      )}

      {!config && !error && <p className="forecasting-page__loading">Loading forecasting artifacts...</p>}

      {config && metrics && outliers && example && futureStateSummary && futureStateSamples && (
        <div className="forecasting-page__sections">
          <WorldModelCard config={config} />

          <SummarySection
            title="Forecast Horizon View"
            evalLabel="Development / Test Evaluation"
            description="MSE, RMSE and MAE for each forecast horizon (K = 1, 2, 3, 5) across the chronological train / validation / test split, from the Feature 12 K-step forecasting artifact."
          >
            <ForecastHorizonView metrics={metrics} />
          </SummarySection>

          <SummarySection title="What Does K Mean?">
            <WhatIsK />
          </SummarySection>

          <SummarySection
            title="Forecast Visualization"
            description="Recursive rollout from the observed state through K=1, K=2, K=3 and K=5, annotated with real test-partition RMSE at each step."
          >
            <ForecastFlowDiagram testMetrics={testMetrics} example={example} />
          </SummarySection>

          <SummarySection
            title="Future Network State"
            description="Inspect the network-state vector forecast produced by the frozen LSTM World Model."
          >
            <FutureNetworkState summary={futureStateSummary} samples={futureStateSamples} />
          </SummarySection>

          <SummarySection title="Important Result: Error Accumulation">
            <ErrorAccumulationCaveat testMetrics={testMetrics} />
          </SummarySection>

          <SummarySection title="Outlier Caveat">
            <OutlierCaveat diagnostics={outliers} />
          </SummarySection>

          <SummarySection title="What This Page Does Not Claim">
            <ForecastingScopeNotes />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
