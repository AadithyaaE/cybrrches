import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import FrozenEvaluationBanner from "../components/generalization/FrozenEvaluationBanner";
import WhatIsGeneralization from "../components/generalization/WhatIsGeneralization";
import DatasetOverview from "../components/generalization/DatasetOverview";
import AttackFamilyResults from "../components/generalization/AttackFamilyResults";
import CaptureDayComparison from "../components/generalization/CaptureDayComparison";
import ForecastingGeneralizationView from "../components/generalization/ForecastingGeneralizationView";
import ImportantResults from "../components/generalization/ImportantResults";
import ForecastingDetectionConnection from "../components/generalization/ForecastingDetectionConnection";
import DataQualityCaveats from "../components/generalization/DataQualityCaveats";
import WhatThisDoesNotProve from "../components/generalization/WhatThisDoesNotProve";
import GeneralizationFlow from "../components/generalization/GeneralizationFlow";
import { getFrozenGeneralizationOverview, type FrozenGeneralizationOverview } from "../services/frozenGeneralizationService";
import "./GeneralizationPage.css";

export default function GeneralizationPage() {
  const [overview, setOverview] = useState<FrozenGeneralizationOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getFrozenGeneralizationOverview()
      .then(setOverview)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load generalization data."));
  }, []);

  return (
    <div>
      <SectionHeader
        title="Generalization"
        description="How does the frozen CyberChess pipeline behave when evaluated on other attack-containing network captures that were not used to train/retrain the models?"
        actions={
          <div className="generalization-page__badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Not Live Detection" tone="info" dot={false} />
          </div>
        }
      />

      <FrozenEvaluationBanner />

      {error && (
        <SummarySection title="Unable to load generalization data">
          <p className="generalization-page__error">{error}</p>
        </SummarySection>
      )}

      {!overview && !error && <p className="generalization-page__loading">Loading generalization artifacts...</p>}

      {overview && (
        <div className="generalization-page__sections">
          <SummarySection title="What Is Generalization?">
            <WhatIsGeneralization />
          </SummarySection>

          <SummarySection
            title="Dataset / Capture Overview"
            description="The development dataset versus the 3 frozen external evaluation capture days."
          >
            <DatasetOverview datasetSummary={overview.datasetSummary} />
          </SummarySection>

          <SummarySection
            title="Attack-Family Results"
            evalLabel="Transfer / Generalization Diagnostic"
            description="Real per-attack-family binary anomaly-detection recall from the frozen classifier."
          >
            <AttackFamilyResults rows={overview.attackFamilyMetrics} />
          </SummarySection>

          <SummarySection
            title="Capture / Day Comparison"
            description="Real frozen-pipeline binary attack metrics for each external capture day, across all 4 evaluated models."
          >
            <CaptureDayComparison rows={overview.binaryAttackMetrics} modelLabels={overview.modelLabels} />
          </SummarySection>

          <SummarySection
            title="Forecasting Generalization"
            description="Real K-step (K=1,2,3,5) World Model forecasting error on each external capture day."
          >
            <ForecastingGeneralizationView rows={overview.forecastingGeneralization} />
          </SummarySection>

          <SummarySection title="Important Results">
            <ImportantResults wed21Outlier={overview.wed21LstmOutlier} />
          </SummarySection>

          <SummarySection
            title="Forecasting / Detection Connection"
            description="A diagnostic comparison on Wednesday-21-02-2018 between the oracle and full-pipeline classifier."
          >
            <ForecastingDetectionConnection />
          </SummarySection>

          <SummarySection title="Data Quality / Generalization Caveats">
            <DataQualityCaveats caveats={overview.dataQualityCaveats} />
          </SummarySection>

          <SummarySection title="What This Does Not Prove">
            <WhatThisDoesNotProve notProven={overview.notProven} doesProvide={overview.doesProvide} />
          </SummarySection>

          <SummarySection title="Simple CyberChess Interpretation">
            <GeneralizationFlow />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
