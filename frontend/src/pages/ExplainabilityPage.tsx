import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import WhatIsExplainability from "../components/explainability/WhatIsExplainability";
import PredictionEvidenceFlow from "../components/explainability/PredictionEvidenceFlow";
import ExampleSelector from "../components/explainability/ExampleSelector";
import ClassifierAttribution from "../components/explainability/ClassifierAttribution";
import LstmOcclusionAttribution from "../components/explainability/LstmOcclusionAttribution";
import TopFeatures from "../components/explainability/TopFeatures";
import LlmExplanationLayer from "../components/explainability/LlmExplanationLayer";
import ReproducibilityChecks from "../components/explainability/ReproducibilityChecks";
import ExplainabilityLimitations from "../components/explainability/ExplainabilityLimitations";
import ExplainabilityFlow from "../components/explainability/ExplainabilityFlow";
import { getExplainabilityOverview, getExplanationExamples, type ExplainabilityOverview } from "../services/explainabilityService";
import type { ExplanationExample } from "../types/explainability";
import "./ExplainabilityPage.css";

export default function ExplainabilityPage() {
  const [overview, setOverview] = useState<ExplainabilityOverview | null>(null);
  const [examples, setExamples] = useState<ExplanationExample[] | null>(null);
  const [selectedSequenceId, setSelectedSequenceId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getExplainabilityOverview(), getExplanationExamples()])
      .then(([overviewRes, examplesRes]) => {
        setOverview(overviewRes);
        setExamples(examplesRes);
        setSelectedSequenceId(examplesRes[0]?.sequence_id ?? null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load explainability data."));
  }, []);

  const selectedExample = examples?.find((e) => e.sequence_id === selectedSequenceId) ?? examples?.[0] ?? null;

  return (
    <div>
      <SectionHeader
        title="Explainability"
        description="Model-grounded attribution for the frozen LSTM World Model + classifier forecasting path."
        actions={
          <div className="explainability-page__badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Validation Evaluation" tone="info" dot={false} />
          </div>
        }
      />

      {error && (
        <SummarySection title="Unable to load explainability data">
          <p className="explainability-page__error">{error}</p>
        </SummarySection>
      )}

      {!overview && !error && <p className="explainability-page__loading">Loading explainability artifacts...</p>}

      {overview && examples && selectedExample && (
        <div className="explainability-page__sections">
          <SummarySection title="What Is Explainability?">
            <WhatIsExplainability />
          </SummarySection>

          <SummarySection title="Prediction → Evidence Flow">
            <PredictionEvidenceFlow />
          </SummarySection>

          <SummarySection
            title="Attribution Example Selector"
            description="20 deterministic, evenly-spaced VALIDATION sequences were selected for the expensive per-cell occlusion analysis. Pick one to inspect its classifier and LSTM attributions below."
          >
            <ExampleSelector examples={examples} selectedSequenceId={selectedExample.sequence_id} onSelect={setSelectedSequenceId} />
          </SummarySection>

          <SummarySection
            title="Classifier Attribution"
            evalLabel="Exact"
            description="Layer C: an exact decomposition of the linear classifier's logit for the selected sequence's forecast state."
          >
            <ClassifierAttribution
              example={selectedExample}
              groundingCheckMaxDiff={overview.classifierAttributionGroundingCheckMaxDiff}
            />
          </SummarySection>

          <SummarySection
            title="LSTM Temporal / Feature Occlusion"
            evalLabel="Approximate"
            description="Layer D: perturbation-based occlusion diagnostics for the LSTM's temporal behaviour."
          >
            <LstmOcclusionAttribution example={selectedExample} occlusionBaseline={overview.config.occlusionBaseline} />
          </SummarySection>

          <SummarySection
            title="Top Features"
            description="Real global feature importance, ranked by mean |Layer-C contribution| across all 3,492 validation sequences."
          >
            <TopFeatures features={overview.globalFeatureImportance} />
          </SummarySection>

          <SummarySection title="LLM Explanation Layer">
            <LlmExplanationLayer status={overview.llmStatus} promptRules={overview.llmPromptRules} />
          </SummarySection>

          <SummarySection title="Reproducibility / Checks">
            <ReproducibilityChecks
              evaluationChecks={overview.evaluationChecks}
              leakageChecks={overview.leakageChecks}
              reproducibility={overview.reproducibility}
            />
          </SummarySection>

          <SummarySection title="Research Limitations">
            <ExplainabilityLimitations />
          </SummarySection>

          <SummarySection title="Simple CyberChess Interpretation">
            <ExplainabilityFlow />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
