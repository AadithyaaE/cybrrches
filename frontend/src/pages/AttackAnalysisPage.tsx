import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import WhatIsAttackProgression from "../components/attackanalysis/WhatIsAttackProgression";
import KStepSummary from "../components/attackanalysis/KStepSummary";
import HorizonView from "../components/attackanalysis/HorizonView";
import TestLimitationSection from "../components/attackanalysis/TestLimitationSection";
import CyberChessWorkflow from "../components/attackanalysis/CyberChessWorkflow";
import AttackAnalysisHonesty from "../components/attackanalysis/AttackAnalysisHonesty";
import SequenceProbabilityExplorer from "../components/attackanalysis/SequenceProbabilityExplorer";
import {
  getAttackProgressionMetrics,
  getAttackProgressionSequenceSummary,
  getAttackProgressionSequences,
} from "../services/attackAnalysisService";
import type { AttackProgressionMetric } from "../data/attackProgressionData";
import type { AttackProgressionSequenceSummary, AttackProgressionSequenceSample } from "../types/attackProgressionSequence";
import "./AttackAnalysisPage.css";

export default function AttackAnalysisPage() {
  const [metrics, setMetrics] = useState<AttackProgressionMetric[] | null>(null);
  const [sequenceSummary, setSequenceSummary] = useState<AttackProgressionSequenceSummary | null>(null);
  const [sequenceSamples, setSequenceSamples] = useState<AttackProgressionSequenceSample[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getAttackProgressionMetrics(), getAttackProgressionSequenceSummary(), getAttackProgressionSequences()])
      .then(([metricsRes, summaryRes, samplesRes]) => {
        setMetrics(metricsRes);
        setSequenceSummary(summaryRes);
        setSequenceSamples(samplesRes);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load attack analysis data."));
  }, []);

  return (
    <div>
      <SectionHeader
        title="Attack Analysis"
        description="How consistent is the forecast future network state with the attack-progression pattern the classifier learned?"
        actions={
          <div className="attack-analysis-page__badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Frozen Evaluation" tone="info" dot={false} />
          </div>
        }
      />

      {error && (
        <SummarySection title="Unable to load attack analysis data">
          <p className="attack-analysis-page__error">{error}</p>
        </SummarySection>
      )}

      {!metrics && !error && <p className="attack-analysis-page__loading">Loading attack analysis artifacts...</p>}

      {metrics && sequenceSummary && sequenceSamples && (
        <div className="attack-analysis-page__sections">
          <SummarySection title="What Is Attack Progression?">
            <WhatIsAttackProgression />
          </SummarySection>

          <SummarySection
            title="K-Step Summary"
            evalLabel="Validation Evaluation"
            description="Feature 13 attack-progression metrics for K=1, 2, 3, 5, distinguishing the deployable Full Pipeline path from the Oracle Diagnostic upper bound."
          >
            <KStepSummary metrics={metrics} />
          </SummarySection>

          <SummarySection
            title="Horizon View"
            description="How full-pipeline validation metrics change from K=1 to K=5."
          >
            <HorizonView metrics={metrics} />
          </SummarySection>

          <SummarySection title="Test Limitation">
            <TestLimitationSection metrics={metrics} />
          </SummarySection>

          <SummarySection title="Simple CyberChess Interpretation">
            <CyberChessWorkflow />
          </SummarySection>

          <SummarySection
            title="Sequence Probability Explorer"
            description="Inspect the actual predicted_infiltration_probability the frozen classifier produced for representative TEST-partition sequences."
          >
            <SequenceProbabilityExplorer summary={sequenceSummary} samples={sequenceSamples} />
          </SummarySection>

          <SummarySection title="Research Honesty">
            <AttackAnalysisHonesty />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
