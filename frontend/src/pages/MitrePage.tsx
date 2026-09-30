import { useEffect, useState } from "react";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import SummarySection from "../components/overview/SummarySection";
import WhatIsMitre from "../components/mitre/WhatIsMitre";
import AttackStageMap from "../components/mitre/AttackStageMap";
import EvidenceRules from "../components/mitre/EvidenceRules";
import ExampleAuditRecord from "../components/mitre/ExampleAuditRecord";
import StageDistribution from "../components/mitre/StageDistribution";
import MitreLimitations from "../components/mitre/MitreLimitations";
import MitreFlow from "../components/mitre/MitreFlow";
import { getMitreOverview, type MitreOverview } from "../services/mitreService";
import "./MitrePage.css";

export default function MitrePage() {
  const [overview, setOverview] = useState<MitreOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getMitreOverview()
      .then(setOverview)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load MITRE ATT&CK data."));
  }, []);

  return (
    <div>
      <SectionHeader
        title="MITRE ATT&CK"
        description="Transparent, rule-based evidence mapping from network-behaviour evidence to candidate ATT&CK stages and techniques."
        actions={
          <div className="mitre-page__badges">
            <StatusBadge label="Offline Research" tone="warning" />
            <StatusBadge label="Rule-Based Evidence Mapping" tone="info" dot={false} />
          </div>
        }
      />

      {error && (
        <SummarySection title="Unable to load MITRE ATT&CK data">
          <p className="mitre-page__error">{error}</p>
        </SummarySection>
      )}

      {!overview && !error && <p className="mitre-page__loading">Loading MITRE ATT&CK artifacts...</p>}

      {overview && (
        <div className="mitre-page__sections">
          <SummarySection title="What Is MITRE ATT&CK?">
            <WhatIsMitre />
          </SummarySection>

          <SummarySection
            title="Attack Stage Map"
            description="The 7 stages Feature 14 evaluates, their mapped MITRE ATT&CK technique, and whether that mapping is treated as confirmed or candidate-only."
          >
            <AttackStageMap
              stageTechniques={overview.stageTechniques}
              stageStatus={overview.stageStatus}
              stageMaxScore={overview.stageMaxScore}
            />
          </SummarySection>

          <SummarySection
            title="Evidence / Rules"
            description="Every deterministic rule Feature 14 evaluates, grouped by stage, with its real trigger count across all 17,460 audit records."
          >
            <EvidenceRules rules={overview.rules} evidenceFeatureAvailability={overview.evidenceFeatureAvailability} />
          </SummarySection>

          <SummarySection title="Example Audit Record">
            <ExampleAuditRecord />
          </SummarySection>

          <SummarySection title="Stage Distribution">
            <StageDistribution
              distribution={overview.primaryStageDistribution}
              totalAuditRecords={overview.totalAuditRecords}
              sampleCounts={overview.sampleCounts}
            />
          </SummarySection>

          <SummarySection title="Simple CyberChess Interpretation">
            <MitreFlow />
          </SummarySection>

          <SummarySection title="Limitations / Research Honesty">
            <MitreLimitations />
          </SummarySection>
        </div>
      )}
    </div>
  );
}
