import {
  STAGE_TECHNIQUES,
  STAGE_STATUS,
  STAGE_MAX_SCORE,
  MITRE_RULES,
  PRIMARY_STAGE_DISTRIBUTION,
  TOTAL_AUDIT_RECORDS,
  SAMPLE_COUNTS,
  EVIDENCE_FEATURE_AVAILABILITY,
  EXAMPLE_AUDIT_RECORD,
  MITRE_LIMITATIONS,
  EVIDENCE_LABEL_BANDS,
  MIN_EVIDENCE_THRESHOLD_FOR_PRIMARY_STAGE,
  type StageTechnique,
  type MitreRule,
  type MappingStatus,
  type EvidenceFeatureAvailability,
} from "../data/mitreRulesData";

/**
 * Data access for the MITRE ATT&CK page (Frontend Feature 6). All data is
 * small (12 rules, 7 stages), so it is bundled as typed constants (see
 * data/mitreRulesData.ts, read directly from results/mitre/) rather than
 * fetched, but exposed as async functions matching the seam used by the
 * other services, so a future API can replace the implementation without
 * changing consuming components.
 */

export interface MitreOverview {
  stageTechniques: StageTechnique[];
  stageStatus: Record<string, MappingStatus>;
  stageMaxScore: Record<string, number | null>;
  rules: MitreRule[];
  primaryStageDistribution: Record<string, number>;
  totalAuditRecords: number;
  sampleCounts: { sequences: number; evidencePointsPerSequence: number };
  evidenceFeatureAvailability: EvidenceFeatureAvailability[];
  exampleAuditRecord: typeof EXAMPLE_AUDIT_RECORD;
  limitations: string[];
  evidenceLabelBands: Record<string, string>;
  minEvidenceThresholdForPrimaryStage: number;
}

export function getMitreOverview(): Promise<MitreOverview> {
  return Promise.resolve({
    stageTechniques: STAGE_TECHNIQUES,
    stageStatus: STAGE_STATUS,
    stageMaxScore: STAGE_MAX_SCORE,
    rules: MITRE_RULES,
    primaryStageDistribution: PRIMARY_STAGE_DISTRIBUTION,
    totalAuditRecords: TOTAL_AUDIT_RECORDS,
    sampleCounts: SAMPLE_COUNTS,
    evidenceFeatureAvailability: EVIDENCE_FEATURE_AVAILABILITY,
    exampleAuditRecord: EXAMPLE_AUDIT_RECORD,
    limitations: MITRE_LIMITATIONS,
    evidenceLabelBands: EVIDENCE_LABEL_BANDS,
    minEvidenceThresholdForPrimaryStage: MIN_EVIDENCE_THRESHOLD_FOR_PRIMARY_STAGE,
  });
}
