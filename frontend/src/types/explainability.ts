export interface TopContributor {
  feature: string;
  time_step: string;
  contribution: number;
  direction: "attack" | "benign";
}

export interface TemporalPerTimestep {
  time_step: string;
  contribution: number;
  direction: "attack" | "benign";
  full_probability: number;
  occluded_probability: number;
}

export interface FeatureGroupSummaryEntry {
  feature: string;
  mean_contribution: number;
  sum_contribution: number;
  sum_abs_contribution: number;
}

export interface Feature13ProbabilityEntry {
  probability: number;
  predicted_class: number;
  actual_future_label: string;
}

export interface MitreEvidenceSummary {
  primary_stage: string;
  stage_scores: Record<string, number>;
  stage_labels: Record<string, string>;
}

export interface ExplanationExample {
  sequence_id: number;
  prediction: string;
  attack_probability: number;
  prediction_source: string;
  top_contributors: TopContributor[];
  classifier_attribution_note: string;
  temporal_summary: {
    method: string;
    per_timestep: TemporalPerTimestep[];
  };
  feature_group_summary: FeatureGroupSummaryEntry[];
  feature_13_probability: Record<string, Feature13ProbabilityEntry>;
  mitre_evidence: MitreEvidenceSummary;
  limitations: string[];
}
