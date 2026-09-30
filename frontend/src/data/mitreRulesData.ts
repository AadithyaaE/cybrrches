/**
 * Source (read directly, all values real): results/mitre/mitre_stage_rule_definitions.json
 * and results/mitre/mitre_stage_mapping_metrics.json (Feature 14).
 *
 * This is a deterministic, rule-based EVIDENCE MAPPING, not a trained model
 * and not ATT&CK ground truth. Stage "evidence_score" is a Stage Evidence
 * Score (0-100), never a probability, model confidence, or prediction
 * accuracy. data/mitreData.ts (Frontend Feature 2) already holds the 7-stage
 * technique_map and is reused here unmodified.
 */

export type MappingStatus = "mapped" | "candidate";

export interface MitreRule {
  ruleId: string;
  stage: string;
  techniqueId: string;
  techniqueName: string;
  conditions: string[];
  supportingFeatures: string[];
  scoreContribution: number;
  explanation: string;
  limitation: string;
  triggerCount: number;
}

export const MITRE_RULES: MitreRule[] = [
  {
    ruleId: "discovery_high_port_diversity",
    stage: "Discovery",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    conditions: ["dst_port_nunique >= 10"],
    supportingFeatures: ["dst_port_nunique"],
    scoreContribution: 40,
    explanation: "A high number of distinct destination ports contacted within a single 1-second window is consistent with network service discovery.",
    limitation: "Flow telemetry cannot independently establish attacker intent; high port diversity can also occur from legitimate multi-service clients.",
    triggerCount: 225,
  },
  {
    ruleId: "discovery_repeated_short_flows",
    stage: "Discovery",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    conditions: ["observation_count >= 5", "flow_duration_mean_us <= 1000000"],
    supportingFeatures: ["observation_count", "Flow Duration"],
    scoreContribution: 30,
    explanation: "Repeated short-duration connections across multiple destination ports are consistent with network service discovery.",
    limitation: "Short flows can also result from normal application behaviour (e.g. health checks, keep-alives).",
    triggerCount: 434,
  },
  {
    ruleId: "discovery_low_bytes_per_flow",
    stage: "Discovery",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    conditions: ["avg_bytes_per_flow <= 200"],
    supportingFeatures: ["TotLen Fwd Pkts", "observation_count"],
    scoreContribution: 15,
    explanation: "Low bytes transferred per flow is consistent with probing rather than substantive data transfer.",
    limitation: "Low-byte flows are common in many benign protocols (DNS, health checks); this is weak supporting evidence only.",
    triggerCount: 991,
  },
  {
    ruleId: "c2_regular_beacon_timing",
    stage: "Command and Control",
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol (C2)",
    conditions: ["flow_iat_coefficient_of_variation <= 0.3"],
    supportingFeatures: ["Flow IAT Mean", "Flow IAT Std"],
    scoreContribution: 35,
    explanation: "Relatively regular inter-arrival timing (low variability) is consistent with beacon-like command-and-control traffic.",
    limitation: "Cannot confirm a specific T1071 sub-technique or a repeated destination, because source/destination IP is not present in this dataset; regular timing alone can also reflect legitimate polling/heartbeat traffic.",
    triggerCount: 2548,
  },
  {
    ruleId: "c2_persistent_bidirectional_traffic",
    stage: "Command and Control",
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol (C2)",
    conditions: ["Tot Fwd Pkts > 0", "Tot Bwd Pkts > 0", "observation_count >= 2"],
    supportingFeatures: ["Tot Fwd Pkts", "Tot Bwd Pkts", "observation_count"],
    scoreContribution: 25,
    explanation: "Persistent, bidirectional communication is consistent with an established command-and-control channel.",
    limitation: "Bidirectional traffic is the norm for almost all legitimate TCP sessions; only meaningful in combination with regular timing.",
    triggerCount: 3188,
  },
  {
    ruleId: "exfil_high_outbound_volume",
    stage: "Exfiltration",
    techniqueId: "T1041",
    techniqueName: "Exfiltration Over C2 Channel",
    conditions: ["flow_byts_per_s >= 500000"],
    supportingFeatures: ["Flow Byts/s"],
    scoreContribution: 40,
    explanation: "Unusually high outbound transfer volume relative to typical flow rates is consistent with possible data exfiltration.",
    limitation: "High-throughput legitimate transfers (backups, large downloads) produce the same signature; data content/destination cannot be verified.",
    triggerCount: 2498,
  },
  {
    ruleId: "exfil_high_outbound_inbound_ratio",
    stage: "Exfiltration",
    techniqueId: "T1041",
    techniqueName: "Exfiltration Over C2 Channel",
    conditions: ["outbound_inbound_byte_ratio >= 10.0"],
    supportingFeatures: ["TotLen Fwd Pkts", "TotLen Bwd Pkts"],
    scoreContribution: 35,
    explanation: "The flow shows unusually large outbound transfer volume relative to inbound traffic, which is consistent with possible data exfiltration.",
    limitation: "Never claims that data was actually exfiltrated; asymmetric flows are also produced by e.g. uploads, backups, telemetry.",
    triggerCount: 5038,
  },
  {
    ruleId: "impact_high_rate_and_growth",
    stage: "Impact",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    conditions: ["flow_pkts_per_s >= 200", "traffic_growth_pct >= 150.0"],
    supportingFeatures: ["Flow Pkts/s", "traffic_growth_pct"],
    scoreContribution: 50,
    explanation: "Traffic volume and growth indicate a network availability-disruption pattern consistent with Network Denial of Service.",
    limitation: "Interpretable evidence only; does not override Random Forest, LSTM, or Feature 13 predictions.",
    triggerCount: 9856,
  },
  {
    ruleId: "impact_elevated_volume_or_frequency",
    stage: "Impact",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    conditions: ["flow_pkts_per_s >= 200", "OR flow_byts_per_s >= 500000", "OR connection_frequency >= 15"],
    supportingFeatures: ["Flow Pkts/s", "Flow Byts/s", "observation_count"],
    scoreContribution: 30,
    explanation: "Elevated packet rate, byte rate, or connection frequency (any one) is consistent with a network-availability-disruption pattern.",
    limitation: "Interpretable evidence only; a single elevated metric does not confirm an active DoS condition.",
    triggerCount: 16459,
  },
  {
    ruleId: "recon_port_scanning_pattern",
    stage: "Reconnaissance",
    techniqueId: "T1595",
    techniqueName: "Active Scanning (candidate)",
    conditions: ["dst_port_nunique >= 5", "flow_duration_mean_us <= 1000000"],
    supportingFeatures: ["dst_port_nunique", "Flow Duration"],
    scoreContribution: 45,
    explanation: "The observed network probing behaviour is consistent with reconnaissance activity, but the available flow telemetry cannot establish attacker intent.",
    limitation: "CANDIDATE mapping only, score capped at 55/100: the flow dataset cannot reliably distinguish external reconnaissance from internal discovery.",
    triggerCount: 274,
  },
  {
    ruleId: "initial_access_suspicious_connection_pattern",
    stage: "Initial Access",
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application (candidate)",
    conditions: ["SYN Flag Cnt > 0", "ACK Flag Cnt < SYN Flag Cnt"],
    supportingFeatures: ["SYN Flag Cnt", "ACK Flag Cnt"],
    scoreContribution: 40,
    explanation: "The observed traffic is consistent with an attempted network-entry pattern (connection attempts without full handshake completion), but flow telemetry alone cannot confirm successful compromise.",
    limitation: "CANDIDATE mapping only, score capped at 50/100: no process, authentication, or host telemetry is available in this dataset; successful Initial Access can never be confirmed from flow data alone.",
    triggerCount: 55,
  },
  {
    ruleId: "lateral_movement_internal_destination_count",
    stage: "Lateral Movement",
    techniqueId: "T1021",
    techniqueName: "Remote Services (candidate)",
    conditions: ["NOT COMPUTABLE: requires source/destination IP addresses, which are absent from this dataset"],
    supportingFeatures: [],
    scoreContribution: 0,
    explanation: "Lateral movement evidence requires tracking one source contacting multiple internal destinations, which requires IP-address identity information.",
    limitation: "STRUCTURALLY UNAVAILABLE for this dataset: CSE-CIC-IDS2018's processed flow CSVs do not include source or destination IP addresses. This rule can never fire on this data; Lateral Movement will always report UNKNOWN/INSUFFICIENT_EVIDENCE here. This is a data limitation, not a mapper defect.",
    triggerCount: 0,
  },
];

/**
 * Exact technique_map from mitre_stage_rule_definitions.json, one row per
 * stage, with technique_name exactly as the artifact stores it (including
 * the literal "(candidate)" suffix where present) - the artifact is the
 * source of truth for wording, per the Feature 6 spec.
 */
export interface StageTechnique {
  stage: string;
  techniqueId: string;
  techniqueName: string;
}

export const STAGE_TECHNIQUES: StageTechnique[] = [
  { stage: "Discovery", techniqueId: "T1046", techniqueName: "Network Service Discovery" },
  { stage: "Command and Control", techniqueId: "T1071", techniqueName: "Application Layer Protocol (C2)" },
  { stage: "Exfiltration", techniqueId: "T1041", techniqueName: "Exfiltration Over C2 Channel" },
  { stage: "Impact", techniqueId: "T1498", techniqueName: "Network Denial of Service" },
  { stage: "Reconnaissance", techniqueId: "T1595", techniqueName: "Active Scanning (candidate)" },
  { stage: "Initial Access", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application (candidate)" },
  { stage: "Lateral Movement", techniqueId: "T1021", techniqueName: "Remote Services (candidate)" },
];

export const STAGE_MAX_SCORE: Record<string, number | null> = {
  Discovery: 100,
  "Command and Control": 100,
  Exfiltration: 100,
  Impact: 100,
  Reconnaissance: 55,
  "Initial Access": 50,
  "Lateral Movement": 0,
};

export const STAGE_STATUS: Record<string, MappingStatus> = {
  Discovery: "mapped",
  "Command and Control": "mapped",
  Exfiltration: "mapped",
  Impact: "mapped",
  Reconnaissance: "candidate",
  "Initial Access": "candidate",
  "Lateral Movement": "candidate",
};

export const EVIDENCE_LABEL_BANDS = {
  LOW: "0-29",
  MEDIUM: "30-59",
  HIGH: "60-79",
  "VERY HIGH": "80-100",
};

export const MIN_EVIDENCE_THRESHOLD_FOR_PRIMARY_STAGE = 30;

/** Real primary_stage distribution across all 17,460 audit records (3,492 validation sequences x 5 evidence points each). */
export const PRIMARY_STAGE_DISTRIBUTION: Record<string, number> = {
  Impact: 12828,
  Exfiltration: 2356,
  "Command and Control": 1183,
  "UNKNOWN / INSUFFICIENT_EVIDENCE": 676,
  Discovery: 327,
  Reconnaissance: 61,
  "Initial Access": 29,
};

export const TOTAL_AUDIT_RECORDS = 17460;
export const SAMPLE_COUNTS = {
  sequences: 3492,
  evidencePointsPerSequence: 5,
};

export const RULES_NEVER_TRIGGERED = ["lateral_movement_internal_destination_count"];

/**
 * Real per-field evidence-feature availability (Feature 14 metrics JSON):
 * OBSERVED evidence has 100% availability for all fields; several fields
 * (dst_port_nunique, observation_count, avg_bytes_per_flow,
 * connection_frequency) are 0% available on PREDICTED (LSTM-forecast)
 * evidence at every horizon, because they are Feature 6 window metadata,
 * not part of the 68-dimensional LSTM state vector.
 */
export interface EvidenceFeatureAvailability {
  feature: string;
  observedAvailabilityPct: number;
  predictedAvailabilityPctByHorizon: Record<string, number>;
}

export const EVIDENCE_FEATURE_AVAILABILITY: EvidenceFeatureAvailability[] = [
  { feature: "dst_port_nunique", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 0.0, "2": 0.0, "3": 0.0, "5": 0.0 } },
  { feature: "flow_duration_mean_us", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 100.0, "2": 100.0, "3": 100.0, "5": 100.0 } },
  { feature: "observation_count", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 0.0, "2": 0.0, "3": 0.0, "5": 0.0 } },
  { feature: "avg_bytes_per_flow", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 0.0, "2": 0.0, "3": 0.0, "5": 0.0 } },
  { feature: "flow_iat_coefficient_of_variation", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 99.4, "2": 99.7, "3": 99.8, "5": 99.9 } },
  { feature: "outbound_inbound_byte_ratio", observedAvailabilityPct: 95.6, predictedAvailabilityPctByHorizon: { "1": 94.7, "2": 94.8, "3": 96.0, "5": 98.2 } },
  { feature: "connection_frequency", observedAvailabilityPct: 100.0, predictedAvailabilityPctByHorizon: { "1": 0.0, "2": 0.0, "3": 0.0, "5": 0.0 } },
];

/** One real audit record from mitre_stage_mapping_metrics.json's "example_audit_record" - sequence 15670, observed_t. */
export const EXAMPLE_AUDIT_RECORD = {
  sequenceId: 15670,
  evidencePoint: "observed_t",
  timestamp: "2018-03-01 10:12:32",
  primaryStage: "Command and Control",
  stageScores: [
    { stage: "Discovery", score: 30.0, label: "MEDIUM", triggeredRules: ["discovery_repeated_short_flows"] },
    { stage: "Command and Control", score: 60.0, label: "HIGH", triggeredRules: ["c2_regular_beacon_timing", "c2_persistent_bidirectional_traffic"] },
    { stage: "Exfiltration", score: 0.0, label: "LOW", triggeredRules: [] },
    { stage: "Impact", score: 0.0, label: "LOW", triggeredRules: [] },
    { stage: "Reconnaissance", score: 0.0, label: "LOW", triggeredRules: [] },
    { stage: "Initial Access", score: 40.0, label: "MEDIUM", triggeredRules: ["initial_access_suspicious_connection_pattern"] },
    { stage: "Lateral Movement", score: 0.0, label: "LOW", triggeredRules: [] },
  ],
};

export const MITRE_LIMITATIONS: string[] = [
  "No ATT&CK ground-truth stage labels exist in this dataset (only Benign/Infilteration binary labels), so ATT&CK classification accuracy, precision, recall and F1 cannot be claimed or computed.",
  "Lateral Movement evidence is structurally unavailable: this dataset has no source/destination IP addresses, so internal-destination-count evidence can never be computed here - it will always report UNKNOWN/INSUFFICIENT_EVIDENCE.",
  "PREDICTED evidence (from the LSTM forecast state) lacks dst_port_nunique, observation_count, avg_bytes_per_flow and connection_frequency, because these are Feature 6 window metadata, not part of the 68-dimensional LSTM state vector - so Discovery/Reconnaissance rules that depend on them can only fire on OBSERVED evidence, never on PREDICTED evidence.",
  "Reconnaissance and Initial Access are explicitly capped as CANDIDATE-only mappings (55/100 and 50/100 respectively) because flow telemetry cannot establish attacker intent or confirm compromise.",
  "The Impact rule's thresholds (packet rate, byte rate, connection frequency, traffic growth) are fixed, hand-specified calibration values, not learned from data, and do not override the Random Forest, LSTM, or Feature 13 predictions.",
  "This is deterministic, rule-based evidence mapping - not a trained model, not proof of attacker intent, and it carries no learned generalization guarantees.",
];

export const MITRE_SOURCES = {
  ruleDefinitions: "results/mitre/mitre_stage_rule_definitions.json",
  metrics: "results/mitre/mitre_stage_mapping_metrics.json",
  report: "results/mitre/mitre_stage_mapping_report.txt",
};
