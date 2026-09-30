/**
 * Source: results/mitre/mitre_stage_rule_definitions.json (Feature 14).
 * Deterministic, RULE-BASED EVIDENCE MAPPING from network-behaviour stages to
 * MITRE ATT&CK techniques. There is no ATT&CK ground truth in this dataset,
 * so this is evidence mapping, not verified technique attribution or accuracy.
 */

export interface MitreMapping {
  stage: string;
  techniqueId: string;
  techniqueName: string;
  candidate: boolean;
}

export const MITRE_TECHNIQUE_MAP: MitreMapping[] = [
  { stage: "Discovery", techniqueId: "T1046", techniqueName: "Network Service Discovery", candidate: false },
  { stage: "Command and Control", techniqueId: "T1071", techniqueName: "Application Layer Protocol (C2)", candidate: false },
  { stage: "Exfiltration", techniqueId: "T1041", techniqueName: "Exfiltration Over C2 Channel", candidate: false },
  { stage: "Impact", techniqueId: "T1498", techniqueName: "Network Denial of Service", candidate: false },
  { stage: "Reconnaissance", techniqueId: "T1595", techniqueName: "Active Scanning", candidate: true },
  { stage: "Initial Access", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", candidate: true },
  { stage: "Lateral Movement", techniqueId: "T1021", techniqueName: "Remote Services", candidate: true },
];

export const MITRE_SOURCE = "results/mitre/mitre_stage_rule_definitions.json";
