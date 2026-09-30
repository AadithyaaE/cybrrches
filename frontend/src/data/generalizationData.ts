/**
 * Source: results/frozen_generalization/per_attack_family_metrics.csv and
 * results/frozen_generalization/generalization_report.txt (Feature 16).
 * The frozen (never retrained) pipeline evaluated on 3 external CSE-CIC-IDS2018
 * capture days. This is a TRANSFER / GENERALIZATION DIAGNOSTIC, not attack-family
 * classification accuracy - the classifier was only ever trained on a binary
 * benign-vs-Infiltration view.
 */

export interface AttackFamilyGeneralization {
  day: string;
  attackFamily: string;
  nSequences: number;
  detectedAsAttackCount: number;
  detectionRecall: number;
  note: string;
}

export const PER_ATTACK_FAMILY_METRICS: AttackFamilyGeneralization[] = [
  {
    day: "Wednesday-28-02-2018",
    attackFamily: "Infilteration",
    nSequences: 5789,
    detectedAsAttackCount: 4763,
    detectionRecall: 0.8228,
    note: "Direct, training-label-compatible detection recall.",
  },
  {
    day: "Wednesday-14-02-2018",
    attackFamily: "FTP-BruteForce",
    nSequences: 5826,
    detectedAsAttackCount: 3686,
    detectionRecall: 0.6327,
    note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family.",
  },
  {
    day: "Wednesday-14-02-2018",
    attackFamily: "SSH-Bruteforce",
    nSequences: 5442,
    detectedAsAttackCount: 3766,
    detectionRecall: 0.692,
    note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family.",
  },
  {
    day: "Wednesday-21-02-2018",
    attackFamily: "DDOS attack-HOIC",
    nSequences: 1332,
    detectedAsAttackCount: 1332,
    detectionRecall: 1.0,
    note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family.",
  },
  {
    day: "Wednesday-21-02-2018",
    attackFamily: "DDOS attack-LOIC-UDP",
    nSequences: 458,
    detectedAsAttackCount: 1,
    detectionRecall: 0.0022,
    note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family.",
  },
];

export const GENERALIZATION_KNOWN_FAILURE_FAMILY = "DDOS attack-LOIC-UDP";

export const GENERALIZATION_SOURCE = "results/frozen_generalization/per_attack_family_metrics.csv";

/**
 * Verbatim "SCOPE / HONESTY NOTES" from results/frozen_generalization/generalization_report.txt,
 * plus one additional OBSERVED note computed from generalization_metrics.json
 * (Wednesday-21-02-2018 LSTM one-step regression: mse=10647.78, worst_sample_mse=206446.06, n=1870).
 */
export const RESEARCH_LIMITATIONS: string[] = [
  "External attack families (FTP-BruteForce, SSH-Bruteforce, DDOS-HOIC, DDOS-LOIC-UDP) are transfer/generalization diagnostics of a model trained only on a benign-vs-Infiltration view, not validated attack-family classification.",
  "MITRE evidence for external data was generated without destination-port diversity or a traffic-growth baseline, so Discovery/Reconnaissance/Impact-growth rules may show reduced or no evidence for that reason alone, not necessarily because the underlying behaviour is absent.",
  "No ATT&CK ground truth exists for any external day; no stage-mapping accuracy is reported.",
  "Explainability and MITRE evidence for external days were computed on a small deterministic sample (10 sequences per day, evenly spaced) for computational cost reasons.",
  "Attack-progression-probability results for Wednesday-14 and Wednesday-21 are transfer/generalization diagnostics of an Infiltration-trained model on unseen attack families, not validated probabilities of FTP brute force or DDoS.",
  "OBSERVED: Wednesday-21-02-2018 one-step LSTM forecasting error (MSE = 10,647.78, n = 1,870) is strongly outlier-dominated - the single worst sequence alone reaches MSE = 206,446.06, roughly 19x the day's mean.",
  "OBSERVED: DDOS attack-LOIC-UDP (Wednesday-21-02-2018) is a known frozen-generalization failure case - detection recall is 0.22% (1 of 458 sequences detected as attack).",
];
