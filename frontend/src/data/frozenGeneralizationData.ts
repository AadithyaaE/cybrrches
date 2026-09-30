/**
 * Source (read directly, all values real): results/frozen_generalization/
 * (dataset_summary.csv, binary_attack_metrics.csv, per_attack_family_metrics.csv,
 * forecasting_metrics.csv, prediction_summary.csv, config.json,
 * confusion_matrices/*.json, generalization_report.txt) and
 * results/external_dataset_preparation/external_dataset_verification.txt
 * (Feature 16 - FROZEN GENERALIZATION EVALUATION).
 *
 * The trained CyberChess models were kept unchanged (frozen) and evaluated
 * on 3 additional CSE-CIC-IDS2018 capture days never used for
 * training/fitting/tuning. This file holds only real artifact values.
 */

export const EXTERNAL_DAYS = ["Wednesday-28-02-2018", "Wednesday-14-02-2018", "Wednesday-21-02-2018"] as const;
export type ExternalDay = (typeof EXTERNAL_DAYS)[number];

export interface DatasetSummaryRow {
  day: ExternalDay;
  nSequences: number;
  nWindows: number;
  attackPrevalenceWindowsPct: number;
  trainingCompatibleViewApplicable: boolean;
  labelDistribution: Record<string, string>;
  timestampRange: string;
  qualityCaveat: string;
}

export const DATASET_SUMMARY: DatasetSummaryRow[] = [
  {
    day: "Wednesday-28-02-2018",
    nSequences: 22006,
    nWindows: 31854,
    attackPrevalenceWindowsPct: 22.4838,
    trainingCompatibleViewApplicable: true,
    labelDistribution: { Benign: "544,200 (88.76%)", Infilteration: "68,871 (11.24%)" },
    timestampRange: "2018-02-28 01:00:00 -> 12:59:59 (31,854 unique timestamps)",
    qualityCaveat: "READY_FOR_FROZEN_EVALUATION - no truncation signature; ~1.0% exact duplicate rows.",
  },
  {
    day: "Wednesday-14-02-2018",
    nSequences: 29091,
    nWindows: 32043,
    attackPrevalenceWindowsPct: 35.1652,
    trainingCompatibleViewApplicable: false,
    labelDistribution: { Benign: "667,626 (63.68%)", "FTP-BruteForce": "193,360 (18.44%)", "SSH-Bruteforce": "187,589 (17.89%)" },
    timestampRange: "1970-01-05 03:01:17 -> 2018-02-14 12:59:59 (32,043 unique; the 1970 minimum comes from 5 rows with implausible source-data timestamps)",
    qualityCaveat: "READY_FOR_FROZEN_EVALUATION, with caveats: contains exactly 1,048,575 rows (2^20 - 1, Excel's row-limit minus a header) - a possible upstream truncation signature, though the end timestamp (12:59:59) matches the expected full-day pattern. Also has an unusually high duplicate-row rate (~21.5%, 225,628 rows), concentrated almost entirely in the FTP-BruteForce/SSH-Bruteforce attack classes - consistent with automated brute-force tooling producing byte-identical flow records, not necessarily a pipeline artifact.",
  },
  {
    day: "Wednesday-21-02-2018",
    nSequences: 1870,
    nWindows: 3256,
    attackPrevalenceWindowsPct: 71.4681,
    trainingCompatibleViewApplicable: false,
    labelDistribution: { "DDOS attack-HOIC": "686,012 (65.42%)", Benign: "360,833 (34.42%)", "DDOS attack-LOIC-UDP": "1,730 (0.16%)" },
    timestampRange: "2018-02-21 01:55:46 -> 10:43:21 (3,256 unique; stops notably earlier than the ~12:59:59 pattern of the other days)",
    qualityCaveat: "READY_FOR_FROZEN_EVALUATION, with caveat: also contains exactly 1,048,575 rows (same Excel row-limit signature) AND the capture stops at 10:43:21, over 2 hours before the ~12:59:59 pattern in the other files - likely an incomplete capture. Results from this file should not be presented as reflecting a complete day.",
  },
];

export interface BinaryAttackMetricRow {
  day: ExternalDay;
  model: string;
  n: number;
  nPositive: number;
  nNegative: number;
  attackPrevalencePct: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  rocAuc: number;
  prAuc: number;
  fpr: number;
}

const MODEL_LABELS: Record<string, string> = {
  logistic_regression_binary: "Logistic Regression",
  random_forest_binary: "Random Forest",
  next_state_classifier_oracle_binary: "Next-State Classifier - Oracle (ground-truth future state)",
  next_state_classifier_full_pipeline_binary: "Next-State Classifier - Full Pipeline (LSTM-forecast future state)",
};

export { MODEL_LABELS };

export const BINARY_ATTACK_METRICS: BinaryAttackMetricRow[] = [
  { day: "Wednesday-28-02-2018", model: "logistic_regression_binary", n: 22006, nPositive: 5789, nNegative: 16217, attackPrevalencePct: 26.3065, accuracy: 0.43197309824593294, precision: 0.29026814175885995, recall: 0.8022110899982726, f1: 0.4262897007527079, rocAuc: 0.6220211760704036, prAuc: 0.39603849052243123, fpr: 0.700191157427391 },
  { day: "Wednesday-28-02-2018", model: "random_forest_binary", n: 22006, nPositive: 5789, nNegative: 16217, attackPrevalencePct: 26.3065, accuracy: 0.5746160138144143, precision: 0.3402504472271914, recall: 0.6571083088616342, f1: 0.448346985679769, rocAuc: 0.6490288054629787, prAuc: 0.45227742528607273, fpr: 0.45483134981809215 },
  { day: "Wednesday-28-02-2018", model: "next_state_classifier_oracle_binary", n: 22006, nPositive: 5789, nNegative: 16217, attackPrevalencePct: 26.3065, accuracy: 0.4605562119421976, precision: 0.29444369338921184, recall: 0.7524615650371395, f1: 0.42326191517271533, rocAuc: 0.5973267977140188, prAuc: 0.35974328760703034, fpr: 0.6436455571314054 },
  { day: "Wednesday-28-02-2018", model: "next_state_classifier_full_pipeline_binary", n: 22006, nPositive: 5789, nNegative: 16217, attackPrevalencePct: 26.3065, accuracy: 0.38830319003908026, precision: 0.27695080823351553, recall: 0.8227673173259631, f1: 0.41440814373341456, rocAuc: 0.5648882741669963, prAuc: 0.32428614765569064, fpr: 0.7667879385829685 },

  { day: "Wednesday-14-02-2018", model: "logistic_regression_binary", n: 29091, nPositive: 11268, nNegative: 17823, attackPrevalencePct: 38.7336, accuracy: 0.9102127805850607, precision: 0.9180834621329211, recall: 0.8434504792332268, f1: 0.8791859389454209, rocAuc: 0.9709985079686773, prAuc: 0.9250951018959238, fpr: 0.04757897099253773 },
  { day: "Wednesday-14-02-2018", model: "random_forest_binary", n: 29091, nPositive: 11268, nNegative: 17823, attackPrevalencePct: 38.7336, accuracy: 0.6722697741569558, precision: 0.5892342527789214, recall: 0.508075967341143, f1: 0.5456538314906596, rocAuc: 0.7895244397383644, prAuc: 0.6450739123191249, fpr: 0.22392414296134208 },
  { day: "Wednesday-14-02-2018", model: "next_state_classifier_oracle_binary", n: 29091, nPositive: 11268, nNegative: 17823, attackPrevalencePct: 38.7336, accuracy: 0.6655666701041559, precision: 0.5489348171701113, recall: 0.7660631877884274, f1: 0.6395732226873634, rocAuc: 0.7653683149956946, prAuc: 0.6329881110569835, fpr: 0.39796891656847894 },
  { day: "Wednesday-14-02-2018", model: "next_state_classifier_full_pipeline_binary", n: 29091, nPositive: 11268, nNegative: 17823, attackPrevalencePct: 38.7336, accuracy: 0.4902203430614279, precision: 0.4035524748185855, recall: 0.6613418530351438, f1: 0.501244366718235, rocAuc: 0.5825045335456686, prAuc: 0.5305525194943437, fpr: 0.6179655501318521 },

  { day: "Wednesday-21-02-2018", model: "logistic_regression_binary", n: 1870, nPositive: 1790, nNegative: 80, attackPrevalencePct: 95.7219, accuracy: 0.24545454545454545, precision: 0.8528864059590316, recall: 0.2558659217877095, f1: 0.39363987967339925, rocAuc: 0.16089734636871503, prAuc: 0.9131136655702083, fpr: 0.9875 },
  { day: "Wednesday-21-02-2018", model: "random_forest_binary", n: 1870, nPositive: 1790, nNegative: 80, attackPrevalencePct: 95.7219, accuracy: 0.044919786096256686, precision: 1.0, recall: 0.0022346368715083797, f1: 0.004459308807134894, rocAuc: 0.1943959497206704, prAuc: 0.9261289800607946, fpr: 0.0 },
  { day: "Wednesday-21-02-2018", model: "next_state_classifier_oracle_binary", n: 1870, nPositive: 1790, nNegative: 80, attackPrevalencePct: 95.7219, accuracy: 0.9588235294117647, precision: 0.9587573647562935, recall: 1.0, f1: 0.9789444900191414, rocAuc: 1.0, prAuc: 1.0, fpr: 0.9625 },
  { day: "Wednesday-21-02-2018", model: "next_state_classifier_full_pipeline_binary", n: 1870, nPositive: 1790, nNegative: 80, attackPrevalencePct: 95.7219, accuracy: 0.7454545454545455, precision: 0.9859467455621301, recall: 0.7446927374301676, f1: 0.8485041374920432, rocAuc: 0.7994902234636873, prAuc: 0.9901975294615077, fpr: 0.2375 },
];

export interface ConfusionMatrix {
  tn: number;
  fp: number;
  fn: number;
  tp: number;
}

export const CONFUSION_MATRICES: Record<ExternalDay, Record<string, ConfusionMatrix>> = {
  "Wednesday-28-02-2018": {
    logistic_regression_binary: { tn: 4862, fp: 11355, fn: 1145, tp: 4644 },
    random_forest_binary: { tn: 8841, fp: 7376, fn: 1985, tp: 3804 },
    next_state_classifier_oracle_binary: { tn: 5779, fp: 10438, fn: 1433, tp: 4356 },
    next_state_classifier_full_pipeline_binary: { tn: 3782, fp: 12435, fn: 1026, tp: 4763 },
  },
  "Wednesday-14-02-2018": {
    logistic_regression_binary: { tn: 16975, fp: 848, fn: 1764, tp: 9504 },
    random_forest_binary: { tn: 13832, fp: 3991, fn: 5543, tp: 5725 },
    next_state_classifier_oracle_binary: { tn: 10730, fp: 7093, fn: 2636, tp: 8632 },
    next_state_classifier_full_pipeline_binary: { tn: 6809, fp: 11014, fn: 3816, tp: 7452 },
  },
  "Wednesday-21-02-2018": {
    logistic_regression_binary: { tn: 1, fp: 79, fn: 1332, tp: 458 },
    random_forest_binary: { tn: 80, fp: 0, fn: 1786, tp: 4 },
    next_state_classifier_oracle_binary: { tn: 3, fp: 77, fn: 0, tp: 1790 },
    next_state_classifier_full_pipeline_binary: { tn: 61, fp: 19, fn: 457, tp: 1333 },
  },
};

export interface AttackFamilyMetricRow {
  day: ExternalDay;
  attackFamily: string;
  nSequences: number;
  detectedAsAttackCount: number;
  falseNegatives: number;
  detectionRecall: number;
  note: string;
}

export const ATTACK_FAMILY_METRICS: AttackFamilyMetricRow[] = [
  { day: "Wednesday-28-02-2018", attackFamily: "Infilteration", nSequences: 5789, detectedAsAttackCount: 4763, falseNegatives: 1026, detectionRecall: 0.8228, note: "Direct, training-label-compatible detection recall." },
  { day: "Wednesday-14-02-2018", attackFamily: "FTP-BruteForce", nSequences: 5826, detectedAsAttackCount: 3686, falseNegatives: 2140, detectionRecall: 0.6327, note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family." },
  { day: "Wednesday-14-02-2018", attackFamily: "SSH-Bruteforce", nSequences: 5442, detectedAsAttackCount: 3766, falseNegatives: 1676, detectionRecall: 0.692, note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family." },
  { day: "Wednesday-21-02-2018", attackFamily: "DDOS attack-HOIC", nSequences: 1332, detectedAsAttackCount: 1332, falseNegatives: 0, detectionRecall: 1.0, note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family." },
  { day: "Wednesday-21-02-2018", attackFamily: "DDOS attack-LOIC-UDP", nSequences: 458, detectedAsAttackCount: 1, falseNegatives: 457, detectionRecall: 0.0022, note: "Binary anomaly detection recall (predicted non-Benign), NOT attack-family classification - the classifier was never trained to distinguish this family." },
];

export interface ForecastingGeneralizationRow {
  day: ExternalDay;
  horizon: 1 | 2 | 3 | 5;
  n: number;
  mse: number;
  rmse: number;
  mae: number;
  apPrecision: number;
  apRecall: number;
  apF1: number;
  apRocAuc: number;
  apFpr: number;
}

export const FORECASTING_GENERALIZATION: ForecastingGeneralizationRow[] = [
  { day: "Wednesday-28-02-2018", horizon: 1, n: 22006, mse: 4.781149387359619, rmse: 2.186583995819092, mae: 0.4994911253452301, apPrecision: 0.27695080823351553, apRecall: 0.8227673173259631, apF1: 0.41440814373341456, apRocAuc: 0.5648882741669963, apFpr: 0.7667879385829685 },
  { day: "Wednesday-28-02-2018", horizon: 2, n: 21314, mse: 4.950197219848633, rmse: 2.2249038219451904, mae: 0.5086086988449097, apPrecision: 0.2784543844109832, apRecall: 0.8869687885734439, apF1: 0.42384663998314726, apRocAuc: 0.5653242654023489, apFpr: 0.8332161350124656 },
  { day: "Wednesday-28-02-2018", horizon: 3, n: 20647, mse: 5.110660076141357, rmse: 2.260676860809326, mae: 0.5142382979393005, apPrecision: 0.2794462431617729, apRecall: 0.9011701170117011, apF1: 0.4266053091311943, apRocAuc: 0.5605298543371432, apFpr: 0.8552875695732839 },
  { day: "Wednesday-28-02-2018", horizon: 5, n: 19400, mse: 5.411930084228516, rmse: 2.326355457305908, mae: 0.5207371711730957, apPrecision: 0.28425406203840475, apRecall: 0.9007676465081446, apF1: 0.43213868678702955, apRocAuc: 0.5725410694990309, apFpr: 0.8616544562202149 },

  { day: "Wednesday-14-02-2018", horizon: 1, n: 29091, mse: 0.6163159012794495, rmse: 0.7850579023361206, mae: 0.4081503748893738, apPrecision: 0.4035524748185855, apRecall: 0.6613418530351438, apF1: 0.501244366718235, apRocAuc: 0.5825045335456686, apFpr: 0.6179655501318521 },
  { day: "Wednesday-14-02-2018", horizon: 2, n: 28906, mse: 0.6557824611663818, rmse: 0.8098039627075195, mae: 0.4236105978488922, apPrecision: 0.43668705979127037, apRecall: 0.7538161164359247, apF1: 0.5530127933852014, apRocAuc: 0.691437930830999, apFpr: 0.621215557319424 },
  { day: "Wednesday-14-02-2018", horizon: 3, n: 28730, mse: 0.6976186037063599, rmse: 0.8352356553077698, mae: 0.44010645151138306, apPrecision: 0.4628846357195728, apRecall: 0.7769790557330494, apF1: 0.580147107547545, apRocAuc: 0.7421858390451123, apFpr: 0.5817775741610354 },
  { day: "Wednesday-14-02-2018", horizon: 5, n: 28408, mse: 0.7534070611000061, rmse: 0.867990255355835, mae: 0.45811763405799866, apPrecision: 0.4496059726254666, apRecall: 0.769613063542776, apF1: 0.5676135619845529, apRocAuc: 0.7267791888223235, apFpr: 0.6193698949824971 },

  { day: "Wednesday-21-02-2018", horizon: 1, n: 1870, mse: 10647.77734375, rmse: 103.18806457519531, mae: 14.585763931274414, apPrecision: 0.9859467455621301, apRecall: 0.7446927374301676, apF1: 0.8485041374920432, apRocAuc: 0.7994902234636873, apFpr: 0.2375 },
  { day: "Wednesday-21-02-2018", horizon: 2, n: 1830, mse: 9852.150390625, rmse: 99.25799560546875, mae: 14.030537605285645, apPrecision: 0.9773722627737226, apRecall: 0.7612279704377487, apF1: 0.8558644934483861, apRocAuc: 0.8082056866497449, apFpr: 0.43661971830985913 },
  { day: "Wednesday-21-02-2018", horizon: 3, n: 1793, mse: 9259.2685546875, rmse: 96.22509002685547, mae: 13.526582717895508, apPrecision: 0.9636871508379888, apRecall: 0.9982638888888888, apF1: 0.9806708357021034, apRocAuc: 0.836008725071225, apFpr: 1.0 },
  { day: "Wednesday-21-02-2018", horizon: 5, n: 1728, mse: 8292.447265625, rmse: 91.06287384033203, mae: 12.732155799865723, apPrecision: 0.9855386840202458, apRecall: 0.8137313432835821, apF1: 0.8914323086984958, apRocAuc: 0.874694452266967, apFpr: 0.37735849056603776 },
];

/** Wednesday-21-02-2018 LSTM one-step regression outlier diagnostic (results/frozen_generalization/generalization_metrics.json). */
export const WED21_LSTM_OUTLIER = {
  mse: 10647.7783203125,
  rmse: 103.1881,
  mae: 14.5858,
  n: 1870,
  worstSampleSequenceId: 1702,
  worstSampleMse: 206446.0625,
  worstSampleDominantFeature: "Fwd Act Data Pkts",
};

/** Small real sample of predicted_infiltration probabilities (results/frozen_generalization/prediction_summary.csv, 31 rows total). */
export interface PredictionSummaryRow {
  day: ExternalDay;
  sequenceId: number;
  actualLabel: string;
  predictedProbability: number;
}

export const PREDICTION_SUMMARY_SAMPLE: PredictionSummaryRow[] = [
  { day: "Wednesday-28-02-2018", sequenceId: 0, actualLabel: "Benign", predictedProbability: 0.5351951718330383 },
  { day: "Wednesday-28-02-2018", sequenceId: 2445, actualLabel: "Infilteration", predictedProbability: 0.5787436366081238 },
  { day: "Wednesday-28-02-2018", sequenceId: 4890, actualLabel: "Benign", predictedProbability: 0.45852532982826233 },
  { day: "Wednesday-28-02-2018", sequenceId: 7335, actualLabel: "Benign", predictedProbability: 0.5467983484268188 },
];

export const DATA_QUALITY_CAVEATS: string[] = [
  "Wednesday-14-02-2018 and Wednesday-21-02-2018 both contain exactly 1,048,575 rows (2^20 - 1, Excel's maximum worksheet row limit minus one header row) - a strong signature of possible upstream truncation during dataset preparation, verified as not a download error (file byte-sizes are internally consistent with this row count).",
  "Wednesday-21-02-2018's capture stops at 10:43:21, over 2 hours before the ~12:59:59 pattern seen in the other two days - likely an incomplete capture for this day; results from it should not be presented as reflecting a complete day.",
  "External data have temporal-gap fragmentation: the number of usable 10-window sequences is well below the number of raw 1-second windows on every external day (e.g. Wednesday-28: 22,006 sequences from 31,854 windows) because sequences cannot cross a timestamp gap.",
  "Wednesday-21-02-2018 has substantially fewer usable sequences (1,870) than Wednesday-28-02-2018 (22,006), consistent with its much shorter, likely-incomplete capture window.",
  "Wednesday-21-02-2018's one-step LSTM forecasting MSE (10,647.78) is dominated by a small number of extreme outliers - the single worst sequence alone reaches MSE = 206,446.06, roughly 19x the day's mean, with 'Fwd Act Data Pkts' as the dominant feature.",
  "External MITRE evidence is limited because destination-port diversity and a traffic-growth baseline were not computed for this lightweight external pass, so Discovery/Reconnaissance/Impact-growth rules show reduced or no evidence for that reason alone, not necessarily because the underlying behaviour is absent.",
  "Wednesday-14-02-2018 has an unusually high duplicate-row rate (~21.5%, 225,628 of 1,048,575 rows), concentrated almost entirely in the FTP-BruteForce/SSH-Bruteforce attack classes - consistent with automated brute-force tooling producing byte-identical flow records, not a pipeline artifact.",
  "These external captures are transfer/generalization diagnostics of a model trained only on a benign-vs-Infiltration view, not attack-family classification training data.",
  "No ATT&CK ground truth exists for any external day; no MITRE stage-mapping accuracy is reported.",
];

export const NOT_PROVEN: string[] = [
  "universal attack detection",
  "production readiness",
  "performance on arbitrary datasets",
  "performance on all attack families",
  "that the model will work unchanged on every enterprise network",
  "that 100% recall on DDOS-HOIC generalizes to all DDoS attacks",
];

export const DOES_PROVIDE: string[] = [
  "frozen cross-capture evaluation",
  "evidence of transfer to several attack families",
  "evidence of degradation/failure on some conditions",
  "diagnostic information about forecasting and downstream detection",
];

export const FROZEN_GENERALIZATION_SOURCES = {
  report: "results/frozen_generalization/generalization_report.txt",
  metrics: "results/frozen_generalization/generalization_metrics.json",
  datasetSummary: "results/frozen_generalization/dataset_summary.csv",
  binaryAttackMetrics: "results/frozen_generalization/binary_attack_metrics.csv",
  perAttackFamilyMetrics: "results/frozen_generalization/per_attack_family_metrics.csv",
  forecastingMetrics: "results/frozen_generalization/forecasting_metrics.csv",
  predictionSummary: "results/frozen_generalization/prediction_summary.csv",
  confusionMatrices: "results/frozen_generalization/confusion_matrices/*.json",
  config: "results/frozen_generalization/config.json",
  externalDatasetVerification: "results/external_dataset_preparation/external_dataset_verification.txt",
};
