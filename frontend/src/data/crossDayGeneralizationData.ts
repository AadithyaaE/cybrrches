/**
 * Source (read directly, all values real): results/cross_day_generalization/
 * (cross_day_report.txt, cross_day_metrics.json, dataset_summary.csv,
 * fold_summary.csv, model_comparison.csv, leakage_audit.json) - Feature 17,
 * CROSS-DAY GENERALIZATION & MULTI-DAY TRAINING.
 *
 * Feature 17 is a FROZEN research experiment (this file only reads its
 * already-written output, never recomputes anything). No winner is
 * declared between the frozen Thursday-only model and the multi-day
 * trained models anywhere in this data - the mixed, day-dependent results
 * are shown exactly as reported.
 */

export const CROSS_DAY_DAYS_EVALUATED = [
  "Thursday-01-03-2018 (original training day)",
  "Wednesday-28-02-2018",
  "Wednesday-14-02-2018 (excluded from multi-day training: truncation/duplicate caveat)",
  "Wednesday-21-02-2018",
] as const;

export const CROSS_DAY_EXCLUDED_DAY = {
  day: "Tuesday-20-02-2018",
  reason: "Schema-incompatible (84 columns vs. the standard 80) - never mapped, validated, or prepared for this project.",
};

export interface CrossDayFoldSummary {
  foldName: string;
  trainDays: string[];
  holdoutDay: string;
  nTrainSequences: number;
  nHoldoutSequences: number;
  fullPipelineFrozen: { recall: number; precision: number; f1: number; rocAuc: number; fpr: number };
  fullPipelineMultiDay: { recall: number; precision: number; f1: number; rocAuc: number; fpr: number };
  keyFinding: string;
}

export const CROSS_DAY_FOLDS: CrossDayFoldSummary[] = [
  {
    foldName: "fold_holdout_Wed21",
    trainDays: ["Thursday-01-03-2018", "Wednesday-28-02-2018"],
    holdoutDay: "Wednesday-21-02-2018",
    nTrainSequences: 44040,
    nHoldoutSequences: 1870,
    fullPipelineFrozen: { recall: 0.7447, precision: 0.9859, f1: 0.8485, rocAuc: 0.7995, fpr: 0.2375 },
    fullPipelineMultiDay: { recall: 0.9894, precision: 0.9568, f1: 0.9728, rocAuc: 0.8082, fpr: 1.0 },
    keyFinding: "Multi-day training raised recall/F1 but FPR rose to 1.0 (near-all-positive prediction) - not a clean improvement; RandomForest additionally degenerated to all-negative prediction on this fold.",
  },
  {
    foldName: "fold_holdout_Wed28",
    trainDays: ["Thursday-01-03-2018", "Wednesday-21-02-2018"],
    holdoutDay: "Wednesday-28-02-2018",
    nTrainSequences: 23904,
    nHoldoutSequences: 22006,
    fullPipelineFrozen: { recall: 0.8228, precision: 0.277, f1: 0.4144, rocAuc: 0.5649, fpr: 0.7668 },
    fullPipelineMultiDay: { recall: 0.5832, precision: 0.3177, f1: 0.4113, rocAuc: 0.6078, fpr: 0.4471 },
    keyFinding: "Multi-day training lowered recall and FPR by a similar order, with F1 essentially unchanged - a different, more conservative operating point rather than a strict improvement or regression.",
  },
];

export const CROSS_DAY_FAILURE_MODES = [
  "RandomForest showed degraded-to-fully-degenerate (all-negative) prediction after multi-day training on both folds tested.",
  "fold_holdout_Wed21's full-pipeline classifier reached FPR=1.0 alongside its highest recall - flagged as non-improvement, not celebrated, per the automated degenerate-prediction check.",
  "Forecasting error on Wednesday-21-02-2018 is roughly an order of magnitude larger than on the other days in EVERY configuration (frozen or multi-day) - consistent with its extreme, bursty volumetric-DDoS traffic profile.",
];

export const CROSS_DAY_METHODOLOGY_NOTE =
  "Only 2 of a possible 4 leave-one-day-out folds were run (disclosed, not hidden); Wednesday-14-02-2018 never contributed to any training combination due to its documented truncation/duplicate-rate caveat, though it remained fully evaluated as a frozen-baseline day.";

export const CROSS_DAY_MULTI_DAY_VERDICT =
  "Multi-day training changed results on both folds tested, in different directions - it did not uniformly improve or uniformly worsen performance. No overall winner is declared between the frozen Thursday-only model and the multi-day-trained models.";
