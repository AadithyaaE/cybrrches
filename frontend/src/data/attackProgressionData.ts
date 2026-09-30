/**
 * Source: results/attack_progression/attack_progression_horizon_metrics.csv (Feature 13).
 * K-step attack-progression-probability metrics. This is a VALIDATION EVALUATION
 * (with a TEST partition provided for transparency, not a live attack probability).
 *
 * `full_pipeline` = LSTM-predicted future state fed into the Feature 11 classifier.
 * `oracle_diagnostic` = ground-truth future state fed into the same classifier
 * (upper-bound diagnostic, not a deployable mode).
 *
 * Fields are `null` where the source CSV cell was empty (genuinely undefined -
 * e.g. the TEST partition has 0 positive examples, so roc_auc/pr_auc/recall/f1
 * are undefined). `precision: 0` on TEST is a real, defined value and is kept as 0,
 * never confused with the `null` cells.
 */

export type AttackProgressionMode = "full_pipeline" | "oracle_diagnostic";
export type AttackProgressionPartition = "validation" | "test";

export interface AttackProgressionMetric {
  horizon: 1 | 2 | 3 | 5;
  mode: AttackProgressionMode;
  partition: AttackProgressionPartition;
  n: number;
  nPositive: number;
  nNegative: number;
  rocAuc: number | null;
  prAuc: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
}

export const ATTACK_PROGRESSION_METRICS: AttackProgressionMetric[] = [
  { horizon: 1, mode: "full_pipeline", partition: "validation", n: 3492, nPositive: 1677, nNegative: 1815, rocAuc: 0.6601401886814148, prAuc: 0.6258363243129139, precision: 0.5609430604982206, recall: 0.751937984496124, f1: 0.642547770700637, fpr: 0.543801652892562 },
  { horizon: 1, mode: "oracle_diagnostic", partition: "validation", n: 3492, nPositive: 1677, nNegative: 1815, rocAuc: 0.666649911047374, prAuc: 0.6568098868390803, precision: 0.5856733524355301, recall: 0.6094215861657722, f1: 0.5973115137346581, fpr: 0.39834710743801655 },
  { horizon: 1, mode: "full_pipeline", partition: "test", n: 2871, nPositive: 0, nNegative: 2871, rocAuc: null, prAuc: null, precision: 0.0, recall: null, f1: null, fpr: 0.460118425635667 },

  { horizon: 2, mode: "full_pipeline", partition: "validation", n: 3388, nPositive: 1631, nNegative: 1757, rocAuc: 0.6727374464653431, prAuc: 0.6348047776865507, precision: 0.5635245901639344, recall: 0.8430410790925812, f1: 0.6755097027757307, fpr: 0.6061468412066021 },
  { horizon: 2, mode: "oracle_diagnostic", partition: "validation", n: 3388, nPositive: 1631, nNegative: 1757, rocAuc: 0.6660037610790088, prAuc: 0.6561374810540423, precision: 0.5871886120996441, recall: 0.6069895769466584, f1: 0.5969249321676213, fpr: 0.39612976664769495 },
  { horizon: 2, mode: "full_pipeline", partition: "test", n: 2726, nPositive: 0, nNegative: 2726, rocAuc: null, prAuc: null, precision: 0.0, recall: null, f1: null, fpr: 0.5385179750550256 },

  { horizon: 3, mode: "full_pipeline", partition: "validation", n: 3288, nPositive: 1584, nNegative: 1704, rocAuc: 0.687802874697681, prAuc: 0.64133091553076, precision: 0.5593961064759635, recall: 0.8888888888888888, f1: 0.686661789807364, fpr: 0.6508215962441315 },
  { horizon: 3, mode: "oracle_diagnostic", partition: "validation", n: 3288, nPositive: 1584, nNegative: 1704, rocAuc: 0.6672637095722483, prAuc: 0.6572612554878905, precision: 0.5900430239704979, recall: 0.6060606060606061, f1: 0.5979445655559016, fpr: 0.3914319248826291 },
  { horizon: 3, mode: "full_pipeline", partition: "test", n: 2592, nPositive: 0, nNegative: 2592, rocAuc: null, prAuc: null, precision: 0.0, recall: null, f1: null, fpr: 0.5339506172839507 },

  { horizon: 5, mode: "full_pipeline", partition: "validation", n: 3092, nPositive: 1498, nNegative: 1594, rocAuc: 0.7064758448320052, prAuc: 0.6401127378203733, precision: 0.5764948453608247, recall: 0.9332443257676902, f1: 0.712719857252103, fpr: 0.6442910915934755 },
  { horizon: 5, mode: "oracle_diagnostic", partition: "validation", n: 3092, nPositive: 1498, nNegative: 1594, rocAuc: 0.6725749347101028, prAuc: 0.665808953278929, precision: 0.5958005249343832, recall: 0.6061415220293725, f1: 0.600926538716082, fpr: 0.3864491844416562 },
  { horizon: 5, mode: "full_pipeline", partition: "test", n: 2341, nPositive: 0, nNegative: 2341, rocAuc: null, prAuc: null, precision: 0.0, recall: null, f1: null, fpr: 0.5224263135412217 },
];

export const ATTACK_PROGRESSION_SOURCE = "results/attack_progression/attack_progression_horizon_metrics.csv";
