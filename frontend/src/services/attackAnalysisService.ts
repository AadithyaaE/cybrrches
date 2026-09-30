import { ATTACK_PROGRESSION_METRICS, type AttackProgressionMetric } from "../data/attackProgressionData";
import type {
  AttackProgressionSequenceSummary,
  AttackProgressionSequenceSample,
} from "../types/attackProgressionSequence";

/**
 * Data access for the Attack Analysis page (Frontend Feature 5).
 *
 * getAttackProgressionMetrics() wraps the small, already-typed Feature 13
 * aggregate metrics (data/attackProgressionData.ts, Frontend Feature 2 -
 * untouched here) as an async function, matching the seam used elsewhere.
 *
 * getAttackProgressionSequence{Summary,Samples}() fetch static JSON
 * snapshots generated from the EXISTING Feature 13 per-sequence predictions
 * artifact (results/attack_progression/attack_progression_predictions.csv) -
 * real predicted_infiltration_probability values for 30 representative TEST
 * sequences, never fabricated.
 */

export function getAttackProgressionMetrics(): Promise<AttackProgressionMetric[]> {
  return Promise.resolve(ATTACK_PROGRESSION_METRICS);
}

let sequenceSummaryCache: Promise<AttackProgressionSequenceSummary> | null = null;
let sequenceSamplesCache: Promise<AttackProgressionSequenceSample[]> | null = null;

export function getAttackProgressionSequenceSummary(): Promise<AttackProgressionSequenceSummary> {
  if (!sequenceSummaryCache) {
    sequenceSummaryCache = fetch("/data/attack_progression_sequences_summary.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load attack progression sequence summary: ${res.status}`);
      return res.json();
    });
  }
  return sequenceSummaryCache;
}

export function getAttackProgressionSequences(): Promise<AttackProgressionSequenceSample[]> {
  if (!sequenceSamplesCache) {
    sequenceSamplesCache = fetch("/data/attack_progression_sequences.json").then((res) => {
      if (!res.ok) throw new Error(`Failed to load attack progression sequences: ${res.status}`);
      return res.json();
    });
  }
  return sequenceSamplesCache;
}
