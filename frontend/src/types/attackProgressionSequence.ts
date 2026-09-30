export interface AttackProgressionSequenceHorizonPoint {
  predictedInfiltrationProbability: number;
  predictedAttackClassAt050: number;
  actualFutureLabel: string;
  futureTimestamp: string;
}

export interface AttackProgressionSequenceSample {
  sequenceId: number;
  currentTimestamp: string;
  segmentId: number;
  horizons: Record<string, AttackProgressionSequenceHorizonPoint>;
}

export interface ProbabilityDescriptiveStat {
  mean: number;
  std: number;
  min: number;
  max: number;
}

export interface AttackProgressionSequenceSummary {
  mode: string;
  partition: string;
  threshold: number;
  horizons: number[];
  totalTestSequencesWithAllHorizons: number;
  sampledSequenceCount: number;
  note: string;
  probabilityDescriptiveStats: Record<string, ProbabilityDescriptiveStat>;
  source: string;
}
