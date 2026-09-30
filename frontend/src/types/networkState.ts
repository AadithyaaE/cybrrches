export interface NetworkStateSummary {
  featureDimensionality: number;
  aggregationSeconds: number;
  totalStates: number;
  uniqueTimestamps: number;
  totalTemporalWindows: number;
  labelDistributionStates: Record<string, number>;
  labelDistributionWindows: Record<string, number>;
  timestampRange: { min: string; max: string };
  observationsPerTimestampSummary: { min: number; max: number; mean: number; median: number };
  missingValueFeaturesAtStateLevel: Record<string, number>;
  missingValueFeaturesAtWindowLevel: Record<string, number>;
  numValidSequences: number;
  sequenceLength: number;
  numTemporalGaps: number;
  source: string;
}

export interface TemporalContextEntry {
  windowId: number;
  timestamp: string;
  label: string;
  position: number;
}

export interface NetworkStateWindow {
  windowId: number;
  timestamp: string;
  windowEnd: string;
  label: string;
  target: number;
  observationCount: number;
  benignCount: number;
  infiltrationCount: number;
  infiltrationRatio: number;
  hasValidTemporalSequence: boolean;
  temporalContext: TemporalContextEntry[] | null;
  features: Record<string, number | null>;
}

export interface FeatureRange {
  min: number | null;
  max: number | null;
}

export type FeatureRanges = Record<string, FeatureRange>;
