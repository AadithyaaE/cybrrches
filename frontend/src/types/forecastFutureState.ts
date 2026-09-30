export interface ForecastFutureStateSummary {
  featureOrder: string[];
  featureCount: number;
  horizons: number[];
  totalTestSequences: number;
  sampledSequenceCount: number;
  valuesAreScaledByDefault: boolean;
  scaledSpaceNote: string;
  rawUnitsNote: string;
  source: Record<string, string>;
  label: string;
}

export interface StateVector {
  scaled: Array<number | null>;
  raw: Array<number | null>;
}

export interface GroundTruthState {
  available: boolean;
  windowId?: number;
  timestamp?: string;
  label?: string;
  scaled?: Array<number | null>;
  raw?: Array<number | null>;
}

export interface ForecastFutureStateSample {
  sequenceId: number;
  inputEndWindowId: number;
  inputEndTimestamp: string;
  forecastTargetLabel: string;
  isKnownOutlierExample: boolean;
  observed: StateVector;
  forecasts: Record<string, StateVector>;
  groundTruth: Record<string, GroundTruthState>;
}

export type ValueMode = "scaled" | "raw";
