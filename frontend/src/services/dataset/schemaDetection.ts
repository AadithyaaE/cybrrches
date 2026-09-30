import {
  REQUIRED_NUMERIC_FEATURES,
  PROTOCOL_RAW_COLUMN,
  TIMESTAMP_COLUMN,
  LABEL_COLUMN,
  DST_PORT_COLUMN,
  KNOWN_EXCLUDED_COLUMNS,
  CSE_CIC_IDS2018_COLUMN_COUNT,
} from "../../data/cyberChessFeatureRequirements";

/** The full real 80-column CSE-CIC-IDS2018 (cleaned) schema, reconstructed from results/model_feature_list.json's 3 lists. */
export const KNOWN_CSE_CIC_IDS2018_COLUMNS: string[] = [
  ...REQUIRED_NUMERIC_FEATURES,
  PROTOCOL_RAW_COLUMN,
  TIMESTAMP_COLUMN,
  LABEL_COLUMN,
  DST_PORT_COLUMN,
  ...KNOWN_EXCLUDED_COLUMNS,
];

export interface SchemaDetectionResult {
  family: string;
  confidence: "exact" | "strong" | "partial" | "unrecognized";
  overlapCount: number;
  overlapRatio: number;
  extraColumnCount: number;
}

export function detectSchemaFamily(header: string[]): SchemaDetectionResult {
  const headerSet = new Set(header);
  const knownSet = new Set(KNOWN_CSE_CIC_IDS2018_COLUMNS);

  const overlapCount = KNOWN_CSE_CIC_IDS2018_COLUMNS.filter((c) => headerSet.has(c)).length;
  const overlapRatio = overlapCount / CSE_CIC_IDS2018_COLUMN_COUNT;
  const extraColumnCount = header.filter((c) => !knownSet.has(c)).length;

  if (overlapCount === CSE_CIC_IDS2018_COLUMN_COUNT && extraColumnCount === 0 && header.length === CSE_CIC_IDS2018_COLUMN_COUNT) {
    return { family: "CSE-CIC-IDS2018 / CICFlowMeter schema (exact match)", confidence: "exact", overlapCount, overlapRatio, extraColumnCount };
  }
  if (overlapRatio >= 0.9) {
    return { family: "CSE-CIC-IDS2018 / CICFlowMeter-family schema (strong match)", confidence: "strong", overlapCount, overlapRatio, extraColumnCount };
  }
  if (overlapRatio >= 0.4) {
    return { family: "Partial match to the CICFlowMeter-style schema", confidence: "partial", overlapCount, overlapRatio, extraColumnCount };
  }
  return { family: "Unrecognized schema (weak or no match to any known compatible family)", confidence: "unrecognized", overlapCount, overlapRatio, extraColumnCount };
}
