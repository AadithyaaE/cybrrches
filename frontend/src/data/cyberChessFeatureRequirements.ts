/**
 * Source (read directly, all values real): results/model_feature_list.json,
 * results/model_preparation_report.json, results/state_schema.json
 * (Feature 3/4 of the research pipeline).
 *
 * This is the SOURCE OF TRUTH for what raw CSV columns CyberChess needs to
 * derive its 68-dimensional network state S(t):
 *
 *   68 state dimensions = 65 numeric features (imputed + standardized by the
 *   frozen, train-fitted preprocessing pipeline) + 3 one-hot Protocol
 *   dimensions (Protocol_0 / Protocol_6 / Protocol_17), derived from a
 *   single raw "Protocol" column.
 *
 * The original cleaned CSE-CIC-IDS2018 CSV has 80 raw columns. A compatible
 * upload does NOT need to have exactly 68 (or 80) columns - it needs to
 * contain (a subset of) these specific, named columns.
 */

export const STATE_DIMENSIONALITY = 68;
export const NUMERIC_STATE_DIMENSIONS = 65;
export const PROTOCOL_STATE_DIMENSIONS = 3;

/** The 65 raw column names that map 1:1 (DIRECT) onto 65 of the 68 state dimensions. */
export const REQUIRED_NUMERIC_FEATURES: string[] = [
  "ACK Flag Cnt", "Active Max", "Active Mean", "Active Min", "Active Std", "Bwd Header Len",
  "Bwd IAT Max", "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Std", "Bwd IAT Tot", "Bwd Pkt Len Max",
  "Bwd Pkt Len Mean", "Bwd Pkt Len Min", "Bwd Pkt Len Std", "Bwd Pkts/s", "Bwd Seg Size Avg",
  "Down/Up Ratio", "ECE Flag Cnt", "Flow Byts/s", "Flow Duration", "Flow IAT Max", "Flow IAT Mean",
  "Flow IAT Min", "Flow IAT Std", "Flow Pkts/s", "Fwd Act Data Pkts", "Fwd Header Len", "Fwd IAT Max",
  "Fwd IAT Mean", "Fwd IAT Min", "Fwd IAT Std", "Fwd IAT Tot", "Fwd PSH Flags", "Fwd Pkt Len Max",
  "Fwd Pkt Len Mean", "Fwd Pkt Len Min", "Fwd Pkt Len Std", "Fwd Pkts/s", "Fwd Seg Size Avg",
  "Fwd Seg Size Min", "Idle Max", "Idle Mean", "Idle Min", "Idle Std", "Init Bwd Win Byts",
  "Init Fwd Win Byts", "PSH Flag Cnt", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Min", "Pkt Len Std",
  "Pkt Len Var", "Pkt Size Avg", "RST Flag Cnt", "SYN Flag Cnt", "Subflow Bwd Byts",
  "Subflow Bwd Pkts", "Subflow Fwd Byts", "Subflow Fwd Pkts", "Tot Bwd Pkts", "Tot Fwd Pkts",
  "TotLen Bwd Pkts", "TotLen Fwd Pkts", "URG Flag Cnt",
];

/** Single raw column that is DERIVED (one-hot encoded) into 3 state dimensions. */
export const PROTOCOL_RAW_COLUMN = "Protocol";
export const PROTOCOL_STATE_COLUMN_NAMES = ["Protocol_0", "Protocol_6", "Protocol_17"];
/** Protocol values the frozen pipeline's one-hot encoding was fitted on (TCP=6, UDP=17, HOPOPT=0). */
export const KNOWN_PROTOCOL_VALUES = ["0", "6", "17"];

/** Not part of the 68-dim state, but needed for 1-second temporal aggregation / sequence ordering (inference requirement). */
export const TIMESTAMP_COLUMN = "Timestamp";

/** Not part of the 68-dim state and not required for inference; only needed to measure detection performance (evaluation requirement). */
export const LABEL_COLUMN = "Label";

/** Reserved but NOT part of the state vector (results/state_construction_report.json: "dst_port_absent": true). Optional; only used by the Feature 14 MITRE Discovery/Reconnaissance rules downstream, never by the core state/model. */
export const DST_PORT_COLUMN = "Dst Port";

/** Columns present in the original 80-column schema that the research pipeline explicitly excluded (near-constant/rarely-populated CICFlowMeter fields). Harmless if present in an upload; simply unused. */
export const KNOWN_EXCLUDED_COLUMNS: string[] = [
  "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "FIN Flag Cnt", "CWE Flag Count",
  "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg",
  "Bwd Blk Rate Avg",
];

export const CSE_CIC_IDS2018_COLUMN_COUNT = 80;

export const FEATURE_REQUIREMENTS_SOURCES = {
  modelFeatureList: "results/model_feature_list.json",
  modelPreparationReport: "results/model_preparation_report.json",
  stateSchema: "results/state_schema.json",
};
