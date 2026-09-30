export type InputType = "csv" | "pcap" | "unsupported";

export type DatasetStatus =
  | "SUPPORTED"
  | "SUPPORTED_WITH_LIMITATIONS"
  | "REQUIRES_FEATURE_MAPPING"
  | "INCOMPATIBLE"
  | "UNKNOWN";

export type FeatureMappingKind = "DIRECT" | "DERIVED" | "MISSING" | "UNSUPPORTED";

export interface FeatureMappingEntry {
  feature: string;
  kind: FeatureMappingKind;
  detail: string;
}

export interface ParsedCsvStats {
  header: string[];
  columnCount: number;
  rowCount: number;
  rowCountExact: boolean;
  detailedStatsRowCount: number;
  detailedStatsCapped: boolean;
  previewRows: string[][];
  missingValueCounts: Record<string, number>;
  numericIssueCounts: Record<string, number>;
  duplicateRowCount: number;
  duplicateCheckCapped: boolean;
  duplicateCheckRowLimit: number;
  malformedRowCount: number;
  hasTimestampColumn: boolean;
  hasLabelColumn: boolean;
  hasProtocolColumn: boolean;
  hasDstPortColumn: boolean;
  detectedLabels: string[];
  labelDetectionCapped: boolean;
  fileTooLargeForFullScan: boolean;
  scanBytesProcessed: number;
  totalBytes: number;
}

export interface CsvParseError {
  code: "EMPTY_FILE" | "NO_HEADER" | "MALFORMED_ROW" | "READ_ERROR";
  message: string;
}

export interface DatasetFileInfo {
  filename: string;
  fileType: InputType;
  fileSizeBytes: number;
  mimeType: string;
}

export interface CompatibilityReport {
  status: DatasetStatus;
  statusReason: string;
  direct: FeatureMappingEntry[];
  derived: FeatureMappingEntry[];
  missing: FeatureMappingEntry[];
  unsupportedColumns: string[];
  timestampAvailable: boolean;
  protocolAvailable: boolean;
  labelAvailable: boolean;
  dstPortAvailable: boolean;
}

export interface InferenceReadinessCheck {
  label: string;
  passed: boolean;
  detail: string;
}

export interface InferenceReadiness {
  ready: boolean;
  checks: InferenceReadinessCheck[];
  missingSummary: string[];
}

export interface DatasetAnalysis {
  fileInfo: DatasetFileInfo;
  stats: ParsedCsvStats;
  compatibility: CompatibilityReport;
  readiness: InferenceReadiness;
}
