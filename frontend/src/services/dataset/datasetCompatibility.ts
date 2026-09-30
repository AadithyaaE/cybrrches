import {
  REQUIRED_NUMERIC_FEATURES,
  PROTOCOL_RAW_COLUMN,
  PROTOCOL_STATE_COLUMN_NAMES,
  TIMESTAMP_COLUMN,
  LABEL_COLUMN,
  DST_PORT_COLUMN,
  KNOWN_EXCLUDED_COLUMNS,
} from "../../data/cyberChessFeatureRequirements";
import type {
  ParsedCsvStats,
  CompatibilityReport,
  FeatureMappingEntry,
  InferenceReadiness,
  DatasetStatus,
} from "../../types/dataset";

/**
 * Deterministic, rule-based comparison of an uploaded CSV's header against
 * the real CyberChess feature requirements (data/cyberChessFeatureRequirements.ts).
 * Never invents a mapping: a required numeric feature is either DIRECTLY
 * present by exact column name, or it is MISSING. The only DERIVED case is
 * the real, documented Protocol -> Protocol_0/6/17 one-hot expansion.
 */

export function buildCompatibilityReport(stats: ParsedCsvStats): CompatibilityReport {
  const headerSet = new Set(stats.header);

  const direct: FeatureMappingEntry[] = [];
  const missing: FeatureMappingEntry[] = [];

  for (const feature of REQUIRED_NUMERIC_FEATURES) {
    if (headerSet.has(feature)) {
      direct.push({ feature, kind: "DIRECT", detail: "Exact column name match." });
    } else {
      missing.push({ feature, kind: "MISSING", detail: "Required numeric feature column not found in the uploaded header." });
    }
  }

  const derived: FeatureMappingEntry[] = [];
  const protocolAvailable = headerSet.has(PROTOCOL_RAW_COLUMN);
  if (protocolAvailable) {
    derived.push({
      feature: PROTOCOL_STATE_COLUMN_NAMES.join(" / "),
      kind: "DERIVED",
      detail: `Derived by one-hot encoding the raw "${PROTOCOL_RAW_COLUMN}" column (3 state dimensions).`,
    });
  } else {
    missing.push({
      feature: PROTOCOL_STATE_COLUMN_NAMES.join(" / "),
      kind: "MISSING",
      detail: `Cannot be derived: the raw "${PROTOCOL_RAW_COLUMN}" column was not found.`,
    });
  }

  const timestampAvailable = headerSet.has(TIMESTAMP_COLUMN);
  const labelAvailable = headerSet.has(LABEL_COLUMN);
  const dstPortAvailable = headerSet.has(DST_PORT_COLUMN);

  const knownAccountedFor = new Set([
    ...REQUIRED_NUMERIC_FEATURES,
    PROTOCOL_RAW_COLUMN,
    TIMESTAMP_COLUMN,
    LABEL_COLUMN,
    DST_PORT_COLUMN,
    ...KNOWN_EXCLUDED_COLUMNS,
  ]);
  const unsupportedColumns = stats.header.filter((c) => !knownAccountedFor.has(c));

  const missingRequiredCount = REQUIRED_NUMERIC_FEATURES.length - direct.length;
  const missingRatio = missingRequiredCount / REQUIRED_NUMERIC_FEATURES.length;

  let status: DatasetStatus;
  let statusReason: string;

  if (missingRequiredCount === 0 && protocolAvailable && timestampAvailable) {
    status = "SUPPORTED";
    statusReason = "All 65 required numeric features, the Protocol column, and the Timestamp column are present.";
  } else if (missingRequiredCount === 0 && (!protocolAvailable || !timestampAvailable)) {
    status = "SUPPORTED_WITH_LIMITATIONS";
    const parts: string[] = [];
    if (!protocolAvailable) parts.push("the 3 Protocol one-hot dimensions cannot be derived");
    if (!timestampAvailable) parts.push("1-second temporal aggregation/sequence ordering cannot be performed without a Timestamp column");
    statusReason = `All 65 required numeric features are present, but ${parts.join(" and ")}.`;
  } else if (missingRatio < 0.5) {
    status = "REQUIRES_FEATURE_MAPPING";
    statusReason = `${missingRequiredCount} of ${REQUIRED_NUMERIC_FEATURES.length} required numeric features are missing by name. These are not derived or guessed - a future feature-mapping step would need to address them.`;
  } else {
    status = "INCOMPATIBLE";
    statusReason = `${missingRequiredCount} of ${REQUIRED_NUMERIC_FEATURES.length} required numeric features (${(missingRatio * 100).toFixed(0)}%) are missing. This does not resemble the CyberChess-compatible CICFlowMeter-style schema.`;
  }

  return {
    status,
    statusReason,
    direct,
    derived,
    missing,
    unsupportedColumns,
    timestampAvailable,
    protocolAvailable,
    labelAvailable,
    dstPortAvailable,
  };
}

export function buildInferenceReadiness(compat: CompatibilityReport): InferenceReadiness {
  const checks = [
    {
      label: "Dataset recognized",
      passed: compat.status === "SUPPORTED" || compat.status === "SUPPORTED_WITH_LIMITATIONS",
      detail: compat.statusReason,
    },
    {
      label: "Timestamp available",
      passed: compat.timestampAvailable,
      detail: compat.timestampAvailable
        ? "Timestamp column present - 1-second aggregation and sequence ordering can be performed."
        : "Timestamp column missing - temporal aggregation into network-state windows cannot be performed.",
    },
    {
      label: "Required features available",
      passed: compat.missing.filter((m) => m.kind === "MISSING" && m.feature !== "Protocol_0 / Protocol_6 / Protocol_17").length === 0,
      detail:
        compat.missing.length === 0
          ? "All required numeric features are present."
          : `${compat.missing.length} required feature group(s) are missing (see Feature Compatibility above).`,
    },
    {
      label: "State mapping possible",
      passed: compat.protocolAvailable,
      detail: compat.protocolAvailable
        ? "Protocol column present - the full 68-dimensional state (65 numeric + 3 Protocol one-hot) can be constructed."
        : "Protocol column missing - the 3 Protocol one-hot dimensions cannot be constructed.",
    },
  ];

  const ready = checks.every((c) => c.passed);
  const missingSummary = compat.missing.map((m) => m.feature);
  if (!compat.timestampAvailable) missingSummary.push(`${"Timestamp"} column`);

  return { ready, checks, missingSummary };
}
